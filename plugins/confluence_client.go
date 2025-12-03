package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	httpTimeout       = 60 * time.Second
	schemeHTTPS       = "https"
	authMissingScopes = "missing-scopes"
	authBadCreds      = "bad-credentials"
)

var (
	// ErrBaseURLInvalidOrUnreachable is returned when the base URL/host/service is invalid or unreachable.
	ErrBaseURLInvalidOrUnreachable = errors.New("base url invalid or service unreachable")

	// ErrBadCredentials indicates token is invalid/expired or username does not match the token.
	ErrBadCredentials = errors.New("bad credentials")

	// ErrMissingScopes indicates the token is valid but missing required scopes.
	ErrMissingScopes = errors.New("token missing required scopes")

	// ErrUnexpectedHTTPStatus is used for other non-2xx statuses not classified above.
	ErrUnexpectedHTTPStatus = errors.New("unexpected http status")

	// ErrAPIResponseTooLarge is returned internally when a single API response exceeds
	// the configured per-request size limit. Callers treat this as a soft failure:
	// skip the current batch and move on when possible.
	ErrAPIResponseTooLarge = errors.New("confluence api response exceeded configured size limit")

	// ErrTotalScanVolumeExceeded is returned when the total downloaded bytes across
	// the scan exceed the configured global limit. Callers should stop scanning
	// gracefully and not treat this as a hard failure.
	ErrTotalScanVolumeExceeded = errors.New("confluence total scan volume exceeded configured limit")
)

// ConfluenceClient defines the operations required by the Confluence plugin.
// Methods stream results via visitor callbacks and handle pagination internally.
type ConfluenceClient interface {
	WalkAllPages(ctx context.Context, limit int, visit func(*Page) error) error
	WalkPagesByIDs(ctx context.Context, pageIDs []string, limit int, visit func(*Page) error) error
	WalkPagesBySpaceIDs(ctx context.Context, spaceIDs []string, limit int, visit func(*Page) error) error
	WalkPageVersions(ctx context.Context, pageID string, limit int, visit func(int) error) error
	FetchPageAtVersion(ctx context.Context, pageID string, version int) (*Page, error)
	WalkSpacesByKeys(ctx context.Context, spaceKeys []string, limit int, visit func(*Space) error) error
	WikiBaseURL() string
	APIResponseLimitHit() bool
}

// httpConfluenceClient is a ConfluenceClient implementation backed by net/http.
// It supports optional Basic Auth using a Confluence email/username and API token.
type httpConfluenceClient struct {
	baseWikiURL string
	httpClient  *http.Client
	username    string
	token       string
	apiBase     string

	// Optional limits (0 means "no limit").
	maxAPIResponseBytes int64
	maxTotalScanBytes   int64
	maxPageBodyBytes    int64

	totalScanBytes int64

	// apiResponseLimitHit indicates that at least one API batch exceeded the
	// configured per-request size limit during this scan. Used by the plugin
	// to emit a single consolidated warning instead of one per batch.
	apiResponseLimitHit bool
}

type ConfluenceClientOption func(*httpConfluenceClient)

// WithMaxAPIResponseBytes sets an optional per-request API response size limit in bytes.
// A value of 0 disables the limit. Negative values are treated as 0.
func WithMaxAPIResponseBytes(n int64) ConfluenceClientOption {
	if n < 0 {
		n = 0
	}
	return func(c *httpConfluenceClient) {
		c.maxAPIResponseBytes = n
	}
}

// WithMaxTotalScanBytes sets an optional total downloaded-bytes limit in bytes
// for the entire Confluence scan. A value of 0 disables the limit.
// Negative values are treated as 0.
func WithMaxTotalScanBytes(n int64) ConfluenceClientOption {
	if n < 0 {
		n = 0
	}
	return func(c *httpConfluenceClient) {
		c.maxTotalScanBytes = n
	}
}

// WithMaxPageBodyBytes sets an optional limit in bytes for individual page bodies.
// Pages whose storage body exceeds this limit are skipped and logged as warnings.
// A value of 0 disables the limit. Negative values are treated as 0.
func WithMaxPageBodyBytes(n int64) ConfluenceClientOption {
	if n < 0 {
		n = 0
	}
	return func(c *httpConfluenceClient) {
		c.maxPageBodyBytes = n
	}
}

// NewConfluenceClient constructs a ConfluenceClient for the given base input URL.
// Behavior:
//   - Normalizes base wiki URL to "https://{host}/wiki".
//   - Discovers cloudId and always uses platform v2:
//     "https://api.atlassian.com/ex/confluence/{cloudId}/wiki/api/v2".
//   - Applies any provided ConfluenceClientOption values (for example, response/scan
//     size limits) before issuing API requests.
func NewConfluenceClient(inputBaseURL, username, token string, opts ...ConfluenceClientOption) (ConfluenceClient, error) {
	baseWikiURL, err := normalizeWikiBase(inputBaseURL)
	if err != nil {
		return nil, err
	}
	c := &httpConfluenceClient{
		baseWikiURL: baseWikiURL,
		httpClient:  &http.Client{Timeout: httpTimeout},
		username:    username,
		token:       token,
	}
	for _, opt := range opts {
		opt(c)
	}
	apiBase, err := c.buildAPIBase(context.Background())
	if err != nil {
		return nil, err
	}
	c.apiBase = apiBase
	return c, nil
}

// WikiBaseURL returns the base Confluence wiki URL configured for this client.
// Example: "https://tenant.atlassian.net/wiki".
func (c *httpConfluenceClient) WikiBaseURL() string { return c.baseWikiURL }

// APIResponseLimitHit reports whether any API response exceeded the configured
// per-request size limit during this scan.
func (c *httpConfluenceClient) APIResponseLimitHit() bool {
	return c.apiResponseLimitHit
}

// normalizeWikiBase takes any Confluence-related URL (site root, /wiki, a page URL, etc.)
// and returns "https://{host}/wiki".
func normalizeWikiBase(inputURL string) (string, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(inputURL))
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	if parsedURL.Host == "" {
		return "", fmt.Errorf("invalid url: missing host")
	}
	// force https and canonical wiki root
	parsedURL.Scheme = schemeHTTPS
	parsedURL.User = nil
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	parsedURL.Path = "/wiki"
	return strings.TrimRight(parsedURL.String(), "/"), nil
}

// buildAPIBase discovers the site's cloudId and builds the platform v2 base:
// "https://api.atlassian.com/ex/confluence/{cloudId}/wiki/api/v2".
func (c *httpConfluenceClient) buildAPIBase(ctx context.Context) (string, error) {
	cloudID, err := c.discoverCloudID(ctx)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse("https://api.atlassian.com")
	u.Path = path.Join("/ex/confluence", cloudID, "wiki", "api", "v2")
	return strings.TrimRight(u.String(), "/"), nil
}

// discoverCloudID resolves the Atlassian cloudId for baseWikiURL by calling
// "https://{host}/_edge/tenant_info" and decoding {"cloudId": "..."}.
// If cloudId cannot be obtained, the base URL is considered invalid/unavailable.
func (c *httpConfluenceClient) discoverCloudID(ctx context.Context) (string, error) {
	site, err := url.Parse(c.baseWikiURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	site.RawQuery, site.Fragment, site.User = "", "", nil
	site.Scheme = schemeHTTPS
	site.Path = "/_edge/tenant_info"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.String(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build tenant_info request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", ErrBaseURLInvalidOrUnreachable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Any non-200 here indicates the host/service isn't a valid Confluence wiki endpoint
		// or is unavailable to us.
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 2048)) // drain for completeness
		return "", ErrBaseURLInvalidOrUnreachable
	}

	var tmp struct {
		CloudID string `json:"cloudId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tmp); err != nil {
		return "", ErrBaseURLInvalidOrUnreachable
	}
	if tmp.CloudID == "" {
		return "", ErrBaseURLInvalidOrUnreachable
	}
	return tmp.CloudID, nil
}

// walkPagesWithFilter builds a /pages request with common query parameters
// and an optional filter (id, space-id, etc.), then streams pages via visit.
func (c *httpConfluenceClient) walkPagesWithFilter(
	ctx context.Context,
	filterKey string,
	filterValues []string,
	limit int,
	visit func(*Page) error,
) error {
	apiURL := c.apiURL("/pages")
	q := apiURL.Query()
	q.Set("limit", strconv.Itoa(limit))
	q.Set("body-format", "storage")
	q.Set("sort", "-created-date") // Newest created date to oldest

	if filterKey != "" && len(filterValues) > 0 {
		q.Set(filterKey, strings.Join(filterValues, ","))
	}

	apiURL.RawQuery = q.Encode()
	return c.walkPagesPaginated(ctx, apiURL.String(), visit)
}

// WalkAllPages iterates all accessible pages and calls visit for each Page.
func (c *httpConfluenceClient) WalkAllPages(ctx context.Context, limit int, visit func(*Page) error) error {
	return c.walkPagesWithFilter(ctx, "", nil, limit, visit)
}

// WalkPagesByIDs iterates the given page IDs and calls visit for each Page.
func (c *httpConfluenceClient) WalkPagesByIDs(ctx context.Context, pageIDs []string, limit int, visit func(*Page) error) error {
	return c.walkPagesWithFilter(ctx, "id", pageIDs, limit, visit)
}

// WalkPagesBySpaceIDs iterates pages across the provided space IDs and calls visit.
func (c *httpConfluenceClient) WalkPagesBySpaceIDs(ctx context.Context, spaceIDs []string, limit int, visit func(*Page) error) error {
	return c.walkPagesWithFilter(ctx, "space-id", spaceIDs, limit, visit)
}

// WalkPageVersions lists version numbers for a page and calls visit for each.
func (c *httpConfluenceClient) WalkPageVersions(ctx context.Context, pageID string, limit int, visit func(int) error) error {
	apiURL := c.apiURL(fmt.Sprintf("/pages/%s/versions", url.PathEscape(pageID)))
	q := apiURL.Query()
	q.Set("limit", strconv.Itoa(limit))
	apiURL.RawQuery = q.Encode()

	return walkPaginated[int](
		ctx,
		apiURL,
		c.getJSON,
		parseVersionsResponse,
		visit,
	)
}

// FetchPageAtVersion fetches a page at a specific version.
func (c *httpConfluenceClient) FetchPageAtVersion(ctx context.Context, pageID string, version int) (*Page, error) {
	apiURL := c.apiURL(fmt.Sprintf("/pages/%s", url.PathEscape(pageID)))
	q := apiURL.Query()
	q.Set("version", strconv.Itoa(version))
	q.Set("body-format", "storage")
	apiURL.RawQuery = q.Encode()

	bodyBytes, _, err := c.getJSON(ctx, apiURL.String())
	if err != nil {
		return nil, err
	}
	var page Page
	if err := json.Unmarshal(bodyBytes, &page); err != nil {
		return nil, fmt.Errorf("decode page version: %w", err)
	}
	return &page, nil
}

// WalkSpacesByKeys lists spaces by their keys and calls visit for each Space.
func (c *httpConfluenceClient) WalkSpacesByKeys(ctx context.Context, spaceKeys []string, limit int, visit func(*Space) error) error {
	apiURL := c.apiURL("/spaces")
	q := apiURL.Query()
	q.Set("limit", strconv.Itoa(limit))
	q.Set("keys", strings.Join(spaceKeys, ","))
	apiURL.RawQuery = q.Encode()

	return walkPaginated[*Space](
		ctx,
		apiURL,
		c.getJSON,
		parseSpacesResponse,
		visit,
	)
}

// walkPaginated is a generic pager.
// It fetches items from initial URL, applies parse, calls visit for each item,
// then advances using resolveNext until there is no next page.
func walkPaginated[T any](
	ctx context.Context,
	apiURL *url.URL,
	get func(context.Context, string) ([]byte, http.Header, error),
	parse func(http.Header, []byte) ([]T, string, string, error),
	visit func(T) error,
) error {
	base := baseWithoutCursor(apiURL)
	nextURL := apiURL.String()

	for {
		body, headers, err := get(ctx, nextURL)
		if err != nil {
			return err
		}
		items, linkNext, bodyNext, err := parse(headers, body)
		if err != nil {
			return err
		}
		for _, it := range items {
			if err := visit(it); err != nil {
				return err
			}
		}
		rawNext := linkNext
		if rawNext == "" {
			rawNext = bodyNext
		}
		if rawNext == "" {
			return nil
		}
		cur := cursorFromURL(rawNext)
		if cur == "" {
			return nil
		}
		nextURL = withCursor(base, cur)
	}
}

// walkPagesPaginated iterates pages starting from initialURL using streaming
// decode, applying size limits and pagination until no further cursor exists.
func (c *httpConfluenceClient) walkPagesPaginated(
	ctx context.Context, initialURL string, visit func(*Page) error,
) error {
	start, err := url.Parse(initialURL)
	if err != nil {
		return fmt.Errorf("parse initial pages url: %w", err)
	}
	base := baseWithoutCursor(start)

	nextURL := initialURL
	for {
		rc, headers, err := c.getJSONStream(ctx, nextURL)
		if err != nil {
			return err
		}

		linkNext := nextURLFromLinkHeader(headers)

		reader := c.wrapWithCountingReader(rc)
		limitedVisit := c.wrapWithPageBodyLimit(visit)

		bodyNext, decodeErr := streamPagesFromBody(reader, limitedVisit)
		closeErr := rc.Close()

		if decodeErr != nil {
			newNextURL, done, handleErr := c.handleStreamError(decodeErr, closeErr, linkNext, base)
			if handleErr != nil {
				return handleErr
			}
			if done {
				// Either we've reached the end or we've hit a terminal error that
				// was handled gracefully.
				return nil
			}
			if newNextURL == "" {
				// No follow-up cursor to continue with.
				return nil
			}

			nextURL = newNextURL
			continue
		}

		if closeErr != nil {
			return closeErr
		}

		cur := firstNonEmptyString(cursorFromURL(linkNext), cursorFromURL(bodyNext))
		if cur == "" {
			return nil
		}
		nextURL = withCursor(base, cur)
	}
}

// wrapWithCountingReader wraps the response body with a countingReader when
// any per-response or total scan limits are configured, otherwise returns rc.
func (c *httpConfluenceClient) wrapWithCountingReader(rc io.ReadCloser) io.Reader {
	if c.maxAPIResponseBytes == 0 && c.maxTotalScanBytes == 0 {
		return rc
	}

	return &countingReader{
		r:               rc,
		apiLimitBytes:   c.maxAPIResponseBytes,
		apiConsumed:     0,
		totalBytes:      &c.totalScanBytes,
		totalLimitBytes: c.maxTotalScanBytes,
	}
}

// wrapWithPageBodyLimit decorates the visit callback to skip pages whose
// storage body exceeds maxPageBodyBytes, logging a warning when that happens.
func (c *httpConfluenceClient) wrapWithPageBodyLimit(
	visit func(*Page) error,
) func(*Page) error {
	if c.maxPageBodyBytes == 0 {
		return visit
	}

	return func(p *Page) error {
		if p.Body.Storage != nil {
			bodySize := int64(len(p.Body.Storage.Value))
			if bodySize > c.maxPageBodyBytes {
				log.Warn().
					Str("page_id", p.ID).
					Int64("body_bytes", bodySize).
					Msg("Skipping page content because the Confluence page body exceeded the configured size limit.")
				return nil
			}
		}
		return visit(p)
	}
}

// handleStreamError centralizes handling for decode/close errors and decides
// whether to stop, continue with a new cursor, or return an error.
func (c *httpConfluenceClient) handleStreamError(
	decodeErr, closeErr error,
	linkNext string,
	base *url.URL,
) (nextURL string, done bool, err error) {
	if errors.Is(decodeErr, ErrAPIResponseTooLarge) {
		c.apiResponseLimitHit = true

		if closeErr != nil {
			return "", true, closeErr
		}

		cur := cursorFromURL(linkNext)
		if cur == "" {
			// No "next" link: nothing else to do.
			return "", true, nil
		}
		return withCursor(base, cur), false, nil
	}

	if errors.Is(decodeErr, ErrTotalScanVolumeExceeded) {
		if closeErr != nil {
			return "", true, closeErr
		}
		return "", true, ErrTotalScanVolumeExceeded
	}

	if closeErr != nil {
		return "", true, closeErr
	}
	return "", true, decodeErr
}

// apiURL joins the relative API path to the platform base,
// producing a URL rooted at .../api/v2/<relative>.
func (c *httpConfluenceClient) apiURL(relativePath string) *url.URL {
	parsedURL, _ := url.Parse(c.apiBase)
	parsedURL.Path = path.Join(parsedURL.Path, strings.TrimPrefix(relativePath, "/"))
	return parsedURL
}

// getJSON performs a GET request and returns the response body and headers.
// It sets Accept: application/json and uses Basic Auth when credentials were
// provided. Non-2xx responses are classified into sentinel errors when possible.
func (c *httpConfluenceClient) getJSON(ctx context.Context, reqURL string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	if c.username != "" && c.token != "" {
		req.SetBasicAuth(c.username, c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, nil, fmt.Errorf("%s", rateLimitMessage(resp.Header))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if resp.StatusCode == http.StatusUnauthorized {
			switch classifyAuth401(bodyBytes) {
			case authMissingScopes:
				return nil, nil, ErrMissingScopes
			default:
				return nil, nil, fmt.Errorf("%w: invalid username or token", ErrBadCredentials)
			}
		}
		return nil, nil, fmt.Errorf("%w %d: %s", ErrUnexpectedHTTPStatus, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}

	// Track total scan volume for non-streamed responses as well.
	if c.maxTotalScanBytes > 0 {
		c.totalScanBytes += int64(len(body))
		if c.totalScanBytes > c.maxTotalScanBytes {
			return nil, nil, ErrTotalScanVolumeExceeded
		}
	}

	return body, resp.Header.Clone(), nil
}

// getJSONStream performs a GET request and returns the response Body (caller must Close)
// and headers, allowing streaming decode without buffering the entire payload.
// Non-2xx responses are classified into sentinel errors when possible.
func (c *httpConfluenceClient) getJSONStream(ctx context.Context, reqURL string) (io.ReadCloser, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	if c.username != "" && c.token != "" {
		req.SetBasicAuth(c.username, c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http get: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		defer resp.Body.Close()
		return nil, nil, fmt.Errorf("%s", rateLimitMessage(resp.Header))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if resp.StatusCode == http.StatusUnauthorized {
			switch classifyAuth401(bodyBytes) {
			case authMissingScopes:
				return nil, nil, ErrMissingScopes
			default:
				return nil, nil, fmt.Errorf("%w: invalid username or token", ErrBadCredentials)
			}
		}
		return nil, nil, fmt.Errorf("%w %d: %s", ErrUnexpectedHTTPStatus, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	// Caller must Close.
	return resp.Body, resp.Header.Clone(), nil
}

// classifyAuth401 inspects a 401 JSON body to distinguish missing scopes vs generic unauthorized.
func classifyAuth401(body []byte) string {
	var payload struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &payload)
	msg := strings.ToLower(strings.TrimSpace(payload.Message))
	if strings.Contains(msg, "scope does not match") {
		return authMissingScopes
	}
	return authBadCreds
}

// rateLimitMessage formats a user-friendly message for HTTP 429 responses,
// using the Retry-After header when available (seconds).
func rateLimitMessage(h http.Header) string {
	retryAfter := strings.TrimSpace(h.Get("Retry-After"))
	if retryAfter == "" {
		return "rate limited (429)"
	}
	secs, err := strconv.Atoi(retryAfter) // seconds
	if err != nil || secs < 0 {
		return "rate limited (429)"
	}
	minutes := secs / 60
	seconds := secs % 60
	return fmt.Sprintf("rate limited (429) — retry after %d minute(s) %d second(s)", minutes, seconds)
}

// PageVersion models the "version" object returned by Confluence.
type PageVersion struct {
	Number int `json:"number"`
}

// PageBody contains the Storage-Format body of a page.
type PageBody struct {
	Storage *struct {
		Value string `json:"value"`
	} `json:"storage,omitempty"`
}

// Page represents a Confluence page.
type Page struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Title     string            `json:"title"`
	SpaceID   string            `json:"spaceId"`
	Type      string            `json:"type"`
	Body      PageBody          `json:"body"`
	Links     map[string]string `json:"_links"`
	Version   PageVersion       `json:"version"`
}

// Space represents a Confluence space.
type Space struct {
	ID    string            `json:"id"`
	Key   string            `json:"key"`
	Name  string            `json:"name"`
	Links map[string]string `json:"_links"`
}

// listSpacesResponse models the JSON response returned by /spaces queries.
type listSpacesResponse struct {
	Results []*Space          `json:"results"`
	Links   map[string]string `json:"_links"`
}

type versionEntry struct {
	Number int `json:"number"`
}

// listVersionsResponse models the JSON response returned by /pages/{id}/versions.
type listVersionsResponse struct {
	Results []versionEntry    `json:"results"`
	Links   map[string]string `json:"_links"`
}

// parseSpacesResponse decodes a spaces response and returns the spaces plus any
// "next" URL found in either the Link header or the body _links.next.
func parseSpacesResponse(headers http.Header, body []byte) ([]*Space, string, string, error) {
	var payload listSpacesResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", "", fmt.Errorf("decode spaces: %w", err)
	}
	linkNext := nextURLFromLinkHeader(headers)
	bodyNext := ""
	if payload.Links != nil {
		bodyNext = payload.Links["next"]
	}
	return payload.Results, linkNext, bodyNext, nil
}

// parseVersionsResponse decodes a versions response and returns a slice of
// version numbers plus any "next" URL (Link header or body _links.next).
func parseVersionsResponse(headers http.Header, body []byte) ([]int, string, string, error) {
	var payload listVersionsResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", "", fmt.Errorf("decode versions: %w", err)
	}
	versionNumbers := make([]int, 0, len(payload.Results))
	for _, entry := range payload.Results {
		versionNumbers = append(versionNumbers, entry.Number)
	}
	linkNext := nextURLFromLinkHeader(headers)
	bodyNext := ""
	if payload.Links != nil {
		bodyNext = payload.Links["next"]
	}
	return versionNumbers, linkNext, bodyNext, nil
}

// nextURLFromLinkHeader extracts the rel="next" URL from the Link header.
// It returns an empty string when no such relation is present.
func nextURLFromLinkHeader(h http.Header) string {
	link := h.Get("Link")
	if link == "" {
		return ""
	}
	// Example: Link: </wiki/api/v2/pages?cursor=...>; rel="next", </wiki/api/v2>; rel="base"
	for part := range strings.SplitSeq(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		if i := strings.IndexByte(part, '<'); i >= 0 {
			part = part[i+1:]
			if j := strings.IndexByte(part, '>'); j >= 0 {
				return part[:j]
			}
		}
	}
	return ""
}

// streamPagesFromBody streams the Confluence /pages response,
// calling visit(*Page) for each element in results, and returns body _links.next if present.
func streamPagesFromBody(r io.Reader, visit func(*Page) error) (string, error) {
	dec := json.NewDecoder(r)

	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("decode: top-level token: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return "", fmt.Errorf("decode: expected '{' at top-level")
	}

	var bodyLinksNext string

	for {
		t, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("decode: key token: %w", err)
		}

		if d, ok := t.(json.Delim); ok && d == '}' {
			return bodyLinksNext, nil
		}

		key, ok := t.(string)
		if !ok {
			return "", fmt.Errorf("decode: expected object key")
		}

		switch key {
		case "results":
			if err := decodeResultsArray(dec, visit); err != nil {
				return "", err
			}
		case "_links":
			next, err := decodeLinksNext(dec)
			if err != nil {
				return "", err
			}
			bodyLinksNext = next
		default:
			var skip any
			if err := dec.Decode(&skip); err != nil {
				return "", fmt.Errorf("decode: skip: %w", err)
			}
		}
	}
}

// decodeResultsArray consumes the next token, which must be '[' for a "results"
// array, then stream-decodes each element into a Page and calls visit for it.
// It stops at the closing ']' and returns any decoding or visitor error.
func decodeResultsArray(dec *json.Decoder, visit func(*Page) error) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode: results '[': %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '[' {
		return fmt.Errorf("decode: expected '[' for results")
	}

	for dec.More() {
		var p Page
		if err := dec.Decode(&p); err != nil {
			return fmt.Errorf("decode: page: %w", err)
		}
		if err := visit(&p); err != nil {
			return err
		}
	}

	if tok, err = dec.Token(); err != nil {
		return fmt.Errorf("decode: results ']': %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != ']' {
		return fmt.Errorf("decode: expected closing ']' for results")
	}
	return nil
}

// decodeLinksNext decodes the JSON object that follows the "_links" key and
// returns its "next" value (empty string if absent). It consumes the entire
// object and wraps any decoding error with context.
func decodeLinksNext(dec *json.Decoder) (string, error) {
	var ln map[string]string
	if err := dec.Decode(&ln); err != nil {
		return "", fmt.Errorf("decode: _links: %w", err)
	}
	return ln["next"], nil
}

// baseWithoutCursor returns a shallow copy of inputURL with the "cursor" query
// parameter removed. The original URL is not modified.
func baseWithoutCursor(inputURL *url.URL) *url.URL {
	cloneURL := *inputURL
	queryParams := cloneURL.Query()
	queryParams.Del("cursor")
	cloneURL.RawQuery = queryParams.Encode()
	return &cloneURL
}

// cursorFromURL parses rawURL (absolute or relative) and returns the "cursor"
// query parameter value if present; otherwise returns an empty string.
func cursorFromURL(rawURL string) string {
	if strings.TrimSpace(rawURL) == "" {
		return ""
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsedURL.Query().Get("cursor")
}

// withCursor returns the string form of baseURL with its "cursor" query
// parameter set to cursorValue (overwriting any existing one).
func withCursor(baseURL *url.URL, cursorValue string) string {
	updatedURL := *baseURL
	queryParams := updatedURL.Query()
	queryParams.Set("cursor", cursorValue)
	updatedURL.RawQuery = queryParams.Encode()
	return updatedURL.String()
}

// firstNonEmptyString returns primary if it is non-empty; otherwise fallback.
func firstNonEmptyString(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

// countingReader wraps an io.Reader and tracks:
//   - bytes read for the current API response, enforcing maxAPIResponseBytes
//   - global total bytes read across the scan, enforcing totalLimitBytes.
//
// When a limit is exceeded, subsequent reads return a sentinel error and allow
// callers (streaming decoders) to bail out gracefully.
type countingReader struct {
	r               io.Reader
	apiLimitBytes   int64
	apiConsumed     int64
	totalBytes      *int64
	totalLimitBytes int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n <= 0 {
		return n, err
	}

	if cr.apiLimitBytes > 0 {
		cr.apiConsumed += int64(n)
		if cr.apiConsumed > cr.apiLimitBytes {
			// Surface a sentinel error to the decoder so callers can classify it
			// as warn for this batch.
			return n, ErrAPIResponseTooLarge
		}
	}

	if cr.totalBytes != nil {
		*cr.totalBytes += int64(n)
		if cr.totalLimitBytes > 0 && *cr.totalBytes > cr.totalLimitBytes {
			// Global total-volume limit exceeded.
			return n, ErrTotalScanVolumeExceeded
		}
	}

	return n, err
}
