//go:build goexperiment.jsonv2

package plugins

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"encoding/json/jsontext"
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
}

// httpConfluenceClient is a ConfluenceClient implementation backed by net/http.
// It supports optional Basic Auth using a Confluence email/username and API token.
type httpConfluenceClient struct {
	baseWikiURL string
	httpClient  *http.Client
	username    string
	token       string
	apiBase     string
}

// NewConfluenceClient constructs a ConfluenceClient for the given base wiki URL
// (e.g., https://<company id>.atlassian.net/wiki). If username and token are
// non-empty, requests use HTTP Basic Auth.
func NewConfluenceClient(baseWikiURL, username string, tokenType TokenType, tokenValue string) (ConfluenceClient, error) {
	c := &httpConfluenceClient{
		baseWikiURL: strings.TrimRight(baseWikiURL, "/"),
		httpClient:  &http.Client{Timeout: httpTimeout},
		username:    username,
		token:       tokenValue,
	}
	apiBase, err := c.buildAPIBase(context.Background(), tokenType)
	if err != nil {
		return nil, err
	}
	c.apiBase = apiBase
	return c, nil
}

func (c *httpConfluenceClient) buildAPIBase(ctx context.Context, tokenType TokenType) (string, error) {
	switch tokenType {
	case "", TokenClassic:
		u, err := url.Parse(c.baseWikiURL)
		if err != nil {
			return "", fmt.Errorf("parse base wiki url: %w", err)
		}
		u.Path = path.Join(u.Path, "api", "v2")
		return strings.TrimRight(u.String(), "/"), nil

	case TokenScoped:
		cloudID, err := c.discoverCloudID(ctx)
		if err != nil {
			return "", err
		}
		u, _ := url.Parse("https://api.atlassian.com")
		u.Path = path.Join("/ex/confluence", cloudID, "wiki", "api", "v2")
		return strings.TrimRight(u.String(), "/"), nil

	default:
		return "", fmt.Errorf("unsupported token type %q", tokenType)
	}
}

// https://support.atlassian.com/jira/kb/retrieve-my-atlassian-sites-cloud-id/
func (c *httpConfluenceClient) discoverCloudID(ctx context.Context) (string, error) {
	site, err := url.Parse(c.baseWikiURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	site.RawQuery, site.Fragment = "", ""
	site.Scheme = "https"
	site.Path = "/_edge/tenant_info"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.String(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build tenant_info request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("tenant_info request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("tenant_info http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var tmp struct {
		CloudID string `json:"cloudId"`
	}
	if err := json.UnmarshalRead(resp.Body, &tmp); err != nil {
		return "", fmt.Errorf("decode tenant_info: %w", err)
	}
	if tmp.CloudID == "" {
		return "", fmt.Errorf("tenant_info: empty cloudId")
	}
	return tmp.CloudID, nil
}

// WalkAllPages iterates all accessible pages and calls visit for each Page.
func (c *httpConfluenceClient) WalkAllPages(ctx context.Context, limit int, visit func(*Page) error) error {
	apiURL := c.apiURL("/pages")
	q := apiURL.Query()
	q.Set("limit", strconv.Itoa(limit))
	q.Set("body-format", "storage")
	apiURL.RawQuery = q.Encode()
	return c.walkPagesPaginated(ctx, apiURL.String(), visit)
}

// WalkPagesByIDs iterates the given page IDs and calls visit for each Page.
func (c *httpConfluenceClient) WalkPagesByIDs(ctx context.Context, pageIDs []string, limit int, visit func(*Page) error) error {
	apiURL := c.apiURL("/pages")
	q := apiURL.Query()
	q.Set("limit", strconv.Itoa(limit))
	q.Set("body-format", "storage")
	q.Set("id", strings.Join(pageIDs, ","))
	apiURL.RawQuery = q.Encode()
	return c.walkPagesPaginated(ctx, apiURL.String(), visit)
}

// WalkPagesBySpaceIDs iterates pages across the provided space IDs and calls visit.
func (c *httpConfluenceClient) WalkPagesBySpaceIDs(ctx context.Context, spaceIDs []string, limit int, visit func(*Page) error) error {
	apiURL := c.apiURL("/pages")
	q := apiURL.Query()
	q.Set("limit", strconv.Itoa(limit))
	q.Set("body-format", "storage")
	q.Set("space-id", strings.Join(spaceIDs, ","))
	apiURL.RawQuery = q.Encode()
	return c.walkPagesPaginated(ctx, apiURL.String(), visit)
}

// WalkPageVersions lists version numbers for a page and calls visit for each.
func (c *httpConfluenceClient) WalkPageVersions(ctx context.Context, pageID string, limit int, visit func(int) error) error {
	apiURL := c.apiURL(fmt.Sprintf("/pages/%s/versions", url.PathEscape(pageID)))
	q := apiURL.Query()
	q.Set("limit", strconv.Itoa(limit))
	apiURL.RawQuery = q.Encode()

	// Use generic pager but rebuild next using base+cursor.
	base := baseWithoutCursor(apiURL)
	return walkPaginated[int](
		ctx,
		apiURL.String(),
		c.getJSON,
		func(linkNext, bodyNext string) string {
			cur := firstNonEmptyString(cursorFromURL(linkNext), cursorFromURL(bodyNext))
			if cur == "" {
				return ""
			}
			return withCursor(base, cur)
		},
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

	// Use generic pager but rebuild next using base+cursor.
	base := baseWithoutCursor(apiURL)
	return walkPaginated[*Space](
		ctx,
		apiURL.String(),
		c.getJSON,
		func(linkNext, bodyNext string) string {
			cur := firstNonEmptyString(cursorFromURL(linkNext), cursorFromURL(bodyNext))
			if cur == "" {
				return ""
			}
			return withCursor(base, cur)
		},
		parseSpacesResponse,
		visit,
	)
}

// Generic pager
// Fetches items from initialURL, applies parse, calls visit for each item,
// and advances using resolveNext until there is no next page.
func walkPaginated[T any](
	ctx context.Context,
	initialURL string,
	get func(context.Context, string) ([]byte, http.Header, error),
	resolveNext func(string, string) string,
	parse func(http.Header, []byte) ([]T, string, string, error),
	visit func(T) error,
) error {
	nextURL := initialURL
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
		nextURL = resolveNext(linkNext, bodyNext)
		if nextURL == "" {
			return nil
		}
	}
}

// walkPagesPaginated iterates pages starting from initialURL (streaming decode of results array).
func (c *httpConfluenceClient) walkPagesPaginated(
	ctx context.Context, initialURL string, visit func(*Page) error,
) error {
	// Build a base URL without any cursor, then append the next cursor each time.
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

		// Prefer Link header; body may also include _links.next.
		linkNext := nextURLFromLinkHeader(headers)
		bodyNext, decodeErr := streamPagesFromBody(rc, visit)
		closeErr := rc.Close()
		if decodeErr != nil {
			return decodeErr
		}
		if closeErr != nil {
			return closeErr
		}

		// Extract only the cursor and rebuild the next URL from our base.
		cur := firstNonEmptyString(cursorFromURL(linkNext), cursorFromURL(bodyNext))
		if cur == "" {
			return nil
		}
		nextURL = withCursor(base, cur)
	}
}

// walkSpacesPaginated iterates spaces starting from initialURL
func (c *httpConfluenceClient) walkSpacesPaginated(
	ctx context.Context, initialURL string, visit func(*Space) error,
) error {
	return walkPaginated[*Space](ctx, initialURL, c.getJSON,
		func(linkNext, bodyNext string) string {
			base, err := url.Parse(initialURL)
			if err != nil {
				return ""
			}
			b := baseWithoutCursor(base)
			cur := firstNonEmptyString(cursorFromURL(linkNext), cursorFromURL(bodyNext))
			if cur == "" {
				return ""
			}
			return withCursor(b, cur)
		},
		parseSpacesResponse, visit)
}

// walkVersionsPaginated iterates page versions starting from initialURL.
func (c *httpConfluenceClient) walkVersionsPaginated(
	ctx context.Context, initialURL string, visit func(int) error,
) error {
	return walkPaginated[int](ctx, initialURL, c.getJSON,
		func(linkNext, bodyNext string) string {
			base, err := url.Parse(initialURL)
			if err != nil {
				return ""
			}
			b := baseWithoutCursor(base)
			cur := firstNonEmptyString(cursorFromURL(linkNext), cursorFromURL(bodyNext))
			if cur == "" {
				return ""
			}
			return withCursor(b, cur)
		},
		parseVersionsResponse, visit)
}

// apiURL joins the relative API path to the base wiki URL or the platform host,
// producing a URL rooted at .../api/v2/<relative>.
func (c *httpConfluenceClient) apiURL(relativePath string) *url.URL {
	parsedURL, _ := url.Parse(c.apiBase)
	parsedURL.Path = path.Join(parsedURL.Path, strings.TrimPrefix(relativePath, "/"))
	return parsedURL
}

// getJSON performs a GET request and returns the response body and headers.
// It sets Accept: application/json and uses Basic Auth when credentials were
// provided. Non-2xx responses return an error with a short body snippet.
// HTTP 429 includes a human-friendly message derived from Retry-After.
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
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}
	return body, resp.Header.Clone(), nil
}

// getJSONStream performs a GET request and returns the response Body (caller must Close)
// and headers, allowing streaming decode without buffering the entire payload.
// HTTP errors are handled similarly to getJSON.
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
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	// Caller must Close.
	return resp.Body, resp.Header.Clone(), nil
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

// Page represents a Confluence page
type Page struct {
	ID      string            `json:"id"`
	Status  string            `json:"status"`
	Title   string            `json:"title"`
	SpaceID string            `json:"spaceId"`
	Type    string            `json:"type"`
	Body    PageBody          `json:"body"`
	Links   map[string]string `json:"_links"`
	Version PageVersion       `json:"version"`
}

// Space represents a Confluence space
type Space struct {
	ID    string            `json:"id"`
	Key   string            `json:"key"`
	Name  string            `json:"name"`
	Links map[string]string `json:"_links"`
}

// listPagesResponse models the JSON response returned by /pages queries.
type listPagesResponse struct {
	Results []*Page           `json:"results"`
	Links   map[string]string `json:"_links"`
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
	parts := strings.Split(link, ",")
	for _, part := range parts {
		partTrimmed := strings.TrimSpace(part)
		if !strings.Contains(partTrimmed, `rel="next"`) {
			continue
		}
		start := strings.Index(partTrimmed, "<")
		end := strings.Index(partTrimmed, ">")
		if start >= 0 && end > start+1 {
			return partTrimmed[start+1 : end]
		}
	}
	return ""
}

// streamPagesFromBody streams the Confluence /pages response,
// calling visit(*Page) for each element in results, and returns body _links.next if present.
func streamPagesFromBody(r io.Reader, visit func(*Page) error) (string, error) {
	dec := jsontext.NewDecoder(
		r,
		// jsontext.WithByteLimit(10MiB), // TODO(go.dev/issue/56733): enable when available
	)

	tok, err := dec.ReadToken()
	if err != nil {
		return "", fmt.Errorf("decode: top-level token: %w", err)
	}
	if tok.Kind() != '{' {
		return "", fmt.Errorf("decode: expected '{' at top-level")
	}

	var bodyLinksNext string

	for {
		switch dec.PeekKind() {
		case '}':
			if _, err := dec.ReadToken(); err != nil {
				return "", fmt.Errorf("decode: top-level '}': %w", err)
			}
			return bodyLinksNext, nil
		case '"':
			keyTok, err := dec.ReadToken()
			if err != nil {
				return "", fmt.Errorf("decode: key token: %w", err)
			}
			key := keyTok.String()

			switch key {
			case "results":
				tok, err := dec.ReadToken()
				if err != nil {
					return "", fmt.Errorf("decode: results '[': %w", err)
				}
				if tok.Kind() != '[' {
					return "", fmt.Errorf("decode: expected '[' for results")
				}
				for {
					switch dec.PeekKind() {
					case ']':
						if _, err := dec.ReadToken(); err != nil {
							return "", fmt.Errorf("decode: results ']': %w", err)
						}
						goto nextField
					default:
						var p Page
						if err := json.UnmarshalDecode(dec, &p); err != nil {
							return "", fmt.Errorf("decode: page: %w", err)
						}
						if err := visit(&p); err != nil {
							return "", err
						}
					}
				}
			case "_links":
				var ln map[string]string
				if err := json.UnmarshalDecode(dec, &ln); err != nil {
					return "", fmt.Errorf("decode: _links: %w", err)
				}
				bodyLinksNext = ln["next"]
			default:
				if err := dec.SkipValue(); err != nil {
					return "", fmt.Errorf("decode: skip %q: %w", key, err)
				}
			}
		default:
			return "", fmt.Errorf("decode: unexpected token kind %q", dec.PeekKind())
		}
	nextField:
	}
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
