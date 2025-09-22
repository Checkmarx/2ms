package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// ConfluenceClient defines the operations required by the Confluence plugin.
// Methods stream results via visitor callbacks and handle pagination internally.
type ConfluenceClient interface {
	WalkAllPages(ctx context.Context, limit int, visit func(Page) error) error
	WalkPagesByIDs(ctx context.Context, pageIDs []string, limit int, visit func(Page) error) error
	WalkPagesBySpaceIDs(ctx context.Context, spaceIDs []string, limit int, visit func(Page) error) error
	WalkPageVersions(ctx context.Context, pageID string, limit int, visit func(int) error) error
	FetchPageAtVersion(ctx context.Context, pageID string, version int) (Page, error)
	WalkSpacesByKeys(ctx context.Context, spaceKeys []string, limit int, visit func(Space) error) error
}

// httpConfluenceClient is a ConfluenceClient implementation backed by net/http.
// It supports optional Basic Auth using a Confluence email/username and API token.
type httpConfluenceClient struct {
	baseWikiURL string
	httpClient  *http.Client
	username    string
	token       string
}

// NewConfluenceClient constructs a ConfluenceClient for the given base wiki URL
// (e.g., https://<company id>.atlassian.net/wiki). If username and token are
// non-empty, requests use HTTP Basic Auth.
func NewConfluenceClient(baseWikiURL string, username, token string) ConfluenceClient {
	httpClient := &http.Client{Timeout: httpTimeout}
	return &httpConfluenceClient{
		baseWikiURL: baseWikiURL,
		httpClient:  httpClient,
		username:    username,
		token:       token,
	}
}

// WalkAllPages iterates all accessible pages and calls visit for each Page.
func (c *httpConfluenceClient) WalkAllPages(ctx context.Context, limit int, visit func(Page) error) error {
	apiURL := c.apiURL("/pages")
	query := apiURL.Query()
	query.Set("limit", strconv.Itoa(limit))
	query.Set("body-format", "storage")
	apiURL.RawQuery = query.Encode()
	return c.walkPagesPaginated(ctx, apiURL.String(), visit)
}

// WalkPagesByIDs iterates the given page IDs and calls visit for each Page.
func (c *httpConfluenceClient) WalkPagesByIDs(ctx context.Context, pageIDs []string, limit int, visit func(Page) error) error {
	apiURL := c.apiURL("/pages")
	query := apiURL.Query()
	query.Set("limit", strconv.Itoa(limit))
	query.Set("body-format", "storage")
	query.Set("id", strings.Join(pageIDs, ","))
	apiURL.RawQuery = query.Encode()
	return c.walkPagesPaginated(ctx, apiURL.String(), visit)
}

// WalkPagesBySpaceIDs iterates pages across the provided space IDs and calls visit.
func (c *httpConfluenceClient) WalkPagesBySpaceIDs(ctx context.Context, spaceIDs []string, limit int, visit func(Page) error) error {
	apiURL := c.apiURL("/pages")
	query := apiURL.Query()
	query.Set("limit", strconv.Itoa(limit))
	query.Set("body-format", "storage")
	query.Set("space-id", strings.Join(spaceIDs, ","))
	apiURL.RawQuery = query.Encode()
	return c.walkPagesPaginated(ctx, apiURL.String(), visit)
}

// WalkPageVersions lists version numbers for a page and calls visit for each.
func (c *httpConfluenceClient) WalkPageVersions(ctx context.Context, pageID string, limit int, visit func(int) error) error {
	apiURL := c.apiURL(fmt.Sprintf("/pages/%s/versions", url.PathEscape(pageID)))
	query := apiURL.Query()
	query.Set("limit", strconv.Itoa(limit))
	apiURL.RawQuery = query.Encode()
	return c.walkVersionsPaginated(ctx, apiURL.String(), visit)
}

// FetchPageAtVersion fetches a page at a specific version.
func (c *httpConfluenceClient) FetchPageAtVersion(ctx context.Context, pageID string, version int) (Page, error) {
	apiURL := c.apiURL(fmt.Sprintf("/pages/%s", url.PathEscape(pageID)))
	query := apiURL.Query()
	query.Set("version", strconv.Itoa(version))
	query.Set("body-format", "storage")
	apiURL.RawQuery = query.Encode()

	bodyBytes, _, err := c.getJSON(ctx, apiURL.String())
	if err != nil {
		return Page{}, err
	}
	var page Page
	if err = json.Unmarshal(bodyBytes, &page); err != nil {
		return Page{}, fmt.Errorf("decode page version: %w", err)
	}
	return page, nil
}

// WalkSpacesByKeys lists spaces by their keys and calls visit for each Space.
func (c *httpConfluenceClient) WalkSpacesByKeys(ctx context.Context, spaceKeys []string, limit int, visit func(Space) error) error {
	apiURL := c.apiURL("/spaces")
	query := apiURL.Query()
	query.Set("limit", strconv.Itoa(limit))
	query.Set("keys", strings.Join(spaceKeys, ","))
	apiURL.RawQuery = query.Encode()
	return c.walkSpacesPaginated(ctx, apiURL.String(), visit)
}

// walkPagesPaginated iterates pages starting from initialURL
func (c *httpConfluenceClient) walkPagesPaginated(ctx context.Context, initialURL string, visit func(Page) error) error {
	nextPageURL := initialURL
	for {
		bodyBytes, responseHeaders, err := c.getJSON(ctx, nextPageURL)
		if err != nil {
			return err
		}
		pages, linkHeaderNext, bodyLinksNext, parseErr := parsePagesResponse(responseHeaders, bodyBytes)
		if parseErr != nil {
			return parseErr
		}
		for _, page := range pages {
			if err = visit(page); err != nil {
				return err
			}
		}
		nextPageURL = c.resolveNextPageURL(linkHeaderNext, bodyLinksNext)
		if nextPageURL == "" {
			return nil
		}
	}
}

// walkSpacesPaginated iterates spaces starting from initialURL
func (c *httpConfluenceClient) walkSpacesPaginated(ctx context.Context, initialURL string, visit func(Space) error) error {
	nextPageURL := initialURL
	for {
		bodyBytes, responseHeaders, err := c.getJSON(ctx, nextPageURL)
		if err != nil {
			return err
		}
		spaces, linkHeaderNext, bodyLinksNext, parseErr := parseSpacesResponse(responseHeaders, bodyBytes)
		if parseErr != nil {
			return parseErr
		}
		for _, space := range spaces {
			if err = visit(space); err != nil {
				return err
			}
		}
		nextPageURL = c.resolveNextPageURL(linkHeaderNext, bodyLinksNext)
		if nextPageURL == "" {
			return nil
		}
	}
}

// walkVersionsPaginated iterates page versions starting from initialURL.
func (c *httpConfluenceClient) walkVersionsPaginated(ctx context.Context, initialURL string, visit func(int) error) error {
	nextPageURL := initialURL
	for {
		bodyBytes, responseHeaders, err := c.getJSON(ctx, nextPageURL)
		if err != nil {
			return err
		}
		versionNumbers, linkHeaderNext, bodyLinksNext, parseErr := parseVersionsResponse(responseHeaders, bodyBytes)
		if parseErr != nil {
			return parseErr
		}
		for _, versionNumber := range versionNumbers {
			if err = visit(versionNumber); err != nil {
				return err
			}
		}
		nextPageURL = c.resolveNextPageURL(linkHeaderNext, bodyLinksNext)
		if nextPageURL == "" {
			return nil
		}
	}
}

// apiURL joins the relative API path to the base wiki URL, producing a URL
// rooted at /wiki/api/v2/<relative>.
func (c *httpConfluenceClient) apiURL(relativePath string) *url.URL {
	parsedURL, _ := url.Parse(c.baseWikiURL) // base ends with /wiki
	parsedURL.Path = path.Join(parsedURL.Path, "api", "v2", strings.TrimPrefix(relativePath, "/"))
	return parsedURL
}

// resolveNextPageURL chooses the next page URL, preferring the Link header's
// rel="next" target and falling back to the body _links.next. Relative URLs
// are resolved against the base wiki URL.
func (c *httpConfluenceClient) resolveNextPageURL(linkHeaderNext, bodyLinksNext string) string {
	next := strings.TrimSpace(linkHeaderNext)
	if next == "" {
		next = strings.TrimSpace(bodyLinksNext)
	}
	if next == "" {
		return ""
	}
	ref, err := url.Parse(next)
	if err != nil {
		return ""
	}
	if ref.IsAbs() {
		return ref.String()
	}
	base, _ := url.Parse(c.baseWikiURL)
	return base.ResolveReference(ref).String()
}

// getJSON performs a GET request and returns the response body and headers.
// It sets Accept: application/json and uses Basic Auth when credentials were
// provided. Non-2xx responses return an error with a short body snippet.
// HTTP 429 includes a human-friendly message derived from Retry-After.
func (c *httpConfluenceClient) getJSON(ctx context.Context, reqURL string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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
	Results []Page            `json:"results"`
	Links   map[string]string `json:"_links"`
}

// listSpacesResponse models the JSON response returned by /spaces queries.
type listSpacesResponse struct {
	Results []Space           `json:"results"`
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

// parsePagesResponse decodes a pages response and returns the pages plus any
// "next" URL found in either the Link header or the body _links.next.
func parsePagesResponse(headers http.Header, body []byte) ([]Page, string, string, error) {
	var payload listPagesResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", "", fmt.Errorf("decode pages: %w", err)
	}
	linkNext := nextURLFromLinkHeader(headers)
	bodyNext := ""
	if payload.Links != nil {
		bodyNext = payload.Links["next"]
	}
	return payload.Results, linkNext, bodyNext, nil
}

// parseSpacesResponse decodes a spaces response and returns the spaces plus any
// "next" URL found in either the Link header or the body _links.next.
func parseSpacesResponse(headers http.Header, body []byte) ([]Space, string, string, error) {
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
