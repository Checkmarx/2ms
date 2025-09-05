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

type ConfluenceClient interface {
	ListAllPages(ctx context.Context, limit int) ([]Page, error)
	ListPagesByIDs(ctx context.Context, pageIDs []string, limit int) ([]Page, error)
	ListPagesBySpaceIDs(ctx context.Context, spaceIDs []string, limit int) ([]Page, error)
	ListPageVersionNumbers(ctx context.Context, pageID string, limit int) ([]int, error)
	FetchPageVersion(ctx context.Context, pageID string, version int) (Page, error)
	ListSpacesByKeys(ctx context.Context, spaceKeys []string, limit int) ([]Space, error)
}

type httpConfluenceClient struct {
	baseWikiURL string
	httpClient  *http.Client
	username    string
	token       string
}

func (c *httpConfluenceClient) ListAllPages(ctx context.Context, limit int) ([]Page, error) {
	apiURL := c.apiURL("/pages")
	params := apiURL.Query()
	params.Set("limit", strconv.Itoa(limit))
	params.Set("body-format", "storage")
	apiURL.RawQuery = params.Encode()
	return c.collectPagesPaginated(ctx, apiURL.String())
}

func (c *httpConfluenceClient) ListPagesByIDs(ctx context.Context, pageIDs []string, limit int) ([]Page, error) {
	apiURL := c.apiURL("/pages")
	params := apiURL.Query()
	params.Set("limit", strconv.Itoa(limit))
	params.Set("body-format", "storage")
	params.Set("id", strings.Join(pageIDs, ","))
	apiURL.RawQuery = params.Encode()
	return c.collectPagesPaginated(ctx, apiURL.String())
}

func (c *httpConfluenceClient) ListPagesBySpaceIDs(ctx context.Context, spaceIDs []string, limit int) ([]Page, error) {
	apiURL := c.apiURL("/pages")
	params := apiURL.Query()
	params.Set("limit", strconv.Itoa(limit))
	params.Set("body-format", "storage")
	params.Set("space-id", strings.Join(spaceIDs, ","))
	apiURL.RawQuery = params.Encode()
	return c.collectPagesPaginated(ctx, apiURL.String())
}

func (c *httpConfluenceClient) ListPageVersionNumbers(ctx context.Context, pageID string, limit int) ([]int, error) {
	apiURL := c.apiURL(fmt.Sprintf("/pages/%s/versions", url.PathEscape(pageID)))
	params := apiURL.Query()
	params.Set("limit", strconv.Itoa(limit))
	apiURL.RawQuery = params.Encode()
	return c.collectVersionNumbersPaginated(ctx, apiURL.String())
}

func (c *httpConfluenceClient) FetchPageVersion(ctx context.Context, pageID string, version int) (Page, error) {
	apiURL := c.apiURL(fmt.Sprintf("/pages/%s", url.PathEscape(pageID)))
	params := apiURL.Query()
	params.Set("version", strconv.Itoa(version))
	params.Set("body-format", "storage")
	apiURL.RawQuery = params.Encode()

	body, _, err := c.getJSON(ctx, apiURL.String())
	if err != nil {
		return Page{}, err
	}
	var page Page
	if err := json.Unmarshal(body, &page); err != nil {
		return Page{}, fmt.Errorf("decode page version: %w", err)
	}
	return page, nil
}

func (c *httpConfluenceClient) ListSpacesByKeys(ctx context.Context, spaceKeys []string, limit int) ([]Space, error) {
	apiURL := c.apiURL("/spaces")
	params := apiURL.Query()
	params.Set("limit", strconv.Itoa(limit))
	params.Set("keys", strings.Join(spaceKeys, ","))
	apiURL.RawQuery = params.Encode()
	return c.collectSpacesPaginated(ctx, apiURL.String())
}

func (c *httpConfluenceClient) collectPagesPaginated(ctx context.Context, initialURL string) ([]Page, error) {
	var collected []Page
	nextPageURL := initialURL
	for {
		body, headers, err := c.getJSON(ctx, nextPageURL)
		if err != nil {
			return nil, err
		}
		pages, linkNext, bodyNext, perr := parsePagesResponse(headers, body)
		if perr != nil {
			return nil, perr
		}
		collected = append(collected, pages...)
		nextPageURL = c.resolveNextPageURL(linkNext, bodyNext)
		if nextPageURL == "" {
			break
		}
	}
	return collected, nil
}

func (c *httpConfluenceClient) collectVersionNumbersPaginated(ctx context.Context, initialURL string) ([]int, error) {
	var collected []int
	nextPageURL := initialURL
	for {
		body, headers, err := c.getJSON(ctx, nextPageURL)
		if err != nil {
			return nil, err
		}
		versionNumbers, linkNext, bodyNext, parseErr := parseVersionsResponse(headers, body)
		if parseErr != nil {
			return nil, parseErr
		}
		collected = append(collected, versionNumbers...)
		nextPageURL = c.resolveNextPageURL(linkNext, bodyNext)
		if nextPageURL == "" {
			break
		}
	}
	return collected, nil
}

func (c *httpConfluenceClient) collectSpacesPaginated(ctx context.Context, initialURL string) ([]Space, error) {
	var collected []Space
	nextPageURL := initialURL
	for {
		body, headers, err := c.getJSON(ctx, nextPageURL)
		if err != nil {
			return nil, err
		}
		spaces, linkNext, bodyNext, perr := parseSpacesResponse(headers, body)
		if perr != nil {
			return nil, perr
		}
		collected = append(collected, spaces...)
		nextPageURL = c.resolveNextPageURL(linkNext, bodyNext)
		if nextPageURL == "" {
			break
		}
	}
	return collected, nil
}

func (c *httpConfluenceClient) apiURL(relativePath string) *url.URL {
	u, _ := url.Parse(c.baseWikiURL) // base ends with /wiki
	u.Path = path.Join(u.Path, "api", "v2", strings.TrimPrefix(relativePath, "/"))
	return u
}

// prefers Link header `rel="next"`, falls back to body _links.next.
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

// getJSON performs GET and returns response body + headers.
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

func rateLimitMessage(h http.Header) string {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return "rate limited (429)"
	}
	secs, err := strconv.Atoi(raw) // seconds
	if err != nil || secs < 0 {
		return "rate limited (429)"
	}
	minutes := secs / 60
	seconds := secs % 60
	return fmt.Sprintf("rate limited (429) — retry after %d minute(s) %d second(s)", minutes, seconds)
}

type PageVersion struct {
	Number int `json:"number"`
}

type PageBody struct {
	Storage *struct {
		Value string `json:"value"`
	} `json:"storage,omitempty"`
}

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

type Space struct {
	ID    string            `json:"id"`
	Key   string            `json:"key"`
	Name  string            `json:"name"`
	Links map[string]string `json:"_links"`
}

type listPagesResponse struct {
	Results []Page            `json:"results"`
	Links   map[string]string `json:"_links"`
}

type listSpacesResponse struct {
	Results []Space           `json:"results"`
	Links   map[string]string `json:"_links"`
}

type versionEntry struct {
	Number int `json:"number"`
}

type listVersionsResponse struct {
	Results []versionEntry    `json:"results"`
	Links   map[string]string `json:"_links"`
}

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

func nextURLFromLinkHeader(h http.Header) string {
	link := h.Get("Link")
	if link == "" {
		return ""
	}
	// Example: Link: </wiki/api/v2/pages?cursor=...>; rel="next", </wiki/api/v2>; rel="base"
	parts := strings.Split(link, ",")
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if !strings.Contains(p, `rel="next"`) {
			continue
		}
		start := strings.Index(p, "<")
		end := strings.Index(p, ">")
		if start >= 0 && end > start+1 {
			return p[start+1 : end]
		}
	}
	return ""
}
