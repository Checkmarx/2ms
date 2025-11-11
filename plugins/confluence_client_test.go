package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildAPIBase(t *testing.T) {
	tlsTenant := func(cloudID string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_edge/tenant_info" {
				_, _ = w.Write([]byte(`{"cloudId":"` + cloudID + `"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
	}

	tests := []struct {
		name         string
		setup        func() *httpConfluenceClient
		expectedBase string
		expectedErr  error
	}{
		{
			name: "discovers cloudId",
			setup: func() *httpConfluenceClient {
				ts := tlsTenant("abc-123")
				t.Cleanup(ts.Close)
				base, _ := url.Parse(ts.URL)
				base.Path = "/wiki"
				return &httpConfluenceClient{
					baseWikiURL: base.String(),
					httpClient:  ts.Client(), // trust the TLS test server
				}
			},
			expectedBase: "https://api.atlassian.com/ex/confluence/abc-123/wiki/api/v2",
			expectedErr:  nil,
		},
		{
			name: "discoverCloudID error",
			setup: func() *httpConfluenceClient {
				// TLS server that returns 500 for /_edge/tenant_info
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/_edge/tenant_info" {
						http.Error(w, "boom", http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				t.Cleanup(ts.Close)

				base, _ := url.Parse(ts.URL)
				base.Path = "/wiki"
				return &httpConfluenceClient{
					baseWikiURL: base.String(),
					httpClient:  ts.Client(), // trust test server
				}
			},
			expectedBase: "",
			expectedErr:  ErrBaseURLInvalidOrUnreachable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.setup()
			actualBase, err := c.buildAPIBase(context.Background())
			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedBase, actualBase)
		})
	}
}

func TestDiscoverCloudID(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		setup       func(t *testing.T) (*httpConfluenceClient, func())
		expectedID  string
		expectedErr error
	}{
		{
			name: "success",
			setup: func(t *testing.T) (*httpConfluenceClient, func()) {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/_edge/tenant_info", r.URL.Path)
					_, _ = io.WriteString(w, `{"cloudId":"abc-123"}`)
				}))
				// base has /wiki just like real-world usage
				base, _ := url.Parse(ts.URL)
				base.Path = "/wiki"
				c := &httpConfluenceClient{
					baseWikiURL: base.String(),
					httpClient:  ts.Client(),
				}
				return c, ts.Close
			},
			expectedID:  "abc-123",
			expectedErr: nil,
		},
		{
			name: "parse base url error",
			setup: func(t *testing.T) (*httpConfluenceClient, func()) {
				c := &httpConfluenceClient{
					baseWikiURL: "http://[::1", // invalid
					httpClient:  &http.Client{Timeout: 5 * time.Second},
				}
				return c, func() {}
			},
			expectedID:  "",
			expectedErr: fmt.Errorf("parse \"http://[::1\": missing ']' in host"),
		},
		{
			name: "client do error",
			setup: func(t *testing.T) (*httpConfluenceClient, func()) {
				c := &httpConfluenceClient{
					baseWikiURL: "https://127.0.0.1:1/wiki",
					httpClient:  &http.Client{Timeout: 200 * time.Millisecond},
				}
				return c, func() {}
			},
			expectedID:  "",
			expectedErr: ErrBaseURLInvalidOrUnreachable,
		},
		{
			name: "non-200 http with snippet",
			setup: func(t *testing.T) (*httpConfluenceClient, func()) {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/_edge/tenant_info", r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, "fail")
				}))
				base, _ := url.Parse(ts.URL)
				base.Path = "/wiki"
				c := &httpConfluenceClient{
					baseWikiURL: base.String(),
					httpClient:  ts.Client(),
				}
				return c, ts.Close
			},
			expectedID:  "",
			expectedErr: ErrBaseURLInvalidOrUnreachable,
		},
		{
			name: "decode error",
			setup: func(t *testing.T) (*httpConfluenceClient, func()) {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/_edge/tenant_info", r.URL.Path)
					_, _ = io.WriteString(w, "{") // invalid JSON
				}))
				base, _ := url.Parse(ts.URL)
				base.Path = "/wiki"
				c := &httpConfluenceClient{
					baseWikiURL: base.String(),
					httpClient:  ts.Client(),
				}
				return c, ts.Close
			},
			expectedID:  "",
			expectedErr: ErrBaseURLInvalidOrUnreachable,
		},
		{
			name: "empty cloudId",
			setup: func(t *testing.T) (*httpConfluenceClient, func()) {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/_edge/tenant_info", r.URL.Path)
					_, _ = io.WriteString(w, `{"cloudId":""}`)
				}))
				base, _ := url.Parse(ts.URL)
				base.Path = "/wiki"
				c := &httpConfluenceClient{
					baseWikiURL: base.String(),
					httpClient:  ts.Client(),
				}
				return c, ts.Close
			},
			expectedID:  "",
			expectedErr: ErrBaseURLInvalidOrUnreachable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, cleanup := tc.setup(t)
			defer cleanup()

			actualID, err := c.discoverCloudID(context.Background())
			assert.Equal(t, tc.expectedID, actualID)
			if tc.name == "parse base url error" || tc.name == "client do error" {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}
		})
	}
}

func TestAPIURL(t *testing.T) {
	tests := []struct {
		name         string
		apiBase      string
		inPath       string
		expectedFull string
	}{
		{
			name:         "leading slash",
			apiBase:      "https://example.test/wiki/api/v2",
			inPath:       "/pages",
			expectedFull: "https://example.test/wiki/api/v2/pages",
		},
		{
			name:         "missing leading slash",
			apiBase:      "https://example.test/wiki/api/v2",
			inPath:       "pages",
			expectedFull: "https://example.test/wiki/api/v2/pages",
		},
		{
			name:         "trailing slash base ok",
			apiBase:      "https://example.test/wiki/api/v2/",
			inPath:       "/pages",
			expectedFull: "https://example.test/wiki/api/v2/pages",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &httpConfluenceClient{apiBase: tc.apiBase}
			actual := c.apiURL(tc.inPath).String()
			assert.Equal(t, tc.expectedFull, actual)
		})
	}
}

func TestNextURLFromLinkHeader(t *testing.T) {
	tests := []struct {
		name         string
		link         string
		expectedNext string
	}{
		{
			name:         `has rel="next"`,
			link:         `</wiki/api/v2/pages?cursor=foo>; rel="base", </wiki/api/v2/pages?cursor=bar>; rel="next"`,
			expectedNext: "/wiki/api/v2/pages?cursor=bar",
		},
		{
			name:         `has rel="next" but it is empty`,
			link:         `</wiki/api/v2/pages?cursor=foo>; rel="base", ; rel="next"`,
			expectedNext: "",
		},
		{
			name:         "empty header",
			link:         "",
			expectedNext: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.link != "" {
				h.Set("Link", tc.link)
			}
			actual := nextURLFromLinkHeader(h)
			assert.Equal(t, tc.expectedNext, actual)
		})
	}
}

func TestRateLimitMessage(t *testing.T) {
	tests := []struct {
		name         string
		retryAfter   string
		expectedText string
	}{
		{
			name:         "seconds to minutes+seconds",
			retryAfter:   "75",
			expectedText: "rate limited (429) — retry after 1 minute(s) 15 second(s)",
		},
		{
			name:         "invalid value",
			retryAfter:   "NotANumber",
			expectedText: "rate limited (429)",
		},
		{
			name:         "no header",
			retryAfter:   "",
			expectedText: "rate limited (429)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.retryAfter != "" {
				h.Set("Retry-After", tc.retryAfter)
			}
			actual := rateLimitMessage(h)
			assert.Equal(t, tc.expectedText, actual)
		})
	}
}

func TestBaseWithoutCursor(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "remove only cursor",
			raw:      "https://x.test/wiki/api/v2/pages?cursor=abc&limit=10",
			expected: "https://x.test/wiki/api/v2/pages?limit=10",
		},
		{
			name:     "no cursor present",
			raw:      "https://x.test/wiki/api/v2/pages?limit=10",
			expected: "https://x.test/wiki/api/v2/pages?limit=10",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse(tc.raw)
			actual := baseWithoutCursor(u).String()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestCursorFromURL(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected string
	}{
		{
			name:     "relative with cursor",
			rawURL:   "/wiki/api/v2/pages?cursor=abc",
			expected: "abc",
		},
		{
			name:     "empty",
			rawURL:   "",
			expected: "",
		},
		{
			name:     "invalid url",
			rawURL:   "%",
			expected: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := cursorFromURL(tc.rawURL)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestWithCursor(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		cur          string
		expectedFull string
	}{
		{
			name:         "add cursor",
			raw:          "https://x.test/wiki/api/v2/pages?limit=10",
			cur:          "next",
			expectedFull: "https://x.test/wiki/api/v2/pages?limit=10&cursor=next",
		},
		{
			name:         "overwrite cursor",
			raw:          "https://x.test/wiki/api/v2/pages?cursor=old",
			cur:          "new",
			expectedFull: "https://x.test/wiki/api/v2/pages?cursor=new",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse(tc.raw)
			actual := withCursor(u, tc.cur)

			actualURL, err := url.Parse(actual)
			assert.NoError(t, err)

			expectedURL, err := url.Parse(tc.expectedFull)
			assert.NoError(t, err)

			assert.Equal(t, expectedURL.Scheme, actualURL.Scheme)
			assert.Equal(t, expectedURL.Host, actualURL.Host)
			assert.Equal(t, expectedURL.Path, actualURL.Path)
			assert.Equal(t, expectedURL.Query(), actualURL.Query())
		})
	}
}

func TestFirstNonEmptyString(t *testing.T) {
	tests := []struct {
		name     string
		first    string
		second   string
		expected string
	}{
		{
			name:     "primary",
			first:    "a",
			second:   "b",
			expected: "a",
		},
		{
			name:     "fallback",
			first:    "",
			second:   "b",
			expected: "b",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := firstNonEmptyString(tc.first, tc.second)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestWalkPaginated(t *testing.T) {
	type step struct {
		getErr   error
		parseErr error
		items    []int
		linkNext string
		bodyNext string
	}

	tests := []struct {
		name          string
		steps         []step
		visitErrOnVal *int
		expected      []int
		expectedErr   error
	}{
		{
			name: "uses bodyNext then ends",
			steps: []step{
				{items: []int{1, 2}, bodyNext: "/api?cursor=two"},
				{items: []int{3}},
			},
			expected: []int{1, 2, 3},
		},
		{
			name: "get error on first call",
			steps: []step{
				{getErr: assert.AnError},
			},
			expectedErr: assert.AnError,
		},
		{
			name: "parse error on first call",
			steps: []step{
				{parseErr: assert.AnError},
			},
			expectedErr: assert.AnError,
		},
		{
			name: "visit error on first item",
			steps: []step{
				{items: []int{42}},
			},
			visitErrOnVal: func() *int { v := 42; return &v }(),
			expectedErr:   assert.AnError,
		},
		{
			name: "no next stops after first page",
			steps: []step{
				{items: []int{1, 2}},
			},
			expected: []int{1, 2},
		},
		{
			name: "next present but without cursor then stops",
			steps: []step{
				{items: []int{1}, linkNext: "/api?foo=bar"},
			},
			expected: []int{1},
		},
		{
			name: "prefers linkNext over bodyNext",
			steps: []step{
				{items: []int{1}, linkNext: "/api?cursor=two", bodyNext: "/api?cursor=ignored"},
				{items: []int{2}},
			},
			expected: []int{1, 2},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			i := 0

			get := func(ctx context.Context, _ string) ([]byte, http.Header, error) {
				st := tc.steps[i]
				if st.getErr != nil {
					return nil, nil, st.getErr
				}
				return nil, http.Header{}, nil
			}

			parse := func(_ http.Header, _ []byte) ([]int, string, string, error) {
				st := tc.steps[i]
				i++
				if st.parseErr != nil {
					return nil, "", "", st.parseErr
				}
				return st.items, st.linkNext, st.bodyNext, nil
			}

			var actualVersions []int
			visit := func(n int) error {
				if tc.visitErrOnVal != nil && n == *tc.visitErrOnVal {
					return assert.AnError
				}
				actualVersions = append(actualVersions, n)
				return nil
			}

			start, _ := url.Parse("https://example.test/api")
			err := walkPaginated[int](context.Background(), start, get, parse, visit)

			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expected, actualVersions)
		})
	}
}

func TestStreamPagesFromBody(t *testing.T) {
	tests := []struct {
		name              string
		jsonInput         string
		visit             func(*Page) error
		expectedErr       error
		expectedVisited   []string
		expectedNext      string
		useContainsForErr bool
	}{
		{
			name: "results + _links.next",
			jsonInput: `{
				"results": [
					{"id":"1","title":"A","body":{"storage":{"value":"x"}},"_links":{"self":"/s1"}},
					{"id":"2","title":"B","body":{"storage":{"value":"y"}},"_links":{"self":"/s2"}}
				],
				"_links": {"next": "/wiki/api/v2/pages?cursor=next"}
			}`,
			visit:           func(*Page) error { return nil },
			expectedErr:     nil,
			expectedVisited: []string{"1", "2"},
			expectedNext:    "/wiki/api/v2/pages?cursor=next",
		},
		{
			name:        "top-level ReadToken() fails",
			jsonInput:   ``,
			visit:       func(*Page) error { return nil },
			expectedErr: io.EOF,
		},
		{
			name:              "top-level token not '{'",
			jsonInput:         `[]`,
			visit:             func(*Page) error { return nil },
			expectedErr:       fmt.Errorf("decode: expected '{' at top-level"),
			useContainsForErr: true,
		},
		{
			name:              "unexpected token kind after '{'",
			jsonInput:         `{ 1 }`,
			visit:             func(*Page) error { return nil },
			expectedErr:       fmt.Errorf("decode: key token"),
			useContainsForErr: true,
		},
		{
			name:              "key token ReadToken() fails",
			jsonInput:         `{"`,
			visit:             func(*Page) error { return nil },
			expectedErr:       fmt.Errorf("decode: key token"),
			useContainsForErr: true,
		},
		{
			name: "results decode error (not an array)",
			jsonInput: `{
				"results": {},
				"_links": {"next": "/wiki/api/v2/pages?cursor=n"}
			}`,
			visit:             func(*Page) error { return nil },
			expectedErr:       fmt.Errorf("decode: expected '[' for results"),
			useContainsForErr: true,
		},
		{
			name: "_links decode error (invalid type)",
			jsonInput: `{
				"results": [],
				"_links": 123
			}`,
			visit:             func(*Page) error { return nil },
			expectedErr:       fmt.Errorf("decode: _links"),
			useContainsForErr: true,
		},
		{
			name: "visitor returns error (propagated)",
			jsonInput: `{
				"results": [{"id":"42","title":"Only"}]
			}`,
			visit: func(*Page) error {
				return assert.AnError
			},
			expectedErr:     assert.AnError,
			expectedVisited: nil,
		},
		{
			name: "unknown key is skipped",
			jsonInput: `{
				"ignore_me": {"nested":{"deep": [1,2,3]}},
				"results": [{"id":"99","title":"X"}]
			}`,
			visit:           func(*Page) error { return nil },
			expectedErr:     nil,
			expectedVisited: []string{"99"},
			expectedNext:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var actualVisited []string

			next, err := streamPagesFromBody(strings.NewReader(tc.jsonInput), func(p *Page) error {
				if tc.visit != nil {
					if e := tc.visit(p); e != nil {
						return e
					}
				}
				actualVisited = append(actualVisited, p.ID)
				return nil
			})

			if tc.useContainsForErr {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}
			assert.Equal(t, tc.expectedVisited, actualVisited)
			assert.Equal(t, tc.expectedNext, next)
		})
	}
}

func TestParseSpacesResponse(t *testing.T) {
	tests := []struct {
		name              string
		headers           http.Header
		body              string
		expectedIDs       []string
		expectedLinkNext  string
		expectedBodyNext  string
		expectedErr       error
		useContainsForErr bool
	}{
		{
			name: "link header and body _links.next",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Link", `</wiki/api/v2/spaces?cursor=1>; rel="next"`)
				return h
			}(),
			body:             `{"results":[{"id":"S1","key":"K1"}],"_links":{"next":"/wiki/api/v2/spaces?cursor=2"}}`,
			expectedIDs:      []string{"S1"},
			expectedLinkNext: "/wiki/api/v2/spaces?cursor=1",
			expectedBodyNext: "/wiki/api/v2/spaces?cursor=2",
		},
		{
			name:        "no link header or _links in body",
			headers:     http.Header{},
			body:        `{"results":[{"id":"S9","key":"K9"}]}`,
			expectedIDs: []string{"S9"},
		},
		{
			name:              "decode spaces error",
			headers:           http.Header{},
			body:              `{`,
			expectedErr:       fmt.Errorf(""),
			useContainsForErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spaces, linkNext, bodyNext, err := parseSpacesResponse(tc.headers, []byte(tc.body))

			if tc.useContainsForErr {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}

			var actualIDs []string
			for _, s := range spaces {
				actualIDs = append(actualIDs, s.ID)
			}
			assert.Equal(t, tc.expectedIDs, actualIDs)
			assert.Equal(t, tc.expectedLinkNext, linkNext)
			assert.Equal(t, tc.expectedBodyNext, bodyNext)
		})
	}
}

func TestParseVersionsResponse(t *testing.T) {
	tests := []struct {
		name              string
		headers           http.Header
		body              string
		expectedVersions  []int
		expectedLinkNext  string
		expectedBodyNext  string
		expectedErr       error
		useContainsForErr bool
	}{
		{
			name: "link header and body _links.next",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Link", `</wiki/api/v2/pages/123/versions?cursor=1>; rel="next"`)
				return h
			}(),
			body:             `{"results":[{"number":3},{"number":2},{"number":1}],"_links":{"next":"/wiki/api/v2/pages/123/versions?cursor=2"}}`,
			expectedVersions: []int{3, 2, 1},
			expectedLinkNext: "/wiki/api/v2/pages/123/versions?cursor=1",
			expectedBodyNext: "/wiki/api/v2/pages/123/versions?cursor=2",
		},
		{
			name:             "no link header or _links in body",
			headers:          http.Header{},
			body:             `{"results":[{"number":7},{"number":6}]}`,
			expectedVersions: []int{7, 6},
		},
		{
			name:              "decode versions error ",
			headers:           http.Header{},
			body:              `{`,
			expectedErr:       fmt.Errorf("unexpected end of JSON input"),
			useContainsForErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			versions, linkNext, bodyNext, err := parseVersionsResponse(tc.headers, []byte(tc.body))

			if tc.useContainsForErr {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}

			assert.Equal(t, tc.expectedVersions, versions)
			assert.Equal(t, tc.expectedLinkNext, linkNext)
			assert.Equal(t, tc.expectedBodyNext, bodyNext)
		})
	}
}
func TestGetJSON(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		token          string
		setupServer    func(t *testing.T) *httptest.Server
		expectedErr    error
		expectedHeader string
	}{
		{
			name:     "success with auth and Accept header",
			username: "user",
			token:    "token",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Validate headers
					expAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:token"))
					assert.Equal(t, expAuth, r.Header.Get("Authorization"))
					assert.Equal(t, "application/json", r.Header.Get("Accept"))
					w.Header().Set("Link", "mockLink")
					_, _ = w.Write([]byte(`{"ok":true}`))
				}))
			},
			expectedErr:    nil,
			expectedHeader: "mockLink",
		},
		{
			name: "429 returns friendly error",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Retry-After", "120")
					w.WriteHeader(http.StatusTooManyRequests)
				}))
			},
			expectedErr:    fmt.Errorf("rate limited (429) — retry after 2 minute(s) 0 second(s)"),
			expectedHeader: "",
		},
		{
			name: "non-2xx returns snippet",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "something went wrong", http.StatusInternalServerError)
				}))
			},
			expectedErr:    ErrUnexpectedHTTPStatus,
			expectedHeader: "",
		},
		{
			name: "no auth header when username/token empty",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "", r.Header.Get("Authorization"))
					_, _ = w.Write([]byte(`{}`))
				}))
			},
			expectedErr:    nil,
			expectedHeader: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := tc.setupServer(t)
			defer ts.Close()

			client := &httpConfluenceClient{
				baseWikiURL: ts.URL + "/wiki",
				httpClient:  &http.Client{Timeout: 5 * time.Second},
				username:    tc.username,
				token:       tc.token,
			}

			_, headers, err := client.getJSON(context.Background(), ts.URL)
			if tc.name == "429 returns friendly error" {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}

			var actualHeader string
			if headers != nil {
				actualHeader = headers.Get("Link")
			}
			assert.Equal(t, tc.expectedHeader, actualHeader)
		})
	}
}

func TestGetJSONStream(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		token          string
		setupServer    func(t *testing.T) *httptest.Server
		expectedErr    error
		expectedHeader string
		expectedBody   string
	}{
		{
			name:     "success returns ReadCloser and headers",
			username: "u",
			token:    "p",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					expAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
					assert.Equal(t, expAuth, r.Header.Get("Authorization"))
					assert.Equal(t, "application/json", r.Header.Get("Accept"))
					w.Header().Set("Link", "mockLink")
					_, _ = w.Write([]byte(`{"ok":true}`))
				}))
			},
			expectedErr:    nil,
			expectedHeader: "mockLink",
			expectedBody:   `{"ok":true}`,
		},
		{
			name: "429 returns friendly error",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Retry-After", "5")
					w.WriteHeader(http.StatusTooManyRequests)
				}))
			},
			expectedErr:    fmt.Errorf("rate limited (429) — retry after 0 minute(s) 5 second(s)"),
			expectedHeader: "",
			expectedBody:   "",
		},
		{
			name: "non-2xx returns snippet",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "simulated error", http.StatusBadRequest)
				}))
			},
			expectedErr:    ErrUnexpectedHTTPStatus,
			expectedHeader: "",
			expectedBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := tc.setupServer(t)
			defer ts.Close()

			c := &httpConfluenceClient{
				httpClient: &http.Client{Timeout: 5 * time.Second},
				username:   tc.username,
				token:      tc.token,
			}
			rc, headers, err := c.getJSONStream(context.Background(), ts.URL)
			if tc.name == "429 returns friendly error" {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}

			var actualHeader string
			if headers != nil {
				actualHeader = headers.Get("Link")
			}
			assert.Equal(t, tc.expectedHeader, actualHeader)

			var actualBody string
			if rc != nil {
				defer rc.Close()
				b, _ := io.ReadAll(rc)
				actualBody = strings.TrimSpace(string(b))
			}
			assert.Equal(t, strings.TrimSpace(tc.expectedBody), actualBody)
		})
	}
}

func TestWalkPagesPaginated(t *testing.T) {
	var calls int
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			// First page + Link header with a next cursor
			w.Header().Set("Link", fmt.Sprintf("<%s/wiki/api/v2/pages?cursor=next>; rel=\"next\"", ts.URL))
			_, _ = io.WriteString(w, `{"results":[{"id":"1","title":"A"},{"id":"2","title":"B"}]}`)
		default:
			_, _ = io.WriteString(w, `{"results":[{"id":"3","title":"C"}]}`)
		}
	}))
	defer ts.Close()

	c := &httpConfluenceClient{
		baseWikiURL: ts.URL + "/wiki",
		apiBase:     ts.URL + "/wiki/api/v2",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}

	var actualIDs []string
	actualErr := c.walkPagesPaginated(context.Background(), ts.URL, func(p *Page) error {
		actualIDs = append(actualIDs, p.ID)
		return nil
	})
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []string{"1", "2", "3"}, actualIDs)
}

func TestWalkAllPages(t *testing.T) {
	expectPath := "/wiki/api/v2/pages"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "250", r.URL.Query().Get("limit"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_, _ = io.WriteString(w, `{"results":[{"id":"1","title":"A"},{"id":"2","title":"B"}]}`)
	}))
	defer ts.Close()

	client := &httpConfluenceClient{
		baseWikiURL: ts.URL + "/wiki",
		apiBase:     ts.URL + "/wiki/api/v2",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	var actual []string
	actualErr := client.WalkAllPages(context.Background(), 250, func(p *Page) error {
		actual = append(actual, p.ID)
		return nil
	})
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []string{"1", "2"}, actual)
}

func TestWalkPagesByIDs(t *testing.T) {
	expectPath := "/wiki/api/v2/pages"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("limit"))
		assert.Equal(t, "10,20", r.URL.Query().Get("id"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_, _ = io.WriteString(w, `{"results":[{"id":"10"},{"id":"20"}]}`)
	}))
	defer ts.Close()

	client := &httpConfluenceClient{
		baseWikiURL: ts.URL + "/wiki",
		apiBase:     ts.URL + "/wiki/api/v2",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	var actual []string
	actualErr := client.WalkPagesByIDs(context.Background(), []string{"10", "20"}, 2, func(p *Page) error {
		actual = append(actual, p.ID)
		return nil
	})
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []string{"10", "20"}, actual)
}

func TestWalkPagesBySpaceIDs(t *testing.T) {
	expectPath := "/wiki/api/v2/pages"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("limit"))
		assert.Equal(t, "S1,S2", r.URL.Query().Get("space-id"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_, _ = io.WriteString(w, `{"results":[{"id":"100"},{"id":"200"}]}`)
	}))
	defer ts.Close()

	client := &httpConfluenceClient{
		baseWikiURL: ts.URL + "/wiki",
		apiBase:     ts.URL + "/wiki/api/v2",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	var actual []string
	actualErr := client.WalkPagesBySpaceIDs(context.Background(), []string{"S1", "S2"}, 2, func(p *Page) error {
		actual = append(actual, p.ID)
		return nil
	})
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []string{"100", "200"}, actual)
}

func TestWalkPageVersions(t *testing.T) {
	expectPath := "/wiki/api/v2/pages/123/versions"
	resp := listVersionsResponse{Results: []versionEntry{{Number: 2}, {Number: 1}}}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "50", r.URL.Query().Get("limit"))
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{
		baseWikiURL: testServer.URL + "/wiki",
		apiBase:     testServer.URL + "/wiki/api/v2",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	var actual []int
	actualErr := client.WalkPageVersions(context.Background(), "123", 50, func(n int) error {
		actual = append(actual, n)
		return nil
	})
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []int{2, 1}, actual)
}

func TestFetchPageAtVersion(t *testing.T) {
	expectPath := "/wiki/api/v2/pages/123"

	expected := mkPage("123", 7)

	tests := []struct {
		name              string
		handler           http.HandlerFunc
		expectedErr       error
		useContainsForErr bool
		expectedPage      *Page
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, expectPath, r.URL.Path)
				assert.Equal(t, "7", r.URL.Query().Get("version"))
				assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
				_ = json.NewEncoder(w).Encode(expected)
			},
			expectedErr:  nil,
			expectedPage: expected,
		},
		{
			name: "getJSON error (non-2xx)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, expectPath, r.URL.Path)
				assert.Equal(t, "7", r.URL.Query().Get("version"))
				assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			expectedErr:  ErrUnexpectedHTTPStatus,
			expectedPage: nil,
		},
		{
			name: "decode error (invalid JSON)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, expectPath, r.URL.Path)
				assert.Equal(t, "7", r.URL.Query().Get("version"))
				assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
				_, _ = io.WriteString(w, "{")
			},
			expectedErr:       fmt.Errorf("unexpected end of JSON input"),
			useContainsForErr: true,
			expectedPage:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			client := &httpConfluenceClient{
				baseWikiURL: ts.URL + "/wiki",
				apiBase:     ts.URL + "/wiki/api/v2",
				httpClient:  &http.Client{Timeout: 5 * time.Second},
			}

			actualPage, err := client.FetchPageAtVersion(context.Background(), "123", 7)

			if tc.useContainsForErr {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}
			assert.Equal(t, tc.expectedPage, actualPage)
		})
	}
}

func TestWalkSpacesByKeys(t *testing.T) {
	expectPath := "/wiki/api/v2/spaces"
	resp := listSpacesResponse{
		Results: []*Space{
			{ID: "S1", Key: "KEY1"},
			{ID: "S2", Key: "KEY2"},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("limit"))
		assert.Equal(t, "KEY1,KEY2", r.URL.Query().Get("keys"))
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := &httpConfluenceClient{
		baseWikiURL: ts.URL + "/wiki",
		apiBase:     ts.URL + "/wiki/api/v2",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}

	var actual []string
	actualErr := client.WalkSpacesByKeys(context.Background(), []string{"KEY1", "KEY2"}, 2, func(s *Space) error {
		actual = append(actual, s.ID)
		return nil
	})

	assert.Equal(t, nil, actualErr)
	expected := []string{"S1", "S2"}
	assert.Equal(t, expected, actual)
}

func TestWikiBaseURL(t *testing.T) {
	client := &httpConfluenceClient{
		baseWikiURL: "wikiURL",
	}

	actual := client.WikiBaseURL()
	assert.Equal(t, "wikiURL", actual)
}

func TestDecodeResultsArray(t *testing.T) {
	makeDec := func(s string) *json.Decoder {
		return json.NewDecoder(strings.NewReader(s))
	}

	tests := []struct {
		name              string
		jsonInput         string
		visit             func(*Page) error
		expectedErr       error
		expectedVisited   []string
		useContainsForErr bool
	}{
		{
			name:        "readToken error at start",
			jsonInput:   "",
			visit:       func(*Page) error { return nil },
			expectedErr: io.EOF,
		},
		{
			name:              "first token not '['",
			jsonInput:         `{}`, // object instead of array
			visit:             func(*Page) error { return nil },
			expectedErr:       fmt.Errorf("decode: expected '[' for results"),
			useContainsForErr: true,
		},
		{
			name:              "element decode error",
			jsonInput:         `["not-an-object"]`,
			visit:             func(*Page) error { return nil },
			expectedErr:       fmt.Errorf("decode: page"),
			useContainsForErr: true,
		},
		{
			name:      "visitor returns error",
			jsonInput: `[{"id":"1","title":"A"}]`,
			visit: func(*Page) error {
				return assert.AnError
			},
			expectedErr: assert.AnError,
		},
		{
			name:            "success empty array",
			jsonInput:       `[]`,
			visit:           func(*Page) error { return nil },
			expectedVisited: nil,
			expectedErr:     nil,
		},
		{
			name:      "success with two pages",
			jsonInput: `[{"id":"1","title":"A"},{"id":"2","title":"B"}]`,
			visit: func(p *Page) error {
				return nil
			},
			expectedVisited: []string{"1", "2"},
			expectedErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualVisited []string
			dec := makeDec(tt.jsonInput)

			visit := func(p *Page) error {
				if tt.visit != nil {
					if err := tt.visit(p); err != nil {
						return err
					}
				}
				actualVisited = append(actualVisited, p.ID)
				return nil
			}

			err := decodeResultsArray(dec, visit)

			if tt.useContainsForErr {
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedVisited, actualVisited)
		})
	}
}

func TestDecodeLinksNext(t *testing.T) {
	tests := []struct {
		name         string
		jsonObj      string
		expectedNext string
		expectedErr  error
	}{
		{
			name:         "decode next",
			jsonObj:      `{"next":"/wiki/api/v2/pages?cursor=abc"}`,
			expectedNext: "/wiki/api/v2/pages?cursor=abc",
			expectedErr:  nil,
		},
		{
			name:        "error decoding",
			jsonObj:     `{`,
			expectedErr: io.ErrUnexpectedEOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := json.NewDecoder(strings.NewReader(tc.jsonObj))

			actualNext, err := decodeLinksNext(dec)

			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedNext, actualNext)
		})
	}
}

func TestNormalizeWikiBase(t *testing.T) {
	tests := []struct {
		name              string
		in                string
		expected          string
		expectedErr       error
		useContainsForErr bool
	}{
		{
			name:     "site root → /wiki",
			in:       "https://tenant.atlassian.net",
			expected: "https://tenant.atlassian.net/wiki",
		},
		{
			name:     "/wiki with trailing slash",
			in:       "https://tenant.atlassian.net/wiki/",
			expected: "https://tenant.atlassian.net/wiki",
		},
		{
			name:     "force https scheme",
			in:       "http://tenant.atlassian.net/wiki",
			expected: "https://tenant.atlassian.net/wiki",
		},
		{
			name:     "page url with path/query/fragment",
			in:       "https://tenant.atlassian.net/wiki/spaces/KEY/pages/123?x=1#frag",
			expected: "https://tenant.atlassian.net/wiki",
		},
		{
			name:     "trim spaces and drop userinfo",
			in:       "  https://user:pass@tenant.atlassian.net/some/where \n",
			expected: "https://tenant.atlassian.net/wiki",
		},
		{
			name:              "parse error",
			in:                "%",
			expectedErr:       fmt.Errorf("invalid URL escape"),
			useContainsForErr: true,
		},
		{
			name:              "missing host (absolute with empty host)",
			in:                "https:///wiki",
			expectedErr:       fmt.Errorf("invalid url: missing host"),
			useContainsForErr: true,
		},
		{
			name:              "missing host (relative path)",
			in:                "/wiki",
			expectedErr:       fmt.Errorf("invalid url: missing host"),
			useContainsForErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := normalizeWikiBase(tc.in)
			if tc.useContainsForErr {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestClassifyAuth401(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "missing scopes (any case)",
			body:     `{"code":401,"message":"Scope DOES NOT MATCH token"}`,
			expected: "missing-scopes",
		},
		{
			name:     "bad credentials generic",
			body:     `{"code":401,"message":"Invalid credentials"}`,
			expected: "bad-credentials",
		},
		{
			name:     "empty json",
			body:     `{}`,
			expected: "bad-credentials",
		},
		{
			name:     "invalid json still defaults",
			body:     `{`,
			expected: "bad-credentials",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := classifyAuth401([]byte(tc.body))
			assert.Equal(t, tc.expected, actual)
		})
	}
}
