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
		tokenType    TokenType
		expectedBase string
		expectedErr  error
	}{
		{
			name: "classic",
			setup: func() *httpConfluenceClient {
				return &httpConfluenceClient{baseWikiURL: "https://tenant.atlassian.net/wiki"}
			},
			tokenType:    TokenClassic,
			expectedBase: "https://tenant.atlassian.net/wiki/api/v2",
			expectedErr:  nil,
		},
		{
			name: "scoped (discovers cloudId)",
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
			tokenType:    TokenScoped,
			expectedBase: "https://api.atlassian.com/ex/confluence/abc-123/wiki/api/v2",
			expectedErr:  nil,
		},
		{
			name: "unsupported",
			setup: func() *httpConfluenceClient {
				return &httpConfluenceClient{baseWikiURL: "https://example.test/wiki"}
			},
			tokenType:   TokenType("bad"),
			expectedErr: ErrUnsupportedTokenType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.setup()
			actualBase, err := c.buildAPIBase(context.Background(), tc.tokenType)
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
			expectedErr: fmt.Errorf("tenant_info request"),
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
			expectedErr: ErrUnexpectedHTTPStatus,
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
			expectedErr: io.ErrUnexpectedEOF,
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
			expectedErr: ErrEmptyCloudID,
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
	type payload struct {
		Results []int             `json:"results"`
		Links   map[string]string `json:"_links,omitempty"`
	}
	first := payload{Results: []int{1, 2}, Links: map[string]string{"next": "/api?cursor=two"}}
	second := payload{Results: []int{3}}

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			_ = json.NewEncoder(w).Encode(first)
		default:
			_ = json.NewEncoder(w).Encode(second)
		}
	}))
	defer srv.Close()

	get := func(ctx context.Context, u string) ([]byte, http.Header, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, http.NoBody)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b, resp.Header.Clone(), nil
	}
	parse := func(h http.Header, b []byte) ([]int, string, string, error) {
		var p payload
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, "", "", err
		}
		return p.Results, "", p.Links["next"], nil
	}

	var actual []int
	startURL, _ := url.Parse(srv.URL + "/api")
	actualErr := walkPaginated[int](context.Background(), startURL, get, parse, func(n int) error {
		actual = append(actual, n)
		return nil
	})
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []int{1, 2, 3}, actual)
}

func TestStreamPagesFromBody(t *testing.T) {
	body := `{
	  "results": [
	    {"id":"1","title":"A","body":{"storage":{"value":"x"}},"_links":{"self":"/s1"}},
	    {"id":"2","title":"B","body":{"storage":{"value":"y"}},"_links":{"self":"/s2"}}
	  ],
	  "_links": {"next": "/wiki/api/v2/pages?cursor=next"}
	}`
	var actualVisited []string
	actualNext, actualErr := streamPagesFromBody(strings.NewReader(body), func(p *Page) error {
		actualVisited = append(actualVisited, p.ID)
		return nil
	})
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []string{"1", "2"}, actualVisited)
	assert.Equal(t, "/wiki/api/v2/pages?cursor=next", actualNext)
}

func TestParseSpacesResponse(t *testing.T) {
	body := []byte(`{"results":[{"id":"S1","key":"KEY1","name":"Space One","_links":{"self":"/s"}}],"_links":{"next":"/wiki/api/v2/spaces?cursor=2"}}`)
	headers := http.Header{}
	headers.Set("Link", `</wiki/api/v2/spaces?cursor=1>; rel="next"`)
	spaces, linkNext, bodyNext, actualErr := parseSpacesResponse(headers, body)
	assert.Equal(t, nil, actualErr)
	assert.Len(t, spaces, 1)
	assert.Equal(t, "S1", spaces[0].ID)
	assert.Equal(t, "/wiki/api/v2/spaces?cursor=1", linkNext)
	assert.Equal(t, "/wiki/api/v2/spaces?cursor=2", bodyNext)
}

func TestParseVersionsResponse(t *testing.T) {
	body := []byte(`{"results":[{"number":3},{"number":2},{"number":1}],"_links":{"next":"/wiki/api/v2/pages/123/versions?cursor=2"}}`)
	headers := http.Header{}
	headers.Set("Link", `</wiki/api/v2/pages/123/versions?cursor=1>; rel="next"`)
	versions, linkNext, bodyNext, actualErr := parseVersionsResponse(headers, body)
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, []int{3, 2, 1}, versions)
	assert.Equal(t, "/wiki/api/v2/pages/123/versions?cursor=1", linkNext)
	assert.Equal(t, "/wiki/api/v2/pages/123/versions?cursor=2", bodyNext)
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
	page := Page{
		ID:      "123",
		Title:   "Hello",
		Version: PageVersion{Number: 7},
		Body: PageBody{Storage: &struct {
			Value string `json:"value"`
		}{Value: "<p>x</p>"}},
	}
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "7", r.URL.Query().Get("version"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{
		baseWikiURL: testServer.URL + "/wiki",
		apiBase:     testServer.URL + "/wiki/api/v2",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	actual, actualErr := client.FetchPageAtVersion(context.Background(), "123", 7)
	assert.Equal(t, nil, actualErr)
	assert.Equal(t, "123", actual.ID)
	assert.Equal(t, 7, actual.Version.Number)
	assert.Equal(t, "<p>x</p>", actual.Body.Storage.Value)
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
