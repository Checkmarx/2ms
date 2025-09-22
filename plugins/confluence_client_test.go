package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewConfluenceClient(t *testing.T) {
	actual := NewConfluenceClient("http://example.test/wiki", "user", "token").(*httpConfluenceClient)
	assert.Equal(t, "http://example.test/wiki", actual.baseWikiURL, "baseWikiURL mismatch")
	assert.Equal(t, "user", actual.username, "username mismatch")
	assert.Equal(t, "token", actual.token, "token mismatch")
	assert.NotNil(t, actual.httpClient, "http client should be set")
	assert.Equal(t, httpTimeout, actual.httpClient.Timeout, "timeout mismatch")
}

func TestAPIURL(t *testing.T) {
	t.Run("joins path with leading slash", func(t *testing.T) {
		c := &httpConfluenceClient{baseWikiURL: "https://example.test/wiki"}
		actual := c.apiURL("/pages").String()
		expected := "https://example.test/wiki/api/v2/pages"
		assert.Equal(t, expected, actual)
	})
	t.Run("handles missing leading slash", func(t *testing.T) {
		c := &httpConfluenceClient{baseWikiURL: "https://example.test/wiki"}
		actual := c.apiURL("pages").String()
		expected := "https://example.test/wiki/api/v2/pages"
		assert.Equal(t, expected, actual)
	})
	t.Run("trailing slash base", func(t *testing.T) {
		base := "https://example.test/wiki/"
		c := &httpConfluenceClient{baseWikiURL: base}
		actual := c.apiURL("/pages").String()
		expected := strings.TrimSuffix(base, "/") + "/api/v2/pages"
		assert.Equal(t, expected, actual)
	})
}

func TestResolveNextPageURL(t *testing.T) {
	c := &httpConfluenceClient{baseWikiURL: "http://example.test/wiki"}

	t.Run("prefer Link header next (absolute)", func(t *testing.T) {
		actual := c.resolveNextPageURL("http://example.test/wiki/api/v2/pages?cursor=abc", "")
		expected := "http://example.test/wiki/api/v2/pages?cursor=abc"
		assert.Equal(t, expected, actual)
	})

	t.Run("fallback to body _links.next (relative)", func(t *testing.T) {
		actual := c.resolveNextPageURL("", "/wiki/api/v2/pages?cursor=xyz")
		expected := "http://example.test/wiki/api/v2/pages?cursor=xyz"
		assert.Equal(t, expected, actual)
	})

	t.Run("empty when none", func(t *testing.T) {
		actual := c.resolveNextPageURL("", "")
		assert.Empty(t, actual)
	})
}

func TestNextURLFromLinkHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Link", `</wiki/api/v2/pages?cursor=foo>; rel="base", </wiki/api/v2/pages?cursor=bar>; rel="next"`)
	actual := nextURLFromLinkHeader(headers)
	expected := "/wiki/api/v2/pages?cursor=bar"
	assert.Equal(t, expected, actual)

	headers = http.Header{}
	actual = nextURLFromLinkHeader(headers)
	assert.Empty(t, actual)
}

func TestRateLimitMessage(t *testing.T) {
	headers := http.Header{}
	headers.Set("Retry-After", "75")
	actual := rateLimitMessage(headers)
	expected := "rate limited (429) — retry after 1 minute(s) 15 second(s)"
	assert.Equal(t, expected, actual)

	headers = http.Header{}
	headers.Set("Retry-After", "NotANumber")
	actual = rateLimitMessage(headers)
	expected = "rate limited (429)"
	assert.Equal(t, expected, actual)

	headers = http.Header{}
	actual = rateLimitMessage(headers)
	expected = "rate limited (429)"
	assert.Equal(t, expected, actual)
}

func TestParsePagesResponse(t *testing.T) {
	body := []byte(`{"results":[{"id":"1","status":"current","title":"A","spaceId":"S1","type":"page","body":{"storage":{"value":"content"}},"_links":{"self":"/self"}}],"_links":{"next":"/wiki/api/v2/pages?cursor=2"}}`)
	headers := http.Header{}
	headers.Set("Link", `</wiki/api/v2/pages?cursor=1>; rel="next"`)
	pages, linkNext, bodyNext, err := parsePagesResponse(headers, body)
	assert.NoError(t, err)
	assert.Len(t, pages, 1)
	assert.Equal(t, "1", pages[0].ID)
	assert.Equal(t, "/wiki/api/v2/pages?cursor=1", linkNext)
	assert.Equal(t, "/wiki/api/v2/pages?cursor=2", bodyNext)
}

func TestParseSpacesResponse(t *testing.T) {
	body := []byte(`{"results":[{"id":"S1","key":"KEY1","name":"Space One","_links":{"self":"/s"}}],"_links":{"next":"/wiki/api/v2/spaces?cursor=2"}}`)
	headers := http.Header{}
	headers.Set("Link", `</wiki/api/v2/spaces?cursor=1>; rel="next"`)
	spaces, linkNext, bodyNext, err := parseSpacesResponse(headers, body)
	assert.NoError(t, err)
	assert.Len(t, spaces, 1)
	assert.Equal(t, "S1", spaces[0].ID)
	assert.Equal(t, "/wiki/api/v2/spaces?cursor=1", linkNext)
	assert.Equal(t, "/wiki/api/v2/spaces?cursor=2", bodyNext)
}

func TestParseVersionsResponse(t *testing.T) {
	body := []byte(`{"results":[{"number":3},{"number":2},{"number":1}],"_links":{"next":"/wiki/api/v2/pages/123/versions?cursor=2"}}`)
	headers := http.Header{}
	headers.Set("Link", `</wiki/api/v2/pages/123/versions?cursor=1>; rel="next"`)
	versions, linkNext, bodyNext, err := parseVersionsResponse(headers, body)
	assert.NoError(t, err)
	assert.Equal(t, []int{3, 2, 1}, versions)
	assert.Equal(t, "/wiki/api/v2/pages/123/versions?cursor=1", linkNext)
	assert.Equal(t, "/wiki/api/v2/pages/123/versions?cursor=2", bodyNext)
}

func TestGetJSON(t *testing.T) {
	t.Run("success returns body and headers", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// verify auth when provided
			auth := r.Header.Get("Authorization")
			expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:token"))
			assert.Equal(t, expected, auth, "basic auth header mismatch")
			w.Header().Set("X-Foo", "bar")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer testServer.Close()

		client := &httpConfluenceClient{
			baseWikiURL: testServer.URL + "/wiki",
			httpClient:  &http.Client{Timeout: 5 * time.Second},
			username:    "user",
			token:       "token",
		}
		body, headers, err := client.getJSON(context.Background(), testServer.URL)
		assert.NoError(t, err)
		assert.JSONEq(t, `{"ok":true}`, string(body))
		assert.Equal(t, "bar", headers.Get("X-Foo"))
	})

	t.Run("rate limited 429 returns friendly error", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer testServer.Close()

		client := &httpConfluenceClient{httpClient: &http.Client{Timeout: 5 * time.Second}}
		_, _, err := client.getJSON(context.Background(), testServer.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "rate limited (429) — retry after 2 minute(s) 0 second(s)")
	})

	t.Run("non-2xx returns snippet", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "something went wrong", http.StatusInternalServerError)
		}))
		defer testServer.Close()

		client := &httpConfluenceClient{httpClient: &http.Client{Timeout: 5 * time.Second}}
		_, _, err := client.getJSON(context.Background(), testServer.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "http 500: something went wrong")
	})

	t.Run("sets Accept header", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expected := "application/json"
			actual := r.Header.Get("Accept")
			assert.Equal(t, expected, actual, "Accept header mismatch: expected=%s actual=%s", expected, actual)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer ts.Close()

		c := &httpConfluenceClient{httpClient: &http.Client{Timeout: 5 * time.Second}}
		_, _, err := c.getJSON(context.Background(), ts.URL)
		assert.NoError(t, err)
	})

	t.Run("no auth header when username/token empty", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expected := ""
			actual := r.Header.Get("Authorization")
			assert.Equal(t, expected, actual, "Authorization header mismatch: expected=%q actual=%q", expected, actual)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer ts.Close()

		c := &httpConfluenceClient{httpClient: &http.Client{Timeout: 5 * time.Second}}
		_, _, err := c.getJSON(context.Background(), ts.URL)
		assert.NoError(t, err)
	})
}

func TestWalkPagesPaginated(t *testing.T) {
	firstBatch := listPagesResponse{
		Results: []Page{{ID: "1", Title: "A"}, {ID: "2", Title: "B"}},
	}
	secondBatch := listPagesResponse{
		Results: []Page{{ID: "3", Title: "C"}},
	}

	var calls int
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			w.Header().Set("Link", fmt.Sprintf("<%s/wiki/api/v2/pages?cursor=next>; rel=\"next\"", ts.URL))
			_ = json.NewEncoder(w).Encode(firstBatch)
		default:
			_ = json.NewEncoder(w).Encode(secondBatch)
		}
	}))
	defer ts.Close()

	c := &httpConfluenceClient{
		baseWikiURL: ts.URL + "/wiki",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}

	var actualIDs []string
	err := c.walkPagesPaginated(context.Background(), ts.URL, func(p Page) error {
		actualIDs = append(actualIDs, p.ID)
		return nil
	})
	assert.NoError(t, err)

	expectedIDs := []string{"1", "2", "3"}
	assert.Equal(t, expectedIDs, actualIDs)
}

func TestWalkVersionsPaginated(t *testing.T) {
	firstBatch := listVersionsResponse{Results: []versionEntry{{Number: 3}, {Number: 2}}}
	secondBatch := listVersionsResponse{Results: []versionEntry{{Number: 1}}}

	var calls int
	var testServer *httptest.Server
	testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			w.Header().Set("Link", fmt.Sprintf("<%s/wiki/api/v2/pages/123/versions?cursor=n2>; rel=\"next\"", testServer.URL))
			_ = json.NewEncoder(w).Encode(firstBatch)
		default:
			_ = json.NewEncoder(w).Encode(secondBatch)
		}
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{
		baseWikiURL: testServer.URL + "/wiki",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	var actual []int
	err := client.walkVersionsPaginated(context.Background(), testServer.URL, func(n int) error {
		actual = append(actual, n)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []int{3, 2, 1}, actual)
}

func TestWalkSpacesPaginated(t *testing.T) {
	firstBatch := listSpacesResponse{Results: []Space{{ID: "S1", Key: "KEY1"}}, Links: map[string]string{"next": "/wiki/api/v2/spaces?cursor=2"}}
	secondBatch := listSpacesResponse{Results: []Space{{ID: "S2", Key: "KEY2"}}}

	var calls int
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			_ = json.NewEncoder(w).Encode(firstBatch) // no Link header -> body _links.next should be used
		default:
			_ = json.NewEncoder(w).Encode(secondBatch)
		}
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{baseWikiURL: testServer.URL + "/wiki", httpClient: &http.Client{Timeout: 5 * time.Second}}
	var actual []string
	err := client.walkSpacesPaginated(context.Background(), testServer.URL, func(s Space) error {
		actual = append(actual, s.ID)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []string{"S1", "S2"}, actual)
}

func TestWalkAllPages(t *testing.T) {
	expectPath := "/wiki/api/v2/pages"
	resp := listPagesResponse{Results: []Page{{ID: "1", Title: "A"}, {ID: "2", Title: "B"}}}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "250", r.URL.Query().Get("limit"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{baseWikiURL: testServer.URL + "/wiki", httpClient: &http.Client{Timeout: 5 * time.Second}}
	var actual []string
	err := client.WalkAllPages(context.Background(), 250, func(p Page) error {
		actual = append(actual, p.ID)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []string{"1", "2"}, actual)
}

func TestWalkPagesByIDs(t *testing.T) {
	expectPath := "/wiki/api/v2/pages"
	resp := listPagesResponse{Results: []Page{{ID: "10"}, {ID: "20"}}}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("limit"))
		assert.Equal(t, "1,2", r.URL.Query().Get("id"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{baseWikiURL: testServer.URL + "/wiki", httpClient: &http.Client{Timeout: 5 * time.Second}}
	var actual []string
	err := client.WalkPagesByIDs(context.Background(), []string{"1", "2"}, 2, func(p Page) error {
		actual = append(actual, p.ID)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []string{"10", "20"}, actual)
}

func TestWalkPagesBySpaceIDs(t *testing.T) {
	expectPath := "/wiki/api/v2/pages"
	resp := listPagesResponse{Results: []Page{{ID: "100"}, {ID: "200"}}}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("limit"))
		assert.Equal(t, "S1,S2", r.URL.Query().Get("space-id"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{baseWikiURL: testServer.URL + "/wiki", httpClient: &http.Client{Timeout: 5 * time.Second}}
	var actual []string
	err := client.WalkPagesBySpaceIDs(context.Background(), []string{"S1", "S2"}, 2, func(p Page) error {
		actual = append(actual, p.ID)
		return nil
	})
	assert.NoError(t, err)
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

	client := &httpConfluenceClient{baseWikiURL: testServer.URL + "/wiki", httpClient: &http.Client{Timeout: 5 * time.Second}}
	var actual []int
	err := client.WalkPageVersions(context.Background(), "123", 50, func(n int) error {
		actual = append(actual, n)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []int{2, 1}, actual)
}

func TestFetchPageAtVersion(t *testing.T) {
	expectPath := "/wiki/api/v2/pages/123"
	page := Page{ID: "123", Title: "Hello", Version: PageVersion{Number: 7}, Body: PageBody{Storage: &struct {
		Value string `json:"value"`
	}{Value: "<p>x</p>"}}}
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "7", r.URL.Query().Get("version"))
		assert.Equal(t, "storage", r.URL.Query().Get("body-format"))
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{baseWikiURL: testServer.URL + "/wiki", httpClient: &http.Client{Timeout: 5 * time.Second}}
	actual, err := client.FetchPageAtVersion(context.Background(), "123", 7)
	assert.NoError(t, err)
	assert.Equal(t, "123", actual.ID)
	assert.Equal(t, 7, actual.Version.Number)
	assert.NotNil(t, actual.Body.Storage)
	assert.Equal(t, "<p>x</p>", actual.Body.Storage.Value)
}

func TestWalkSpacesByKeys(t *testing.T) {
	expectPath := "/wiki/api/v2/spaces"
	resp := listSpacesResponse{Results: []Space{{ID: "S1", Key: "KEY1"}, {ID: "S2", Key: "KEY2"}}}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectPath, r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("limit"))
		assert.Equal(t, "KEY1,KEY2", r.URL.Query().Get("keys"))
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer testServer.Close()

	client := &httpConfluenceClient{baseWikiURL: testServer.URL + "/wiki", httpClient: &http.Client{Timeout: 5 * time.Second}}
	var actual []string
	err := client.WalkSpacesByKeys(context.Background(), []string{"KEY1", "KEY2"}, 2, func(s Space) error {
		actual = append(actual, s.ID)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []string{"S1", "S2"}, actual)
}
