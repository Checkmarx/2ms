package plugins

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen -destination=confluence_client_mock_test.go -package=plugins github.com/checkmarx/2ms/v4/plugins ConfluenceClient

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid https", "https://checkmarx.atlassian.net/wiki", false},
		{"invalid scheme", "http://checkmarx.atlassian.net/wiki", true},
		{"not a url", "something", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{tc.input}
			err := isValidURL(nil, args)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestChunkStrings(t *testing.T) {
	t.Run("exact multiple", func(t *testing.T) {
		in := makeRangeStrings(1, 300) // 300 items
		chunks := chunkStrings(in, 100)
		assert.Equal(t, 3, len(chunks))
		assert.Equal(t, in[0:100], chunks[0])
		assert.Equal(t, in[100:200], chunks[1])
		assert.Equal(t, in[200:300], chunks[2])
	})

	t.Run("not an exact multiple", func(t *testing.T) {
		in := makeRangeStrings(1, 305) // 305 items
		chunks := chunkStrings(in, 100)
		assert.Equal(t, 4, len(chunks))
		assert.Equal(t, in[0:100], chunks[0])
		assert.Equal(t, in[100:200], chunks[1])
		assert.Equal(t, in[200:300], chunks[2])
		assert.Equal(t, in[300:305], chunks[3])
	})

	t.Run("small input", func(t *testing.T) {
		in := []string{"a", "b"}
		chunks := chunkStrings(in, 250)
		assert.Equal(t, 1, len(chunks))
		assert.Equal(t, in, chunks[0])
	})
}

func TestConvertPageToItem(t *testing.T) {
	const base = "https://checkmarx.atlassian.net/wiki"
	p := &ConfluencePlugin{}

	t.Run("web UI with /wiki and version", func(t *testing.T) {
		page := &Page{
			ID:    "123",
			Title: "Page Title",
			Body: PageBody{Storage: &struct {
				Value string `json:"value"`
			}{Value: "<p>content</p>"}},
			Links:   map[string]string{"webui": "/pages/viewpage.action?pageId=123"},
			Version: PageVersion{Number: 4},
		}

		actualItem := p.convertPageToItem(page, base, 4)
		assert.Equal(t, "confluence-123-4", actualItem.GetID())
		assert.Equal(t, base+"/pages/viewpage.action?pageId=123&pageVersion=4", actualItem.GetSource())
		assert.Equal(t, "<p>content</p>", *actualItem.GetContent())
	})

	t.Run("fallback to base link", func(t *testing.T) {
		page := &Page{
			ID:      "456",
			Links:   map[string]string{"base": base},
			Version: PageVersion{Number: 1},
		}
		actualItem := p.convertPageToItem(page, base, 0)
		assert.Equal(t, "confluence-456-1", actualItem.GetID())
		assert.Equal(t, base, actualItem.GetSource())
	})
}

func TestResolveConfluenceSourceURL(t *testing.T) {
	const base = "https://checkmarx.atlassian.net/wiki"

	t.Run("web UI with /wiki and version", func(t *testing.T) {
		page := &Page{Links: map[string]string{"webui": "/pages/viewpage.action?pageId=123"}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 4)
		expectedURL := "https://checkmarx.atlassian.net/wiki/pages/viewpage.action?pageId=123&pageVersion=4"

		assert.Equal(t, true, actualOK, "expected OK for relative webui with version")
		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("web UI absolute url with version", func(t *testing.T) {
		abs := "https://checkmarx.atlassian.net/wiki/pages/viewpage.action?pageId=456"
		page := &Page{Links: map[string]string{"webui": abs}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 2)
		expectedURL := "https://checkmarx.atlassian.net/wiki/pages/viewpage.action?pageId=456&pageVersion=2"

		assert.Equal(t, true, actualOK, "expected OK for absolute webui with version")
		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("no version number does not add pageVersion", func(t *testing.T) {
		page := &Page{Links: map[string]string{"webui": "/pages/viewpage.action?pageId=321"}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 0)
		expectedURL := "https://checkmarx.atlassian.net/wiki/pages/viewpage.action?pageId=321"

		assert.Equal(t, true, actualOK, "expected OK for relative webui without version")
		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("existing pageVersion kept when versionNumber is zero", func(t *testing.T) {
		page := &Page{Links: map[string]string{"webui": "/pages/viewpage.action?pageId=1&pageVersion=7"}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 0)
		expectedURL := "https://checkmarx.atlassian.net/wiki/pages/viewpage.action?pageId=1&pageVersion=7"

		assert.Equal(t, true, actualOK, "expected OK and to keep existing pageVersion")
		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("existing pageVersion overridden when versionNumber > 0", func(t *testing.T) {
		page := &Page{Links: map[string]string{"webui": "/pages/viewpage.action?pageId=1&pageVersion=7"}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 9)
		expectedURL := "https://checkmarx.atlassian.net/wiki/pages/viewpage.action?pageId=1&pageVersion=9"

		assert.Equal(t, true, actualOK, "expected OK and to override existing pageVersion")
		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("fallback to base link", func(t *testing.T) {
		page := &Page{Links: map[string]string{"base": base}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 0)
		expectedURL := base

		assert.Equal(t, true, actualOK, "expected OK for base fallback")
		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("missing links returns false", func(t *testing.T) {
		page := &Page{} // Links == nil

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 0)
		assert.Equal(t, false, actualOK, "expected resolution to fail when Links is nil")
		assert.Equal(t, "", actualURL)
	})

	t.Run("invalid webui is ignored", func(t *testing.T) {
		page := &Page{Links: map[string]string{"webui": "%"}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, base, 1)
		assert.Equal(t, false, actualOK, "expected resolution to fail for invalid webui")
		assert.Equal(t, "", actualURL)
	})

	t.Run("invalid wiki base returns false when resolving relative webui", func(t *testing.T) {
		page := &Page{Links: map[string]string{"webui": "/pages/viewpage.action?pageId=123"}}

		actualURL, actualOK := resolveConfluenceSourceURL(page, "http://[::1", 1)
		assert.Equal(t, false, actualOK, "expected resolution to fail for invalid wiki base")
		assert.Equal(t, "", actualURL)
	})
}

func TestWalkAndEmitPages(t *testing.T) {
	t.Run("No filters, history off: emits current only", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()

		ctx := context.Background()
		page := mkPage("100", 3)

		mock.EXPECT().
			WalkAllPages(gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ int, visit func(*Page) error) error {
				return visit(page)
			}).Times(1)

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		items := collectEmittedItems(p.itemsChan)
		if assert.Len(t, items, 1) {
			expectedID := p.GetName() + "-100-3"
			expectedSrc := p.baseWikiURL + "/pages/viewpage.action?pageId=100" // no pageVersion when history=false
			expectedContent := "content 100"

			assert.Equal(t, expectedID, items[0].ID)
			assert.Equal(t, expectedSrc, items[0].Source)
			assert.Equal(t, expectedContent, items[0].Content)
		}
	})

	t.Run("No filters, history on: emits current and older versions with correct sources", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		p.History = true

		ctx := context.Background()
		cur := mkPage("200", 5)
		versions := []int{1, 2, 3, 4, 5}

		mock.EXPECT().
			WalkAllPages(gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ int, visit func(*Page) error) error {
				return visit(cur)
			}).Times(1)

		mock.EXPECT().
			WalkPageVersions(gomock.Any(), "200", maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ string, _ int, visit func(int) error) error {
				for _, v := range versions {
					_ = visit(v)
				}
				return nil
			}).Times(1)

		for _, v := range versions[:len(versions)-1] {
			mock.EXPECT().
				FetchPageAtVersion(gomock.Any(), "200", v).
				DoAndReturn(func(_ context.Context, _ string, _ int) (*Page, error) {
					return mkPage("200", v), nil
				}).Times(1)
		}

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		items := collectEmittedItems(p.itemsChan)
		expectedIDs := []string{
			p.GetName() + "-200-5",
			p.GetName() + "-200-1",
			p.GetName() + "-200-2",
			p.GetName() + "-200-3",
			p.GetName() + "-200-4",
		}
		actualIDs := make([]string, 0, len(items))
		for _, s := range items {
			actualIDs = append(actualIDs, s.ID)
		}
		assert.ElementsMatch(t, expectedIDs, actualIDs)

		// Sources: current has no pageVersion; historical have pageVersion=1..4
		expectedSources := []string{
			p.baseWikiURL + "/pages/viewpage.action?pageId=200",
			p.baseWikiURL + "/pages/viewpage.action?pageId=200&pageVersion=1",
			p.baseWikiURL + "/pages/viewpage.action?pageId=200&pageVersion=2",
			p.baseWikiURL + "/pages/viewpage.action?pageId=200&pageVersion=3",
			p.baseWikiURL + "/pages/viewpage.action?pageId=200&pageVersion=4",
		}
		actualSources := make([]string, 0, len(items))
		for _, s := range items {
			actualSources = append(actualSources, s.Source)
			// Content stays the same in our mkPage mock
			assert.Equal(t, "content 200", s.Content)
		}
		assert.ElementsMatch(t, expectedSources, actualSources)
	})

	t.Run("SpaceIDs only: deduplicates spaces and pages with correct sources", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		p.SpaceIDs = []string{"S1", "S2"}

		expectedCalls := numChunks(len(p.SpaceIDs), maxSpaceIDsPerRequest)
		mock.EXPECT().
			WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Page) error) error {
				_ = visit(mkPage("P1", 2))
				_ = visit(mkPage("P1", 2))
				_ = visit(mkPage("P2", 1))
				return nil
			}).Times(expectedCalls)

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		items := collectEmittedItems(p.itemsChan)
		actualIDs := make([]string, 0, len(items))
		for _, it := range items {
			actualIDs = append(actualIDs, it.ID)
		}

		expectedIDs := []string{
			p.GetName() + "-P1-2",
			p.GetName() + "-P2-1",
		}
		assert.ElementsMatch(t, expectedIDs, actualIDs)
	})

	t.Run("SpaceKeys only: resolves keys to unique space IDs then emits pages with correct sources", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		p.SpaceKeys = []string{"Key1", "Key2", "Key1"}
		keyBatches := chunkStrings(p.SpaceKeys, maxSpaceKeysPerRequest)

		mock.EXPECT().
			WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, keys []string, _ int, visit func(*Space) error) error {
				for _, k := range keys {
					switch k {
					case "Key1":
						_ = visit(&Space{ID: "S1", Key: "Key1"})
					case "Key2":
						_ = visit(&Space{ID: "S2", Key: "Key2"})
					}
				}
				return nil
			}).Times(len(keyBatches))

		resolvedUnique := []string{"S1", "S2"}
		expectedCalls := numChunks(len(resolvedUnique), maxSpaceIDsPerRequest)

		mock.EXPECT().
			WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, batch []string, _ int, visit func(*Page) error) error {
				for _, sid := range batch {
					_ = visit(mkPage("P-"+sid, 1))
				}
				return nil
			}).Times(expectedCalls)

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		items := collectEmittedItems(p.itemsChan)
		expectedIDs := []string{
			p.GetName() + "-P-S1-1",
			p.GetName() + "-P-S2-1",
		}
		expectedSources := []string{
			p.baseWikiURL + "/pages/viewpage.action?pageId=P-S1",
			p.baseWikiURL + "/pages/viewpage.action?pageId=P-S2",
		}
		actualIDs, actualSources := make([]string, 0, len(items)), make([]string, 0, len(items))
		for _, s := range items {
			actualIDs = append(actualIDs, s.ID)
			actualSources = append(actualSources, s.Source)
			assert.Contains(t, []string{"content P-S1", "content P-S2"}, s.Content)
		}
		assert.ElementsMatch(t, expectedIDs, actualIDs)
		assert.ElementsMatch(t, expectedSources, actualSources)
	})

	t.Run("PageIDs only: emits each page once with correct sources", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		p.PageIDs = []string{"10", "20", "10"}
		expectedCalls := numChunks(len(p.PageIDs), maxPageIDsPerRequest)

		mock.EXPECT().
			WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, batch []string, _ int, visit func(*Page) error) error {
				for _, id := range batch {
					_ = visit(mkPage(id, 1))
				}
				return nil
			}).Times(expectedCalls)

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		items := collectEmittedItems(p.itemsChan)
		expectedIDs := []string{
			p.GetName() + "-10-1",
			p.GetName() + "-20-1",
		}
		expectedSources := []string{
			p.baseWikiURL + "/pages/viewpage.action?pageId=10",
			p.baseWikiURL + "/pages/viewpage.action?pageId=20",
		}
		actualIDs, actualSources := make([]string, 0, len(items)), make([]string, 0, len(items))
		for _, s := range items {
			actualIDs = append(actualIDs, s.ID)
			actualSources = append(actualSources, s.Source)
			assert.Contains(t, []string{"content 10", "content 20"}, s.Content)
		}
		assert.ElementsMatch(t, expectedIDs, actualIDs)
		assert.ElementsMatch(t, expectedSources, actualSources)
	})

	t.Run("Filters collide: emits each unique page once with correct versions", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		p.SpaceIDs = []string{"S1"}
		mock.EXPECT().
			WalkPagesBySpaceIDs(gomock.Any(), []string{"S1"}, maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Page) error) error {
				_ = visit(mkPage("P1", 3))
				_ = visit(mkPage("P2", 1))
				return nil
			}).Times(1)

		p.SpaceKeys = []string{"Key1"}
		mock.EXPECT().
			WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Space) error) error {
				_ = visit(&Space{ID: "S1", Key: "Key1"})
				return nil
			}).Times(1)

		p.PageIDs = []string{"P1", "P3"}
		mock.EXPECT().
			WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, batch []string, _ int, visit func(*Page) error) error {
				for _, id := range batch {
					_ = visit(mkPage(id, 1))
				}
				return nil
			}).Times(numChunks(len(p.PageIDs), maxPageIDsPerRequest))

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		items := collectEmittedItems(p.itemsChan)
		expectedIDs := []string{
			p.GetName() + "-P1-3", // keeps first seen version for P1
			p.GetName() + "-P2-1",
			p.GetName() + "-P3-1",
		}
		actualIDs := make([]string, 0, len(items))
		for _, s := range items {
			actualIDs = append(actualIDs, s.ID)
		}
		assert.ElementsMatch(t, expectedIDs, actualIDs)
	})

	t.Run("Batching PageIDs: calls per chunk and emits N items", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		N := (maxPageIDsPerRequest * 2) + 7
		p.PageIDs = makeRangeStrings(1, N)

		expectedCalls := numChunks(len(p.PageIDs), maxPageIDsPerRequest)

		mock.EXPECT().
			WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, batch []string, _ int, visit func(*Page) error) error {
				for _, id := range batch {
					_ = visit(mkPage(id, 1))
				}
				return nil
			}).Times(expectedCalls)

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		assert.Equal(t, N, len(p.itemsChan), "items emitted mismatch: expected=%d actual=%d", N, len(p.itemsChan))
	})

	t.Run("Batching SpaceIDs: calls per chunk and emits N items", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		N := (maxSpaceIDsPerRequest * 2) + 3
		p.SpaceIDs = makeRangeStrings(1, N)

		expectedCalls := numChunks(len(p.SpaceIDs), maxSpaceIDsPerRequest)

		mock.EXPECT().
			WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, batch []string, _ int, visit func(*Page) error) error {
				for _, sid := range batch {
					_ = visit(mkPage("P-"+sid, 1))
				}
				return nil
			}).Times(expectedCalls)

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		assert.Equal(t, N, len(p.itemsChan), "items emitted mismatch: expected=%d actual=%d", N, len(p.itemsChan))
	})

	t.Run("Batching SpaceKeys: calls per key batch and per space batch, emits N items", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		N := (maxSpaceKeysPerRequest * 1) + 25
		keys := make([]string, 0, N)
		for i := 1; i <= N; i++ {
			keys = append(keys, "Key"+strconv.Itoa(i))
		}
		p.SpaceKeys = keys

		keyBatches := chunkStrings(p.SpaceKeys, maxSpaceKeysPerRequest)

		mock.EXPECT().
			WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, kb []string, _ int, visit func(*Space) error) error {
				for _, k := range kb {
					_ = visit(&Space{ID: "S-" + k, Key: k})
				}
				return nil
			}).Times(len(keyBatches))

		expectedCalls := 0
		for _, kb := range keyBatches {
			expectedCalls += numChunks(len(kb), maxSpaceIDsPerRequest)
		}

		mock.EXPECT().
			WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, batch []string, _ int, visit func(*Page) error) error {
				for _, sid := range batch {
					_ = visit(mkPage("P-"+sid, 1))
				}
				return nil
			}).Times(expectedCalls)

		err := p.walkAndEmitPages(ctx)
		assert.NoError(t, err)

		assert.Equal(t, N, len(p.itemsChan), "items emitted mismatch: expected=%d actual=%d", N, len(p.itemsChan))
	})

	t.Run("Error propagation: propagates client error", func(t *testing.T) {
		p, ctrl, mock := newPluginWithMock(t)
		defer ctrl.Finish()
		ctx := context.Background()

		p.PageIDs = []string{"1", "2"}

		mock.EXPECT().
			WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ []string, _ int, _ func(*Page) error) error {
				return assert.AnError
			}).Times(1)

		err := p.walkAndEmitPages(ctx)
		assert.Error(t, err)
	})
}
func newPluginWithMock(t *testing.T) (*ConfluencePlugin, *gomock.Controller, *MockConfluenceClient) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mock := NewMockConfluenceClient(ctrl)

	p := &ConfluencePlugin{
		itemsChan: make(chan ISourceItem, 1000),
		client:    mock,
	}
	p.baseWikiURL = "https://tenant.atlassian.net/wiki"
	return p, ctrl, mock
}

func mkPage(id string, ver int) *Page {
	return &Page{
		ID:    id,
		Title: "T-" + id,
		Links: map[string]string{"webui": "/pages/viewpage.action?pageId=" + id},
		Body: PageBody{
			Storage: &struct {
				Value string `json:"value"`
			}{Value: "content " + id},
		},
		Version: PageVersion{Number: ver},
	}
}

type emittedItem struct {
	ID      string
	Source  string
	Content string
}

func collectEmittedItems(ch chan ISourceItem) []emittedItem {
	n := len(ch)
	items := make([]emittedItem, 0, n)
	for i := 0; i < n; i++ {
		it := <-ch
		content := ""
		if it.GetContent() != nil {
			content = *it.GetContent()
		}
		items = append(items, emittedItem{
			ID:      it.GetID(),
			Source:  it.GetSource(),
			Content: content,
		})
	}
	return items
}

func makeRangeStrings(start, end int) []string {
	out := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		out = append(out, strconv.Itoa(i))
	}
	return out
}

func numChunks(n, size int) int {
	if size <= 0 || n <= 0 {
		return 0
	}
	q := n / size
	if n%size != 0 {
		q++
	}
	return q
}
