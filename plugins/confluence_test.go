package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/checkmarx/2ms/v4/engine/chunk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen -destination=confluence_client_mock_test.go -package=plugins github.com/checkmarx/2ms/v4/plugins ConfluenceClient

const mockGetFileThresholdReturn = 1_000_000

func TestGetName(t *testing.T) {
	p := &ConfluencePlugin{}
	assert.Equal(t, "confluence", p.GetName())
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedErr error
	}{
		{
			name:        "valid https",
			input:       "https://checkmarx.atlassian.net/wiki",
			expectedErr: nil,
		},
		{
			name:        "invalid scheme",
			input:       "http://checkmarx.atlassian.net/wiki",
			expectedErr: ErrHTTPSRequired,
		},
		{
			name:        "not a url",
			input:       "%",
			expectedErr: fmt.Errorf("invalid URL escape"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{tc.input}
			err := isValidURL(&cobra.Command{}, args)
			if tc.name == "not a url" {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}
		})
	}
}

func TestChunkStrings(t *testing.T) {
	tests := []struct {
		name       string
		in         []string
		chunkSize  int
		chunkSpans [][2]int // [start,end) ranges expected por chunk
	}{
		{
			name:       "exact multiple",
			in:         makeRangeStrings(1, 300), // 300 items
			chunkSize:  100,
			chunkSpans: [][2]int{{0, 100}, {100, 200}, {200, 300}},
		},
		{
			name:       "not an exact multiple",
			in:         makeRangeStrings(1, 305), // 305 items
			chunkSize:  100,
			chunkSpans: [][2]int{{0, 100}, {100, 200}, {200, 300}, {300, 305}},
		},
		{
			name:       "small input",
			in:         []string{"a", "b"},
			chunkSize:  250,
			chunkSpans: [][2]int{{0, 2}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chunks := chunkStrings(tc.in, tc.chunkSize)
			assert.Equal(t, len(tc.chunkSpans), len(chunks))
			for i, span := range tc.chunkSpans {
				assert.Equal(t, tc.in[span[0]:span[1]], chunks[i])
			}
		})
	}
}

func TestConvertPageToItem(t *testing.T) {
	const base = "https://checkmarx.atlassian.net/wiki"

	tests := []struct {
		name            string
		page            *Page
		expectCalls     int // WikiBaseURL calls
		expectedID      string
		expectedSrc     string
		expectedContent *string
	}{
		{
			name: "webui + version",
			page: &Page{
				ID:    "123",
				Title: "Page Title",
				Body: PageBody{Storage: &struct {
					Value string `json:"value"`
				}{Value: "<p>content</p>"}},
				Links:   map[string]string{"webui": "/pages/viewpage.action?pageId=123"},
				Version: PageVersion{Number: 4},
			},
			expectCalls:     1,
			expectedID:      "confluence-123-4",
			expectedSrc:     base + "/pages/viewpage.action?pageId=123&pageVersion=4",
			expectedContent: ptr("<p>content</p>"),
		},
		{
			name: "fallback base link",
			page: &Page{
				ID:      "456",
				Links:   map[string]string{"base": base},
				Version: PageVersion{Number: 1},
			},
			expectCalls:     0,
			expectedID:      "confluence-456-1",
			expectedSrc:     base,
			expectedContent: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := NewMockConfluenceClient(ctrl)
			mockClient.EXPECT().WikiBaseURL().Return(base).Times(tc.expectCalls)

			p := &ConfluencePlugin{client: mockClient}
			item := p.convertPageToItem(tc.page)

			assert.Equal(t, tc.expectedID, item.GetID())
			assert.Equal(t, tc.expectedSrc, item.GetSource())
			assert.Equal(t, tc.expectedContent, item.GetContent())
		})
	}
}

func TestResolveConfluenceSourceURL(t *testing.T) {
	const base = "https://checkmarx.atlassian.net/wiki"

	tests := []struct {
		name        string
		links       map[string]string
		version     int
		expectCalls int // WikiBaseURL calls
		canResolve  bool
		expectedURL string
		wikiURL     string
	}{
		{
			name:        "webui relative + version",
			links:       map[string]string{"webui": "/pages/viewpage.action?pageId=123"},
			version:     4,
			expectCalls: 1,
			canResolve:  true,
			expectedURL: base + "/pages/viewpage.action?pageId=123&pageVersion=4",
			wikiURL:     base,
		},
		{
			name:        "webui absolute + version",
			links:       map[string]string{"webui": base + "/pages/viewpage.action?pageId=456"},
			version:     2,
			expectCalls: 1,
			canResolve:  true,
			expectedURL: base + "/pages/viewpage.action?pageId=456&pageVersion=2",
			wikiURL:     base,
		},
		{
			name:        "webui present and valid but wikiURL invalid",
			links:       map[string]string{"webui": base + "/pages/viewpage.action?pageId=456"},
			version:     2,
			expectCalls: 1,
			canResolve:  false,
			expectedURL: "",
			wikiURL:     "%",
		},
		{
			name:        "fallback base",
			links:       map[string]string{"base": base},
			version:     1,
			expectCalls: 0,
			canResolve:  true,
			expectedURL: base,
			wikiURL:     base,
		},
		{
			name:        "links nil",
			links:       nil,
			version:     1,
			expectCalls: 0,
			canResolve:  false,
			expectedURL: "",
		},
		{
			name:        "missing one of the required links",
			links:       map[string]string{"something": "mock"},
			version:     1,
			expectCalls: 0,
			canResolve:  false,
			expectedURL: "",
		},
		{
			name:        "invalid webui",
			links:       map[string]string{"webui": "%"},
			version:     1,
			expectCalls: 1,
			canResolve:  false,
			expectedURL: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := NewMockConfluenceClient(ctrl)
			mockClient.EXPECT().WikiBaseURL().Return(tc.wikiURL).Times(tc.expectCalls)

			p := &ConfluencePlugin{client: mockClient}
			page := &Page{Links: tc.links}
			actualURL, ok := p.resolveConfluenceSourceURL(page, tc.version)
			assert.Equal(t, tc.canResolve, ok)
			assert.Equal(t, tc.expectedURL, actualURL)
		})
	}
}

func TestWalkPagesByIDBatches(t *testing.T) {
	tests := []struct {
		name              string
		allIDs            []string
		perBatch          int
		setupWalker       func() func(context.Context, []string, int, func(*Page) error) error
		expectedBatches   [][]string
		expectedEmitCount int
		expectedErr       error
	}{
		{
			name:     "walks in chunks and emits via walker",
			allIDs:   []string{"a", "b", "c", "d", "e"},
			perBatch: 2,
			setupWalker: func() func(context.Context, []string, int, func(*Page) error) error {
				return func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
					for _, id := range ids {
						_ = visit(mkPage(id, 1))
					}
					return nil
				}
			},
			expectedBatches:   [][]string{{"a", "b"}, {"c", "d"}, {"e"}},
			expectedEmitCount: 5,
			expectedErr:       nil,
		},
		{
			name:     "propagates walker error",
			allIDs:   []string{"1", "2"},
			perBatch: 10,
			setupWalker: func() func(context.Context, []string, int, func(*Page) error) error {
				return func(_ context.Context, _ []string, _ int, _ func(*Page) error) error {
					return assert.AnError
				}
			},
			expectedBatches:   [][]string{{"1", "2"}},
			expectedEmitCount: 0,
			expectedErr:       assert.AnError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockChunk := chunk.NewMockIChunk(ctrl)
			mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(tc.expectedEmitCount)

			mockClient := NewMockConfluenceClient(ctrl)
			mockClient.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(tc.expectedEmitCount)

			p := &ConfluencePlugin{
				itemsChan:         make(chan ISourceItem, 100),
				chunker:           mockChunk,
				client:            mockClient,
				returnedSpaceIDs:  map[string]struct{}{},
				returnedPageIDs:   map[string]struct{}{},
				resolvedSpaceKeys: map[string]string{},
				invalidSpaceIDs:   map[string]struct{}{},
				invalidPageIDs:    map[string]struct{}{},
			}

			var seenBatches [][]string
			walker := func(ctx context.Context, ids []string, lim int, v func(*Page) error) error {
				seenBatches = append(seenBatches, append([]string(nil), ids...))
				return tc.setupWalker()(ctx, ids, lim, v)
			}

			err := p.walkPagesByIDBatches(context.Background(), tc.allIDs, tc.perBatch, walker)
			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedBatches, seenBatches)
			assert.Len(t, collectEmittedItems(p.itemsChan), tc.expectedEmitCount)
		})
	}
}

func TestEmitUniquePage(t *testing.T) {
	tests := []struct {
		name              string
		seenPages         map[string]struct{}
		page              *Page
		history           bool
		setupMocks        func(mc *MockConfluenceClient, ch *chunk.MockIChunk, p *Page)
		expectedErr       error
		expectedEmitCount int
	}{
		{
			name:      "first time emits",
			seenPages: map[string]struct{}{},
			page:      mkPage("42", 3),
			history:   false,
			setupMocks: func(mc *MockConfluenceClient, ch *chunk.MockIChunk, p *Page) {
				ch.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(1)
				mc.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(1)
			},
			expectedErr:       nil,
			expectedEmitCount: 1,
		},
		{
			name:              "already seen",
			seenPages:         map[string]struct{}{"42": {}},
			page:              mkPage("42", 3),
			history:           false,
			setupMocks:        func(_ *MockConfluenceClient, _ *chunk.MockIChunk, _ *Page) {},
			expectedErr:       nil,
			expectedEmitCount: 0,
		},
		{
			name:      "emitInChunks error",
			seenPages: map[string]struct{}{},
			page: func() *Page {
				pg := mkPage("99", 1)
				pg.Body.Storage = &struct {
					Value string `json:"value"`
				}{Value: strings.Repeat("X", 64)}
				return pg
			}(),
			history: false,
			setupMocks: func(mc *MockConfluenceClient, ch *chunk.MockIChunk, p *Page) {
				ch.EXPECT().GetFileThreshold().Return(int64(1)).Times(1)
				ch.EXPECT().GetSize().Return(64).Times(1)
				ch.EXPECT().GetMaxPeekSize().Return(0).Times(1)
				ch.EXPECT().ReadChunk(gomock.Any(), -1).Return("", assert.AnError).Times(1)
			},
			expectedErr:       assert.AnError,
			expectedEmitCount: 0,
		},
		{
			name:      "history enabled and emitHistory returns error (after emitting current)",
			seenPages: map[string]struct{}{},
			page:      mkPage("77", 5),
			history:   true,
			setupMocks: func(mc *MockConfluenceClient, ch *chunk.MockIChunk, p *Page) {
				ch.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(1)
				mc.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(1)

				mc.EXPECT().
					WalkPageVersions(gomock.Any(), p.ID, maxPageSize, gomock.Any()).
					Return(assert.AnError).Times(1)
			},
			expectedErr:       assert.AnError,
			expectedEmitCount: 1, // current was emitted before history failed
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockChunk := chunk.NewMockIChunk(ctrl)
			mockClient := NewMockConfluenceClient(ctrl)

			p := &ConfluencePlugin{
				itemsChan: make(chan ISourceItem, 10),
				chunker:   mockChunk,
				client:    mockClient,
				History:   tc.history,
			}

			if tc.setupMocks != nil {
				tc.setupMocks(mockClient, mockChunk, tc.page)
			}

			p.returnedPageIDs = tc.seenPages
			err := p.emitUniquePage(context.Background(), tc.page)
			assert.ErrorIs(t, err, tc.expectedErr)

			emitted := collectEmittedItems(p.itemsChan)
			assert.Len(t, emitted, tc.expectedEmitCount)
		})
	}
}

func TestEmitHistory(t *testing.T) {
	const base = "https://tenant.atlassian.net/wiki"

	tests := []struct {
		name                 string
		pageID               string
		currentVersion       int
		versionsWalked       []int
		errorsFetchPageAt    []error
		wikiBase             string
		expectWikiCalls      int
		expectThresholdCalls int
		expectedIDs          []string
		expectedErr          error
	}{
		{
			name:                 "happy path emits historical v1..v4",
			pageID:               "200",
			currentVersion:       5,
			versionsWalked:       []int{1, 2, 3, 4, 5},
			errorsFetchPageAt:    []error{nil, nil, nil, nil, nil},
			wikiBase:             base,
			expectWikiCalls:      4, // v1..v4
			expectThresholdCalls: 4, // v1..v4
			expectedIDs:          []string{"confluence-200-1", "confluence-200-2", "confluence-200-3", "confluence-200-4"},
			expectedErr:          nil,
		},
		{
			name:                 "error fetching page at v1",
			pageID:               "200",
			currentVersion:       2,
			versionsWalked:       []int{1, 2},
			errorsFetchPageAt:    []error{assert.AnError, nil},
			wikiBase:             base,
			expectWikiCalls:      0, // fail before any emit
			expectThresholdCalls: 0,
			expectedIDs:          []string{},
			expectedErr:          assert.AnError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := NewMockConfluenceClient(ctrl)
			mockChunk := chunk.NewMockIChunk(ctrl)

			mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(tc.expectThresholdCalls)
			mockClient.EXPECT().WikiBaseURL().Return(tc.wikiBase).Times(tc.expectWikiCalls)

			for i, v := range tc.versionsWalked {
				if v == tc.currentVersion {
					continue
				}
				if tc.errorsFetchPageAt[i] != nil {
					mockClient.
						EXPECT().
						FetchPageAtVersion(gomock.Any(), tc.pageID, v).
						Return(nil, tc.errorsFetchPageAt[i]).
						Times(1)
					// after first error, the walker stops
					break
				}
				mockClient.
					EXPECT().
					FetchPageAtVersion(gomock.Any(), tc.pageID, v).
					Return(mkPage(tc.pageID, v), nil).
					Times(1)
			}

			mockClient.
				EXPECT().
				WalkPageVersions(gomock.Any(), tc.pageID, maxPageSize, gomock.Any()).
				DoAndReturn(func(_ context.Context, _ string, _ int, visit func(int) error) error {
					for _, v := range tc.versionsWalked {
						if err := visit(v); err != nil {
							return err
						}
					}
					return nil
				}).
				Times(1)

			p := &ConfluencePlugin{
				client:    mockClient,
				itemsChan: make(chan ISourceItem, 16),
				chunker:   mockChunk,
			}

			cur := mkPage(tc.pageID, tc.currentVersion)
			err := p.emitHistory(context.Background(), cur)

			assert.ErrorIs(t, err, tc.expectedErr)

			items := collectEmittedItems(p.itemsChan)
			actual := make([]string, len(items))
			for i := range items {
				actual[i] = items[i].ID
			}
			assert.ElementsMatch(t, tc.expectedIDs, actual)
		})
	}
}

func TestScanBySpaceIDs(t *testing.T) {
	const base = "https://tenant.atlassian.net/wiki"

	tests := []struct {
		name                 string
		spaceIDs             []string
		pagesErr             error
		expectWikiCalls      int
		expectThresholdCalls int
		expectedIDs          []string
		expectedErr          error
	}{
		{
			name:                 "emit pages",
			spaceIDs:             []string{"1", "2"},
			pagesErr:             nil,
			expectWikiCalls:      2,
			expectThresholdCalls: 2,
			expectedIDs:          []string{"confluence-1-1", "confluence-2-1"},
			expectedErr:          nil,
		},
		{
			name:                 "error from WalkPagesBySpaceIDs",
			spaceIDs:             []string{"1", "2"},
			pagesErr:             assert.AnError,
			expectWikiCalls:      0,
			expectThresholdCalls: 0,
			expectedIDs:          []string{},
			expectedErr:          assert.AnError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockChunk := chunk.NewMockIChunk(ctrl)
			mockClient := NewMockConfluenceClient(ctrl)

			mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(tc.expectThresholdCalls)
			mockClient.EXPECT().WikiBaseURL().Return(base).Times(tc.expectWikiCalls)

			p := &ConfluencePlugin{
				itemsChan:         make(chan ISourceItem, 10),
				client:            mockClient,
				chunker:           mockChunk,
				SpaceIDs:          tc.spaceIDs,
				returnedSpaceIDs:  map[string]struct{}{},
				returnedPageIDs:   map[string]struct{}{},
				resolvedSpaceKeys: map[string]string{},
				invalidSpaceIDs:   map[string]struct{}{},
				invalidPageIDs:    map[string]struct{}{},
			}

			mockClient.
				EXPECT().
				WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
				DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
					if tc.pagesErr != nil {
						return tc.pagesErr
					}
					assert.Equal(t, tc.spaceIDs, ids)
					_ = visit(mkPage("1", 1))
					_ = visit(mkPage("2", 1))
					return nil
				}).Times(1)

			err := p.scanBySpaceIDs(context.Background(), tc.spaceIDs)
			assert.ErrorIs(t, err, tc.expectedErr)

			items := collectEmittedItems(p.itemsChan)
			actualIDs := make([]string, 0, len(items))
			for _, it := range items {
				actualIDs = append(actualIDs, it.ID)
			}
			assert.ElementsMatch(t, tc.expectedIDs, actualIDs)
		})
	}
}

func TestResolveAndCollectSpaceIDs(t *testing.T) {
	tests := []struct {
		name        string
		spaceKeys   []string
		mockWalker  func(m *MockConfluenceClient)
		expectedIDs []string
		expectedErr error
	}{
		{
			name:      "happy path: resolves keys and dedupes",
			spaceKeys: []string{"K1", "K2", "K1"},
			mockWalker: func(m *MockConfluenceClient) {
				m.EXPECT().
					WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, keys []string, _ int, visit func(*Space) error) error {
						for _, k := range keys {
							switch k {
							case "K1":
								_ = visit(&Space{ID: "1", Key: "K1"})
							case "K2":
								_ = visit(&Space{ID: "2", Key: "K2"})
							}
						}
						return nil
					}).
					Times(1)
			},
			expectedIDs: []string{"1", "2"},
			expectedErr: nil,
		},
		{
			name:      "propagates WalkSpacesByKeys error",
			spaceKeys: []string{"Key1", "Key2"},
			mockWalker: func(m *MockConfluenceClient) {
				m.EXPECT().
					WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					Return(assert.AnError).
					Times(1)
			},
			expectedIDs: nil,
			expectedErr: assert.AnError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := NewMockConfluenceClient(ctrl)

			p := &ConfluencePlugin{
				client:            mockClient,
				SpaceKeys:         tc.spaceKeys,
				returnedSpaceIDs:  map[string]struct{}{},
				returnedPageIDs:   map[string]struct{}{},
				resolvedSpaceKeys: map[string]string{},
				invalidSpaceIDs:   map[string]struct{}{},
				invalidPageIDs:    map[string]struct{}{},
			}

			tc.mockWalker(mockClient)

			ids, err := p.resolveAndCollectSpaceIDs(context.Background())
			assert.ErrorIs(t, err, tc.expectedErr)
			assert.ElementsMatch(t, tc.expectedIDs, ids)
		})
	}
}

func TestScanByPageIDs(t *testing.T) {
	const base = "https://tenant.atlassian.net/wiki"

	tests := []struct {
		name                 string
		pageIDs              []string
		pagesErr             error
		expectWikiCalls      int
		expectThresholdCalls int
		expectedIDs          []string
		expectedErr          error
	}{
		{
			name:                 "emit pages",
			pageIDs:              []string{"1", "2", "3"},
			pagesErr:             nil,
			expectWikiCalls:      3,
			expectThresholdCalls: 3,
			expectedIDs:          []string{"confluence-1-1", "confluence-2-1", "confluence-3-1"},
			expectedErr:          nil,
		},
		{
			name:                 "error from WalkPagesByIDs",
			pageIDs:              []string{"1", "2", "3"},
			pagesErr:             assert.AnError,
			expectWikiCalls:      0,
			expectThresholdCalls: 0,
			expectedIDs:          []string{},
			expectedErr:          assert.AnError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockChunk := chunk.NewMockIChunk(ctrl)
			mockClient := NewMockConfluenceClient(ctrl)

			mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(tc.expectThresholdCalls)
			mockClient.EXPECT().WikiBaseURL().Return(base).Times(tc.expectWikiCalls)

			p := &ConfluencePlugin{
				itemsChan:         make(chan ISourceItem, 10),
				client:            mockClient,
				chunker:           mockChunk,
				PageIDs:           tc.pageIDs,
				returnedSpaceIDs:  map[string]struct{}{},
				returnedPageIDs:   map[string]struct{}{},
				resolvedSpaceKeys: map[string]string{},
				invalidSpaceIDs:   map[string]struct{}{},
				invalidPageIDs:    map[string]struct{}{},
			}

			mockClient.
				EXPECT().
				WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
				DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
					if tc.pagesErr != nil {
						return tc.pagesErr
					}
					assert.ElementsMatch(t, tc.pageIDs, ids)
					for _, id := range ids {
						_ = visit(mkPage(id, 1))
					}
					return nil
				}).Times(1)

			err := p.scanByPageIDs(context.Background())
			assert.ErrorIs(t, err, tc.expectedErr)

			items := collectEmittedItems(p.itemsChan)
			actualIDs := make([]string, len(items))
			for i := range items {
				actualIDs[i] = items[i].ID
			}
			assert.ElementsMatch(t, tc.expectedIDs, actualIDs)
		})
	}
}

func TestWalkAndEmitPages(t *testing.T) {
	tests := []struct {
		name               string
		setupMocks         func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk)
		setupPlugin        func(p *ConfluencePlugin)
		expectedErr        error
		expectedIDs        []string
		expectedSources    []string
		expectedBodies     []string
		fileThresholdCalls int
		wikiBaseURLCalls   int
	}{
		{
			name: "no filters, history off",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				page := mkPage("100", 3)
				m.EXPECT().
					WalkAllPages(gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ int, visit func(*Page) error) error {
						return visit(page)
					}).Times(1)
			},
			setupPlugin:        func(p *ConfluencePlugin) { p.History = false },
			expectedErr:        nil,
			expectedIDs:        []string{"confluence-100-3"},
			expectedSources:    []string{"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=100&pageVersion=3"},
			expectedBodies:     []string{"content 100"},
			fileThresholdCalls: 1,
			wikiBaseURLCalls:   1,
		},
		{
			name: "no filters, history on (current + older versions)",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				cur := mkPage("200", 5)
				m.EXPECT().
					WalkAllPages(gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ int, visit func(*Page) error) error {
						return visit(cur)
					}).Times(1)

				m.EXPECT().
					WalkPageVersions(gomock.Any(), "200", maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ string, _ int, visit func(int) error) error {
						for _, v := range []int{1, 2, 3, 4, 5} {
							_ = visit(v)
						}
						return nil
					}).Times(1)

				for _, v := range []int{1, 2, 3, 4} {
					m.EXPECT().
						FetchPageAtVersion(gomock.Any(), "200", v).
						DoAndReturn(func(_ context.Context, _ string, _ int) (*Page, error) {
							return mkPage("200", v), nil
						}).Times(1)
				}
			},
			setupPlugin: func(p *ConfluencePlugin) { p.History = true },
			expectedErr: nil,
			expectedIDs: []string{"confluence-200-5", "confluence-200-1", "confluence-200-2", "confluence-200-3", "confluence-200-4"},
			expectedSources: []string{
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=200&pageVersion=5",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=200&pageVersion=1",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=200&pageVersion=2",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=200&pageVersion=3",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=200&pageVersion=4",
			},
			expectedBodies:     []string{"content 200", "content 200", "content 200", "content 200", "content 200"},
			fileThresholdCalls: 5,
			wikiBaseURLCalls:   5,
		},
		{
			name: "SpaceIDs only (dedupe pages)",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
						assert.ElementsMatch(t, []string{"1", "2"}, ids)

						p1 := mkPage("1", 2)
						p1.SpaceID = "1"
						_ = visit(p1)

						p1dup := mkPage("1", 2)
						p1dup.SpaceID = "1"
						_ = visit(p1dup)

						p2 := mkPage("2", 1)
						p2.SpaceID = "2"
						_ = visit(p2)

						return nil
					}).Times(1)
			},
			setupPlugin: func(p *ConfluencePlugin) { p.SpaceIDs = []string{"1", "2"} },
			expectedErr: nil,
			expectedIDs: []string{"confluence-1-2", "confluence-2-1"},
			expectedSources: []string{
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=1&pageVersion=2",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=2&pageVersion=1",
			},
			expectedBodies:     []string{"content 1", "content 2"},
			fileThresholdCalls: 2,
			wikiBaseURLCalls:   2,
		},
		{
			name: "PageIDs only (dedupe)",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkPagesByIDs(gomock.Any(), []string{"10", "20", "10"}, maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
						for _, id := range ids {
							_ = visit(mkPage(id, 1))
						}
						return nil
					}).Times(1)
			},
			setupPlugin: func(p *ConfluencePlugin) { p.PageIDs = []string{"10", "20", "10"} },
			expectedErr: nil,
			expectedIDs: []string{"confluence-10-1", "confluence-20-1"},
			expectedSources: []string{
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=10&pageVersion=1",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=20&pageVersion=1",
			},
			expectedBodies:     []string{"content 10", "content 20"},
			fileThresholdCalls: 2,
			wikiBaseURLCalls:   2,
		},
		{
			name: "filters collide (unique by page ID)",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkPagesBySpaceIDs(gomock.Any(), []string{"1"}, maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Page) error) error {
						p1 := mkPage("1", 3)
						p1.SpaceID = "1"
						_ = visit(p1)

						p2 := mkPage("2", 1)
						p2.SpaceID = "1"
						_ = visit(p2)
						return nil
					}).Times(1)

				m.EXPECT().
					WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Space) error) error {
						_ = visit(&Space{ID: "1", Key: "Key1"})
						return nil
					}).Times(1)

				m.EXPECT().
					WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
						for _, id := range ids {
							_ = visit(mkPage(id, 1))
						}
						return nil
					}).Times(1)
			},
			setupPlugin: func(p *ConfluencePlugin) {
				p.SpaceIDs = []string{"1"}
				p.SpaceKeys = []string{"Key1"}
				p.PageIDs = []string{"1", "3"}
			},
			expectedErr: nil,
			expectedIDs: []string{"confluence-1-3", "confluence-2-1", "confluence-3-1"},
			expectedSources: []string{
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=1&pageVersion=3",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=2&pageVersion=1",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=3&pageVersion=1",
			},
			expectedBodies:     []string{"content 1", "content 2", "content 3"},
			fileThresholdCalls: 3,
			wikiBaseURLCalls:   3,
		},
		{
			name: "error in WalkPagesBySpaceIDs",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, _ func(*Page) error) error {
						return assert.AnError
					}).Times(1)
			},
			setupPlugin:        func(p *ConfluencePlugin) { p.SpaceIDs = []string{"1", "2"} },
			expectedErr:        assert.AnError,
			expectedIDs:        []string{},
			expectedSources:    []string{},
			expectedBodies:     []string{},
			fileThresholdCalls: 0,
			wikiBaseURLCalls:   0,
		},
		{
			name: "error in WalkSpacesByKeys",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, _ func(*Space) error) error {
						return assert.AnError
					}).Times(1)
			},
			setupPlugin:        func(p *ConfluencePlugin) { p.SpaceKeys = []string{"Key1", "Key2"} },
			expectedErr:        assert.AnError,
			expectedIDs:        []string{},
			expectedSources:    []string{},
			expectedBodies:     []string{},
			fileThresholdCalls: 0,
			wikiBaseURLCalls:   0,
		},
		{
			name: "error in WalkPagesByIDs",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, _ func(*Page) error) error {
						return assert.AnError
					}).Times(1)
			},
			setupPlugin:        func(p *ConfluencePlugin) { p.PageIDs = []string{"1", "2"} },
			expectedErr:        assert.AnError,
			expectedIDs:        []string{},
			expectedSources:    []string{},
			expectedBodies:     []string{},
			fileThresholdCalls: 0,
			wikiBaseURLCalls:   0,
		},
		{
			name: "error in WalkAllPages",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkAllPages(gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ int, _ func(*Page) error) error {
						return assert.AnError
					}).Times(1)
			},
			setupPlugin:        func(p *ConfluencePlugin) {},
			expectedErr:        assert.AnError,
			expectedIDs:        []string{},
			expectedSources:    []string{},
			expectedBodies:     []string{},
			fileThresholdCalls: 0,
			wikiBaseURLCalls:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ctrl, mockClient, mockChunk := newPluginWithMock(t)
			defer ctrl.Finish()

			p.itemsChan = make(chan ISourceItem, 200)
			if tc.setupPlugin != nil {
				tc.setupPlugin(p)
			}

			mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(tc.fileThresholdCalls)
			mockClient.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(tc.wikiBaseURLCalls)

			tc.setupMocks(p, mockClient, mockChunk)

			err := p.walkAndEmitPages(context.Background())
			assert.ErrorIs(t, err, tc.expectedErr)

			items := collectEmittedItems(p.itemsChan)
			actualIDs := make([]string, 0, len(items))
			actualSources := make([]string, 0, len(items))
			actualBodies := make([]string, 0, len(items))
			for _, it := range items {
				actualIDs = append(actualIDs, it.ID)
				actualSources = append(actualSources, it.Source)
				actualBodies = append(actualBodies, it.Content)
			}
			assert.ElementsMatch(t, tc.expectedIDs, actualIDs)
			assert.ElementsMatch(t, tc.expectedSources, actualSources)
			assert.ElementsMatch(t, tc.expectedBodies, actualBodies)
		})
	}
}

func TestDefineCommand(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr error
	}{
		{
			name:        "normal execution",
			expectedErr: nil,
		},
		{
			name:        "error during execution",
			expectedErr: assert.AnError,
		},
	}

	recvErr := func(ch <-chan error) error {
		select {
		case e := <-ch:
			return e
		default:
			return nil
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			items := make(chan ISourceItem, 8)
			errs := make(chan error, 1)

			mockClient := NewMockConfluenceClient(ctrl)

			p := &ConfluencePlugin{
				itemsChan:  items,
				errorsChan: errs,
				client:     mockClient,
			}

			cmd, err := p.DefineCommand(items, errs)
			assert.NoError(t, err)

			mockClient.EXPECT().
				WalkAllPages(gomock.Any(), maxPageSize, gomock.Any()).
				Return(tc.expectedErr).
				Times(1)

			cmd.Run(cmd, []string{"https://tenant.atlassian.net/wiki"})

			err = recvErr(errs)
			assert.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

func TestEmitInChunks(t *testing.T) {
	const base = "https://tenant.atlassian.net/wiki"

	tests := []struct {
		name            string
		buildPage       func() *Page
		setupMock       func(m *chunk.MockIChunk)
		expectedErr     error
		expectedIDs     []string
		expectedSources []string
		expectedBodies  []string
	}{
		{
			name: "storage nil: no emission (no chunk calls)",
			buildPage: func() *Page {
				return &Page{
					ID:      "42",
					Links:   map[string]string{"webui": "/pages/viewpage.action?pageId=42"},
					Body:    PageBody{Storage: nil},
					Version: PageVersion{Number: 7},
				}
			},
			setupMock:       func(_ *chunk.MockIChunk) {}, // still no calls expected
			expectedErr:     nil,
			expectedIDs:     []string{},
			expectedSources: []string{},
			expectedBodies:  []string{},
		},
		{
			name: "below threshold: single item (full body)",
			buildPage: func() *Page {
				return &Page{
					ID:    "100",
					Links: map[string]string{"webui": "/pages/viewpage.action?pageId=100"},
					Body: PageBody{
						Storage: &struct {
							Value string `json:"value"`
						}{Value: "AAAEND"},
					},
					Version: PageVersion{Number: 3},
				}
			},
			setupMock: func(m *chunk.MockIChunk) {
				m.EXPECT().GetFileThreshold().Return(int64(100)).Times(1)
			},
			expectedErr:     nil,
			expectedIDs:     []string{"confluence-100-3"},
			expectedSources: []string{base + "/pages/viewpage.action?pageId=100&pageVersion=3"},
			expectedBodies:  []string{"AAAEND"},
		},
		{
			name: "above threshold: two chunks then EOF",
			buildPage: func() *Page {
				return &Page{
					ID:    "999",
					Links: map[string]string{"webui": "/pages/viewpage.action?pageId=999"},
					Body: PageBody{
						Storage: &struct {
							Value string `json:"value"`
						}{Value: strings.Repeat("x", 50)},
					},
					Version: PageVersion{Number: 8},
				}
			},
			setupMock: func(m *chunk.MockIChunk) {
				// Force chunking branch
				m.EXPECT().GetFileThreshold().Return(int64(1)).Times(1)
				m.EXPECT().GetSize().Return(8).Times(1)
				m.EXPECT().GetMaxPeekSize().Return(4).Times(1)

				gomock.InOrder(
					m.EXPECT().
						ReadChunk(gomock.Any(), -1).
						DoAndReturn(func(_ *bufio.Reader, _ int) (string, error) { return "CHUNK-1\n", nil }),
					m.EXPECT().
						ReadChunk(gomock.Any(), -1).
						DoAndReturn(func(_ *bufio.Reader, _ int) (string, error) { return "CHUNK-2\n", nil }),
					m.EXPECT().
						ReadChunk(gomock.Any(), -1).
						DoAndReturn(func(_ *bufio.Reader, _ int) (string, error) { return "", io.EOF }),
				)
			},
			expectedErr: nil,
			expectedIDs: []string{"confluence-999-8", "confluence-999-8"},
			expectedSources: []string{
				base + "/pages/viewpage.action?pageId=999&pageVersion=8",
				base + "/pages/viewpage.action?pageId=999&pageVersion=8",
			},
			expectedBodies: []string{"CHUNK-1\n", "CHUNK-2\n"},
		},
		{
			name: "ReadChunk error: wrapped and returned, no items",
			buildPage: func() *Page {
				return &Page{
					ID:    "500",
					Links: map[string]string{"webui": "/pages/viewpage.action?pageId=500"},
					Body: PageBody{
						Storage: &struct {
							Value string `json:"value"`
						}{Value: "trigger chunking"},
					},
					Version: PageVersion{Number: 1},
				}
			},
			setupMock: func(m *chunk.MockIChunk) {
				m.EXPECT().GetFileThreshold().Return(int64(1)).Times(1)
				m.EXPECT().GetSize().Return(8).Times(1)
				m.EXPECT().GetMaxPeekSize().Return(4).Times(1)
				m.EXPECT().
					ReadChunk(gomock.Any(), -1).
					Return("", assert.AnError).
					Times(1)
			},
			expectedErr:     assert.AnError,
			expectedIDs:     []string{},
			expectedSources: []string{},
			expectedBodies:  []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockChunk := chunk.NewMockIChunk(ctrl)
			mockClient := NewMockConfluenceClient(ctrl)
			mockClient.EXPECT().WikiBaseURL().Return(base).AnyTimes()

			p := &ConfluencePlugin{
				itemsChan: make(chan ISourceItem, 16),
				chunker:   mockChunk,
				client:    mockClient,
			}

			tc.setupMock(mockChunk)

			err := p.emitInChunks(tc.buildPage())
			assert.ErrorIs(t, err, tc.expectedErr)

			// Drain emitted items
			n := len(p.itemsChan)
			actualIDs := make([]string, 0, n)
			actualSources := make([]string, 0, n)
			actualBodies := make([]string, 0, n)
			for i := 0; i < n; i++ {
				it := <-p.itemsChan
				actualIDs = append(actualIDs, it.GetID())
				actualSources = append(actualSources, it.GetSource())
				if it.GetContent() != nil {
					actualBodies = append(actualBodies, *it.GetContent())
				} else {
					actualBodies = append(actualBodies, "")
				}
			}

			assert.ElementsMatch(t, tc.expectedIDs, actualIDs)
			assert.ElementsMatch(t, tc.expectedSources, actualSources)
			// preserve order for bodies (chunks are emitted in sequence)
			assert.Equal(t, tc.expectedBodies, actualBodies)
		})
	}
}

func TestIsValidNumericID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "empty string", input: "", expected: false},
		{name: "single digit", input: "7", expected: true},
		{name: "leading zeros allowed", input: "000123", expected: true},
		{name: "non-digit char", input: "12a3", expected: false},
		{name: "whitespace not allowed", input: "12 3", expected: false},
		{name: "symbol not allowed", input: "123-", expected: false},
		{name: "unicode fullwidth digits not allowed", input: "１２３", expected: false},
		{name: "length exactly 18 ok", input: "123456789012345678", expected: true},
		{name: "length 19 rejected", input: "1234567890123456789", expected: false},
		{name: "length 20 rejected", input: "12345678901234567890", expected: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := isValidNumericID(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestDifferenceStrings(t *testing.T) {
	tests := []struct {
		name     string
		wants    []string
		seen     map[string]struct{}
		expected []string
	}{
		{
			name:     "empty wants",
			wants:    nil,
			seen:     map[string]struct{}{"a": {}},
			expected: nil,
		},
		{
			name:     "all present",
			wants:    []string{"a", "b"},
			seen:     map[string]struct{}{"a": {}, "b": {}},
			expected: nil,
		},
		{
			name:     "some missing",
			wants:    []string{"a", "b", "c"},
			seen:     map[string]struct{}{"b": {}},
			expected: []string{"a", "c"},
		},
		{
			name:     "nil seen treated as empty set",
			wants:    []string{"m", "n"},
			seen:     nil,
			expected: []string{"m", "n"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := differenceStrings(tc.wants, tc.seen)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestMissingKeysFromResolved(t *testing.T) {
	tests := []struct {
		name          string
		requestedKeys []string
		resolved      map[string]string
		expected      []string
	}{
		{
			name:          "emptyRequested",
			requestedKeys: nil,
			resolved:      map[string]string{"K1": "1"},
			expected:      nil,
		},
		{
			name:          "allResolved",
			requestedKeys: []string{"K1", "K2"},
			resolved:      map[string]string{"K1": "1", "K2": "2"},
			expected:      nil,
		},
		{
			name:          "someUnresolved",
			requestedKeys: []string{"K1", "K2", "K3"},
			resolved:      map[string]string{"K1": "1"},
			expected:      []string{"K2", "K3"},
		},
		{
			name:          "nilResolved",
			requestedKeys: []string{"R1", "R2"},
			resolved:      nil,
			expected:      []string{"R1", "R2"},
		},
	}

	for _, tc := range tests {
		actual := missingKeysFromResolved(tc.requestedKeys, tc.resolved)
		assert.Equal(t, tc.expected, actual, tc.name)
	}
}

func TestAbbreviateMiddle(t *testing.T) {
	long30 := strings.Repeat("x", 30)
	long31 := strings.Repeat("y", 31)
	longRunes := strings.Repeat("界", 35) // 35 runes

	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "empty",
			in:       "",
			expected: "",
		},
		{
			name:     "29 should be unchanged",
			in:       strings.Repeat("a", 29),
			expected: strings.Repeat("a", 29),
		},
		{
			name:     "exactly 30 should be abbreviated",
			in:       long30,
			expected: long30[:10] + "..." + long30[len(long30)-10:],
		},
		{
			name:     "longer than 30 should be abbreviated",
			in:       long31,
			expected: long31[:10] + "..." + long31[len(long31)-10:],
		},
		{
			name:     "unicode runes should be abbreviated",
			in:       longRunes,
			expected: string([]rune(longRunes)[:10]) + "..." + string([]rune(longRunes)[len([]rune(longRunes))-10:]),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, abbreviateMiddle(tc.in))
		})
	}
}

func TestAppendUniqueAbbreviated(t *testing.T) {
	long := strings.Repeat("z", 31) // > 30, should abbreviate
	abbr := long[:10] + "..." + long[len(long)-10:]

	tests := []struct {
		name         string
		values       []string
		seedSeen     map[string]struct{}
		expectedOut  []string
		expectedSeen map[string]bool
	}{
		{
			name:        "abbreviates >30 chars and keeps unique",
			values:      []string{long, long},
			seedSeen:    map[string]struct{}{},
			expectedOut: []string{abbr},
			expectedSeen: map[string]bool{
				long: true,
			},
		},
		{
			name:        "dedups against existing seen",
			values:      []string{"A", "B", "A"},
			seedSeen:    map[string]struct{}{"A": {}},
			expectedOut: []string{"B"},
			expectedSeen: map[string]bool{
				"A": true,
				"B": true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out []string
			seen := copySet(tc.seedSeen)

			appendUniqueAbbreviated(tc.values, seen, &out)

			assert.Equal(t, tc.expectedOut, out)
			for must := range tc.expectedSeen {
				_, ok := seen[must]
				assert.True(t, ok, "expected %q present in seenOriginals", must)
			}
		})
	}
}

func TestAppendUniqueMapKeysAbbreviated(t *testing.T) {
	longKey := strings.Repeat("K", 31)
	longAbbr := longKey[:10] + "..." + longKey[len(longKey)-10:]

	tests := []struct {
		name         string
		rawKeys      []string
		seedSeen     map[string]struct{}
		expectedOut  []string
		expectedSeen map[string]bool
	}{
		{
			name:     "abbreviates long keys and deduplicates",
			rawKeys:  []string{"a", "b", longKey, longKey, "a"},
			seedSeen: map[string]struct{}{},
			expectedOut: []string{
				"a", "b", longAbbr,
			},
			expectedSeen: map[string]bool{
				"a": true, "b": true, longKey: true,
			},
		},
		{
			name:         "empty map",
			rawKeys:      nil,
			seedSeen:     map[string]struct{}{},
			expectedOut:  nil,
			expectedSeen: map[string]bool{},
		},
		{
			name:        "dedups against pre-seeded seen",
			rawKeys:     []string{"X", "Y"},
			seedSeen:    map[string]struct{}{"X": {}},
			expectedOut: []string{"Y"},
			expectedSeen: map[string]bool{
				"X": true, "Y": true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := make(map[string]struct{}, len(tc.rawKeys))
			for _, k := range tc.rawKeys {
				m[k] = struct{}{}
			}
			var out []string
			seen := copySet(tc.seedSeen)

			appendUniqueMapKeysAbbreviated(m, seen, &out)

			assert.Equal(t, tc.expectedOut, out)
			for must := range tc.expectedSeen {
				_, ok := seen[must]
				assert.True(t, ok, "expected %q present in seenOriginals", must)
			}
		})
	}
}

func TestMissingSelectorsWarningMessage(t *testing.T) {
	long := strings.Repeat("9", 31)
	abbr := long[:10] + "..." + long[len(long)-10:]

	const prefix = "The following page IDs, space keys, or space IDs couldn’t be processed because they either don’t exist or you don’t have access permissions: "
	const suffixTail = ". These items were excluded from the scan."

	tests := []struct {
		name     string
		setup    func() *ConfluencePlugin
		expected string
	}{
		{
			name: "empty everything returns empty message",
			setup: func() *ConfluencePlugin {
				return &ConfluencePlugin{
					returnedPageIDs:   map[string]struct{}{},
					returnedSpaceIDs:  map[string]struct{}{},
					invalidPageIDs:    map[string]struct{}{},
					invalidSpaceIDs:   map[string]struct{}{},
					resolvedSpaceKeys: map[string]string{},
				}
			},
			expected: "",
		},
		{
			name: "shows first four and suffix for remaining",
			setup: func() *ConfluencePlugin {
				return &ConfluencePlugin{
					PageIDs:           []string{long, "A", "B", "C", "D", "E"},
					returnedPageIDs:   map[string]struct{}{},
					returnedSpaceIDs:  map[string]struct{}{},
					invalidPageIDs:    map[string]struct{}{},
					invalidSpaceIDs:   map[string]struct{}{},
					resolvedSpaceKeys: map[string]string{},
				}
			},
			expected: prefix + strings.Join([]string{abbr, "A", "B", "C"}, ", ") + " + 2 more" + suffixTail,
		},
		{
			name: "invalid page and space IDs only",
			setup: func() *ConfluencePlugin {
				return &ConfluencePlugin{
					// simulate user requested these; nothing returned
					PageIDs:          []string{"P_BAD1"},
					SpaceIDs:         []string{"S_BAD1"},
					returnedPageIDs:  map[string]struct{}{},
					returnedSpaceIDs: map[string]struct{}{},
					// walker marked them as invalid
					invalidPageIDs:  map[string]struct{}{"P_BAD1": {}},
					invalidSpaceIDs: map[string]struct{}{"S_BAD1": {}},
					// no keys involved here
					resolvedSpaceKeys: map[string]string{},
				}
			},
			expected: prefix + strings.Join([]string{"P_BAD1", "S_BAD1"}, ", ") + suffixTail,
		},
		{
			name: "mixed selectors and dedup",
			setup: func() *ConfluencePlugin {
				return &ConfluencePlugin{
					PageIDs:  []string{"X", "Y", "Y", "Z", "X"},
					SpaceIDs: []string{"S1", "S2", "S2"},
					SpaceKeys: []string{
						"K1", "K2", "K1",
					},
					returnedPageIDs:   map[string]struct{}{"X": {}},
					returnedSpaceIDs:  map[string]struct{}{"S1": {}},
					resolvedSpaceKeys: map[string]string{"K1": "S-resolved-1"},
					invalidPageIDs:    map[string]struct{}{},
					invalidSpaceIDs:   map[string]struct{}{},
				}
			},
			expected: prefix + strings.Join([]string{"Y", "Z", "K2", "S2"}, ", ") + suffixTail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.setup()
			actual := p.missingSelectorsWarningMessage()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestTrimNonEmpty(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty slice ",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "all spaces",
			input:    []string{"   ", "\t", "\n"},
			expected: nil,
		},
		{
			name:     "mix of spaces and values",
			input:    []string{"  A  ", "   ", "\tB", "C\t", "   D   "},
			expected: []string{"A", "B", "C", "D"},
		},
		{
			name:     "already trimmed values kept",
			input:    []string{"A", "B", "C"},
			expected: []string{"A", "B", "C"},
		},
		{
			name:     "duplicates preserved",
			input:    []string{" A ", "A", "  A  "},
			expected: []string{"A", "A", "A"},
		},
	}

	for _, tc := range tests {
		actual := trimNonEmpty(tc.input)
		assert.Equal(t, tc.expected, actual, tc.name)
	}
}

func newPluginWithMock(t *testing.T) (*ConfluencePlugin, *gomock.Controller, *MockConfluenceClient, *chunk.MockIChunk) {
	t.Helper()
	ctrl := gomock.NewController(t)

	mockClient := NewMockConfluenceClient(ctrl)
	mockChunk := chunk.NewMockIChunk(ctrl)

	p := &ConfluencePlugin{
		itemsChan:         make(chan ISourceItem, 1000),
		client:            mockClient,
		chunker:           mockChunk,
		returnedSpaceIDs:  map[string]struct{}{},
		returnedPageIDs:   map[string]struct{}{},
		resolvedSpaceKeys: map[string]string{},
		invalidSpaceIDs:   map[string]struct{}{},
		invalidPageIDs:    map[string]struct{}{},
	}
	return p, ctrl, mockClient, mockChunk
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
	for range n {
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

func copySet(src map[string]struct{}) map[string]struct{} {
	if src == nil {
		return nil
	}
	dst := make(map[string]struct{}, len(src))
	for k := range src {
		dst[k] = struct{}{}
	}
	return dst
}
