package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
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

func TestIsValidTokenType(t *testing.T) {
	tests := []struct {
		name          string
		tokenType     TokenType
		expectedValid bool
	}{
		{
			name:          "empty",
			tokenType:     "",
			expectedValid: true,
		},
		{
			name:          "classic",
			tokenType:     TokenClassic,
			expectedValid: true,
		},
		{
			name:          "scoped",
			tokenType:     TokenScoped,
			expectedValid: true,
		},
		{
			name:          "invalid",
			tokenType:     TokenType("weird"),
			expectedValid: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedValid, isValidTokenType(tc.tokenType))
		})
	}
}

func TestInitialize(t *testing.T) {
	const (
		baseURL         = "https://tenant.atlassian.net/wiki"
		expectedAPIBase = "https://tenant.atlassian.net/wiki/api/v2"
		username        = "user@example.com"
		tokenValue      = "token123"
	)

	tests := []struct {
		name           string
		base           string
		tokenType      TokenType
		username       string
		tokenValue     string
		expectedErr    error
		expectedClient ConfluenceClient
	}{
		{
			name:        "valid initialization (classic)",
			base:        baseURL,
			tokenType:   TokenClassic,
			username:    username,
			tokenValue:  tokenValue,
			expectedErr: nil,
			expectedClient: &httpConfluenceClient{
				baseWikiURL: baseURL,
				httpClient:  &http.Client{Timeout: httpTimeout},
				username:    username,
				token:       tokenValue,
				apiBase:     expectedAPIBase,
			},
		},
		{
			name:           "invalid initialization (unsupported token type)",
			base:           baseURL,
			tokenType:      TokenType("bad"),
			username:       username,
			tokenValue:     tokenValue,
			expectedErr:    ErrUnsupportedTokenType,
			expectedClient: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewConfluencePlugin().(*ConfluencePlugin)
			err := p.initialize(tc.base, tc.username, tc.tokenType, tc.tokenValue)

			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedClient, p.client)
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
			if tc.expectCalls > 0 {
				mockClient.EXPECT().WikiBaseURL().Return(base).Times(tc.expectCalls)
			}

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
	}{
		{
			name:        "webui relative + version",
			links:       map[string]string{"webui": "/pages/viewpage.action?pageId=123"},
			version:     4,
			expectCalls: 1,
			canResolve:  true,
			expectedURL: base + "/pages/viewpage.action?pageId=123&pageVersion=4",
		},
		{
			name:        "webui absolute + version",
			links:       map[string]string{"webui": base + "/pages/viewpage.action?pageId=456"},
			version:     2,
			expectCalls: 1,
			canResolve:  true,
			expectedURL: base + "/pages/viewpage.action?pageId=456&pageVersion=2",
		},
		{
			name:        "fallback base",
			links:       map[string]string{"base": base},
			version:     1,
			expectCalls: 0,
			canResolve:  true,
			expectedURL: base,
		},
		{
			name:        "missing links",
			links:       nil,
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
			if tc.expectCalls > 0 {
				mockClient.EXPECT().WikiBaseURL().Return(base).Times(tc.expectCalls)
			}

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
					return fmt.Errorf("simulated error")
				}
			},
			expectedBatches:   [][]string{{"1", "2"}},
			expectedEmitCount: 0,
			expectedErr:       fmt.Errorf("simulated error"),
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
				itemsChan: make(chan ISourceItem, 100),
				chunker:   mockChunk,
				client:    mockClient,
			}

			seen := map[string]struct{}{}
			var seenBatches [][]string
			walker := func(ctx context.Context, ids []string, lim int, v func(*Page) error) error {
				seenBatches = append(seenBatches, append([]string(nil), ids...))
				return tc.setupWalker()(ctx, ids, lim, v)
			}

			actualErr := p.walkPagesByIDBatches(context.Background(), tc.allIDs, tc.perBatch, seen, walker)
			assert.Equal(t, tc.expectedErr, actualErr)
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
		expectedEmitCount int
	}{
		{
			name:              "first time emits",
			seenPages:         map[string]struct{}{},
			page:              mkPage("42", 3),
			expectedEmitCount: 1,
		},
		{
			name:              "already seen",
			seenPages:         map[string]struct{}{"42": {}},
			page:              mkPage("42", 3),
			expectedEmitCount: 0,
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
				itemsChan: make(chan ISourceItem, 10),
				chunker:   mockChunk,
				client:    mockClient,
			}

			actualErr := p.emitUniquePage(context.Background(), tc.page, tc.seenPages)
			assert.NoError(t, actualErr)
			assert.Len(t, collectEmittedItems(p.itemsChan), tc.expectedEmitCount)
		})
	}
}

func TestEmitHistory(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockChunk := chunk.NewMockIChunk(ctrl)
	mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(4) // v1..v4

	mock := NewMockConfluenceClient(ctrl)
	mock.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(4) // v1..v4

	p := &ConfluencePlugin{
		client:    mock,
		itemsChan: make(chan ISourceItem, 10),
		chunker:   mockChunk,
	}

	cur := mkPage("200", 5)

	mock.EXPECT().
		WalkPageVersions(gomock.Any(), "200", maxPageSize, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, _ int, visit func(int) error) error {
			for _, v := range []int{1, 2, 3, 4, 5} {
				_ = visit(v)
			}
			return nil
		}).Times(1)

	for _, v := range []int{1, 2, 3, 4} {
		mock.EXPECT().
			FetchPageAtVersion(gomock.Any(), "200", v).
			DoAndReturn(func(_ context.Context, _ string, _ int) (*Page, error) {
				return mkPage("200", v), nil
			}).Times(1)
	}

	actualErr := p.emitHistory(context.Background(), cur)
	assert.NoError(t, actualErr)

	items := collectEmittedItems(p.itemsChan)
	actualIDs := []string{items[0].ID, items[1].ID, items[2].ID, items[3].ID}
	expectedIDs := []string{"confluence-200-1", "confluence-200-2", "confluence-200-3", "confluence-200-4"}
	assert.ElementsMatch(t, expectedIDs, actualIDs)
}

func TestScanBySpaceIDs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockChunk := chunk.NewMockIChunk(ctrl)
	mockClient := NewMockConfluenceClient(ctrl)

	mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(2)
	mockClient.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(2)

	p := &ConfluencePlugin{
		itemsChan: make(chan ISourceItem, 10),
		client:    mockClient,
		chunker:   mockChunk,
	}
	p.SpaceIDs = []string{"S1", "S2", "S1"} // dedupe

	seenPages := map[string]struct{}{}
	seenSpaces := map[string]struct{}{}

	mockClient.EXPECT().
		WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
		DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
			assert.ElementsMatch(t, []string{"S1", "S2"}, ids)
			_ = visit(mkPage("P1", 1))
			_ = visit(mkPage("P2", 1))
			return nil
		}).Times(1)

	err := p.scanBySpaceIDs(context.Background(), seenPages, seenSpaces)
	assert.NoError(t, err)
	assert.Len(t, collectEmittedItems(p.itemsChan), 2)
}

func TestScanBySpaceKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockChunk := chunk.NewMockIChunk(ctrl)
	mockClient := NewMockConfluenceClient(ctrl)

	mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(2)
	mockClient.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(2)

	p := &ConfluencePlugin{
		itemsChan: make(chan ISourceItem, 10),
		client:    mockClient,
		chunker:   mockChunk,
	}
	p.SpaceKeys = []string{"K1", "K2", "K1"}

	seenPages := map[string]struct{}{}
	seenSpaces := map[string]struct{}{}

	mockClient.EXPECT().
		WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
		DoAndReturn(func(_ context.Context, keys []string, _ int, visit func(*Space) error) error {
			for _, k := range keys {
				switch k {
				case "K1":
					_ = visit(&Space{ID: "S1", Key: "K1"})
				case "K2":
					_ = visit(&Space{ID: "S2", Key: "K2"})
				}
			}
			return nil
		}).Times(1)

	mockClient.EXPECT().
		WalkPagesBySpaceIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
		DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
			assert.ElementsMatch(t, []string{"S1", "S2"}, ids)
			for _, id := range ids {
				_ = visit(mkPage("P-"+id, 1))
			}
			return nil
		}).Times(1)

	err := p.scanBySpaceKeys(context.Background(), seenPages, seenSpaces)
	assert.NoError(t, err)

	items := collectEmittedItems(p.itemsChan)
	assert.ElementsMatch(t,
		[]string{"confluence-P-S1-1", "confluence-P-S2-1"},
		[]string{items[0].ID, items[1].ID},
	)
}

func TestScanByPageIDs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockChunk := chunk.NewMockIChunk(ctrl)
	mockClient := NewMockConfluenceClient(ctrl)

	mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(3)
	mockClient.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(3)

	p := &ConfluencePlugin{
		itemsChan: make(chan ISourceItem, 10),
		client:    mockClient,
		chunker:   mockChunk,
	}
	p.PageIDs = []string{"1", "2", "3"}

	seenPages := map[string]struct{}{}

	mockClient.EXPECT().
		WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
		DoAndReturn(func(_ context.Context, ids []string, _ int, visit func(*Page) error) error {
			assert.ElementsMatch(t, []string{"1", "2", "3"}, ids)
			for _, id := range ids {
				_ = visit(mkPage(id, 1))
			}
			return nil
		}).Times(1)

	err := p.scanByPageIDs(context.Background(), seenPages)
	assert.NoError(t, err)
	assert.Len(t, collectEmittedItems(p.itemsChan), 3)
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
					WalkPagesBySpaceIDs(gomock.Any(), []string{"S1", "S2"}, maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Page) error) error {
						_ = visit(mkPage("P1", 2))
						_ = visit(mkPage("P1", 2))
						_ = visit(mkPage("P2", 1))
						return nil
					}).Times(1)
			},
			setupPlugin: func(p *ConfluencePlugin) { p.SpaceIDs = []string{"S1", "S2"} },
			expectedErr: nil,
			expectedIDs: []string{"confluence-P1-2", "confluence-P2-1"},
			expectedSources: []string{
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=P1&pageVersion=2",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=P2&pageVersion=1",
			},
			expectedBodies:     []string{"content P1", "content P2"},
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
					WalkPagesBySpaceIDs(gomock.Any(), []string{"S1"}, maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Page) error) error {
						_ = visit(mkPage("P1", 3))
						_ = visit(mkPage("P2", 1))
						return nil
					}).Times(1)

				m.EXPECT().
					WalkSpacesByKeys(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, visit func(*Space) error) error {
						_ = visit(&Space{ID: "S1", Key: "Key1"})
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
				p.SpaceIDs = []string{"S1"}
				p.SpaceKeys = []string{"Key1"}
				p.PageIDs = []string{"P1", "P3"}
			},
			expectedErr: nil,
			expectedIDs: []string{"confluence-P1-3", "confluence-P2-1", "confluence-P3-1"},
			expectedSources: []string{
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=P1&pageVersion=3",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=P2&pageVersion=1",
				"https://tenant.atlassian.net/wiki/pages/viewpage.action?pageId=P3&pageVersion=1",
			},
			expectedBodies:     []string{"content P1", "content P2", "content P3"},
			fileThresholdCalls: 3,
			wikiBaseURLCalls:   3,
		},
		{
			name: "error propagation",
			setupMocks: func(p *ConfluencePlugin, m *MockConfluenceClient, mc *chunk.MockIChunk) {
				m.EXPECT().
					WalkPagesByIDs(gomock.Any(), gomock.Any(), maxPageSize, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ []string, _ int, _ func(*Page) error) error {
						return fmt.Errorf("simulated error")
					}).Times(1)
			},
			setupPlugin:        func(p *ConfluencePlugin) { p.PageIDs = []string{"1", "2"} },
			expectedErr:        fmt.Errorf("simulated error"),
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

			if tc.fileThresholdCalls > 0 {
				mockChunk.EXPECT().GetFileThreshold().Return(int64(mockGetFileThresholdReturn)).Times(tc.fileThresholdCalls)
			}
			if tc.wikiBaseURLCalls > 0 {
				mockClient.EXPECT().WikiBaseURL().Return("https://tenant.atlassian.net/wiki").Times(tc.wikiBaseURLCalls)
			}

			tc.setupMocks(p, mockClient, mockChunk)

			actualErr := p.walkAndEmitPages(context.Background())
			assert.Equal(t, tc.expectedErr, actualErr)

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
		setFlags    func(cmd *cobra.Command)
		args        []string
		expectedErr error
	}{
		{
			name: "token value but no token type",
			setFlags: func(cmd *cobra.Command) {
				_ = cmd.Flags().Set("token-value", "value")
				// token-type intentionally not set
			},
			args:        []string{"https://tenant.atlassian.net/wiki"},
			expectedErr: fmt.Errorf("--token-type must be set when --token-value is provided"),
		},
		{
			name: "invalid token type",
			setFlags: func(cmd *cobra.Command) {
				_ = cmd.Flags().Set("token-type", "bad")
			},
			args:        []string{"https://tenant.atlassian.net/wiki"},
			expectedErr: fmt.Errorf("invalid --token-type \"bad\"; valid values are \"classic\" or \"scoped\""),
		},
		{
			name: "token type classic but without token value",
			setFlags: func(cmd *cobra.Command) {
				_ = cmd.Flags().Set("token-type", string(TokenClassic))
				// no token-value
			},
			args:        []string{"https://tenant.atlassian.net/wiki"},
			expectedErr: fmt.Errorf("--token-type requires --token-value"),
		},
		{
			name: "without credentials",
			setFlags: func(cmd *cobra.Command) {
				// nothing set
			},
			args:        []string{"https://tenant.atlassian.net/wiki"},
			expectedErr: nil,
		},
		{
			name: "token type classic and token value provided",
			setFlags: func(cmd *cobra.Command) {
				_ = cmd.Flags().Set("username", "user@example.com")
				_ = cmd.Flags().Set("token-type", string(TokenClassic))
				_ = cmd.Flags().Set("token-value", "tok")
			},
			args:        []string{"https://tenant.atlassian.net/wiki"},
			expectedErr: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &ConfluencePlugin{}
			cmd, err := p.DefineCommand(make(chan ISourceItem, 1), make(chan error, 1))
			assert.NoError(t, err)

			if tc.setFlags != nil {
				tc.setFlags(cmd)
			}
			err = cmd.PreRunE(cmd, tc.args)
			assert.Equal(t, tc.expectedErr, err)
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
					Return("", fmt.Errorf("simulated error")).
					Times(1)
			},
			expectedErr:     fmt.Errorf("failed to read chunk for page 500: %w", fmt.Errorf("simulated error")),
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

			actualErr := p.emitInChunks(tc.buildPage())
			assert.Equal(t, tc.expectedErr, actualErr)

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

func newPluginWithMock(t *testing.T) (*ConfluencePlugin, *gomock.Controller, *MockConfluenceClient, *chunk.MockIChunk) {
	t.Helper()
	ctrl := gomock.NewController(t)

	mockClient := NewMockConfluenceClient(ctrl)
	mockChunk := chunk.NewMockIChunk(ctrl)

	p := &ConfluencePlugin{
		itemsChan: make(chan ISourceItem, 1000),
		client:    mockClient,
		chunker:   mockChunk,
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
