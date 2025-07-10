package plugins

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

type mockConfluenceClient struct {
	pageContentResponse      []*ConfluencePageContent
	pageContentError         error
	numberOfPages            int
	firstPagesRequestError   error
	secondPagesRequestError  error
	numberOfSpaces           int
	firstSpacesRequestError  error
	secondSpacesRequestError error
}

func (m *mockConfluenceClient) getSpacesRequest(start int) (*ConfluenceSpaceResponse, error) {
	if m.firstSpacesRequestError != nil && start == 0 {
		return nil, m.firstSpacesRequestError
	}

	if m.secondSpacesRequestError != nil && start != 0 {
		return nil, m.secondSpacesRequestError
	}

	var spaces []ConfluenceSpaceResult
	for i := start; i < m.numberOfSpaces && i-start < confluenceDefaultWindow; i++ {
		spaces = append(spaces, ConfluenceSpaceResult{ID: i, Key: strconv.Itoa(i)})
	}
	return &ConfluenceSpaceResponse{
		Results: spaces,
		Size:    len(spaces),
	}, nil
}

func (m *mockConfluenceClient) getPagesRequest(space ConfluenceSpaceResult, start int) (*ConfluencePageResult, error) {
	if m.firstPagesRequestError != nil && start == 0 {
		return nil, m.firstPagesRequestError
	}

	if m.secondPagesRequestError != nil && start != 0 {
		return nil, m.secondPagesRequestError
	}

	var pages []ConfluencePage
	for i := start; i < m.numberOfPages && i-start < confluenceDefaultWindow; i++ {
		pages = append(pages, ConfluencePage{ID: strconv.Itoa(i)})
	}
	return &ConfluencePageResult{Pages: pages}, nil
}

func (m *mockConfluenceClient) getPageContentRequest(page ConfluencePage, version int) (*ConfluencePageContent, error) {
	if m.pageContentError != nil {
		return nil, m.pageContentError
	}
	return m.pageContentResponse[version], nil
}

func TestGetPages(t *testing.T) {
	tests := []struct {
		name                    string
		numberOfPages           int
		firstPagesRequestError  error
		secondPagesRequestError error
		expectedError           error
	}{
		{
			name:                   "Error while getting pages before pagination is required",
			numberOfPages:          confluenceDefaultWindow - 2,
			firstPagesRequestError: fmt.Errorf("some error before pagination is required"),
			expectedError: fmt.Errorf(
				"unexpected error creating an http request %w",
				fmt.Errorf("some error before pagination is required"),
			),
		},
		{
			name:                    "error while getting pages after pagination is required",
			numberOfPages:           confluenceDefaultWindow + 2,
			secondPagesRequestError: fmt.Errorf("some error after pagination required"),
			expectedError: fmt.Errorf(
				"unexpected error creating an http request %w",
				fmt.Errorf("some error after pagination required"),
			),
		},
		{
			name:          "pages less than confluenceDefaultWindow",
			numberOfPages: confluenceDefaultWindow - 2,
			expectedError: nil,
		},
		{
			name:          "exactly confluenceDefaultWindow pages",
			numberOfPages: confluenceDefaultWindow,
			expectedError: nil,
		},
		{
			name:          "fetching more pages after confluenceDefaultWindow",
			numberOfPages: confluenceDefaultWindow + 2,
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mockConfluenceClient{
				numberOfPages:           tt.numberOfPages,
				firstPagesRequestError:  tt.firstPagesRequestError,
				secondPagesRequestError: tt.secondPagesRequestError,
			}
			space := ConfluenceSpaceResult{Name: "Test Space"}
			plugin := &ConfluencePlugin{client: &mockClient}
			result, err := plugin.getPages(space)
			assert.Equal(t, tt.expectedError, err)
			if tt.expectedError == nil {
				var expectedResult ConfluencePageResult
				for i := 0; i < tt.numberOfPages; i++ {
					expectedResult.Pages = append(expectedResult.Pages, ConfluencePage{ID: strconv.Itoa(i)})
				}
				assert.Equal(t, &expectedResult, result)
			}
		})
	}
}

func TestGetSpaces(t *testing.T) {
	tests := []struct {
		name                     string
		numberOfSpaces           int
		firstSpacesRequestError  error
		secondSpacesRequestError error
		expectedError            error
		filteredSpaces           []string
	}{
		{
			name:                    "Error while getting spaces before pagination is required",
			numberOfSpaces:          confluenceDefaultWindow - 2,
			firstSpacesRequestError: fmt.Errorf("some error before pagination is required"),
			expectedError:           fmt.Errorf("some error before pagination is required"),
		},
		{
			name:                     "error while getting spaces after pagination is required",
			numberOfSpaces:           confluenceDefaultWindow + 2,
			secondSpacesRequestError: fmt.Errorf("some error after pagination required"),
			expectedError:            fmt.Errorf("some error after pagination required"),
		},
		{
			name:           "zero spaces",
			numberOfSpaces: 0,
			expectedError:  nil,
		},
		{
			name:           "spaces less than confluenceDefaultWindow",
			numberOfSpaces: confluenceDefaultWindow - 2,
			expectedError:  nil,
		},
		{
			name:           "exactly confluenceDefaultWindow spaces",
			numberOfSpaces: confluenceDefaultWindow,
			expectedError:  nil,
		},
		{
			name:           "fetching more spaces after confluenceDefaultWindow",
			numberOfSpaces: confluenceDefaultWindow + 2,
			expectedError:  nil,
		},
		{
			name:           "fetching spaces with filtered spaces",
			numberOfSpaces: 5,
			filteredSpaces: []string{"2"},
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mockConfluenceClient{
				numberOfSpaces:           tt.numberOfSpaces,
				firstSpacesRequestError:  tt.firstSpacesRequestError,
				secondSpacesRequestError: tt.secondSpacesRequestError,
			}
			plugin := &ConfluencePlugin{
				client: &mockClient,
				Spaces: tt.filteredSpaces,
			}
			result, err := plugin.getSpaces()
			assert.Equal(t, tt.expectedError, err)
			if tt.expectedError == nil {
				var expectedResult []ConfluenceSpaceResult
				if len(tt.filteredSpaces) == 0 {
					for i := 0; i < tt.numberOfSpaces; i++ {
						expectedResult = append(expectedResult, ConfluenceSpaceResult{ID: i, Key: strconv.Itoa(i)})
					}
				} else {
					for i := 0; i < len(tt.filteredSpaces); i++ {
						id, errConvert := strconv.Atoi(tt.filteredSpaces[i])
						key := tt.filteredSpaces[i]
						assert.NoError(t, errConvert)
						expectedResult = append(expectedResult, ConfluenceSpaceResult{ID: id, Key: key})
					}
				}
				assert.Equal(t, expectedResult, result)
			}
		})
	}
}

func TestScanPageVersion(t *testing.T) {
	tests := []struct {
		name               string
		mockPageContent    *ConfluencePageContent
		mockError          error
		expectError        bool
		expectItem         bool
		expectedVersionNum int
	}{
		{
			name: "Successful page scan with previous version",
			mockPageContent: &ConfluencePageContent{
				Body: struct {
					Storage struct {
						Value string `json:"value"`
					} `json:"storage"`
				}(struct {
					Storage struct {
						Value string
					}
				}{
					Storage: struct{ Value string }{Value: "Page content"},
				}),
				History: struct {
					PreviousVersion struct{ Number int } `json:"previousVersion"`
				}(struct {
					PreviousVersion struct {
						Number int
					}
				}{PreviousVersion: struct{ Number int }{Number: 1}}),
				Links: map[string]string{
					"base":  "https://example.com",
					"webui": "/wiki/page",
				},
			},
			expectItem:         true,
			expectedVersionNum: 1,
		},
		{
			name:               "Error fetching page content",
			mockError:          fmt.Errorf("fetch error"),
			expectError:        true,
			expectItem:         false,
			expectedVersionNum: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockConfluenceClient{
				pageContentResponse: []*ConfluencePageContent{tt.mockPageContent},
				pageContentError:    tt.mockError,
			}

			errorsChan := make(chan error, 1)
			itemsChan := make(chan ISourceItem, 1)

			plugin := &ConfluencePlugin{
				client:     mockClient,
				errorsChan: errorsChan,
				itemsChan:  itemsChan,
			}

			page := ConfluencePage{ID: "pageID"}
			space := ConfluenceSpaceResult{Key: "spaceKey"}

			result := plugin.scanPageVersion(page, space, 0)

			assert.Equal(t, tt.expectedVersionNum, result)

			if tt.expectError {
				assert.NotEmpty(t, errorsChan)
				err := <-errorsChan
				assert.Equal(t, tt.mockError, err)
			} else {
				assert.Empty(t, errorsChan)
			}

			if tt.expectItem {
				assert.NotEmpty(t, itemsChan)
				actualItem := <-itemsChan
				expectedItem := item{
					Content: ptrToString("Page content"),
					ID:      "confluence-spaceKey-pageID",
					Source:  "https://example.com/wiki/page",
				}
				assert.Equal(t, &expectedItem, actualItem)
			} else {
				assert.Empty(t, itemsChan)
			}

			close(itemsChan)
			close(errorsChan)
		})
	}
}

func TestScanPageAllVersions(t *testing.T) {
	tests := []struct {
		name             string
		mockPageContents []*ConfluencePageContent
		expectedErrors   []error
		expectedItems    []item
		historyEnabled   bool
	}{
		{
			name: "scan with multiple versions and history enabled",
			mockPageContents: []*ConfluencePageContent{
				{
					Body: struct {
						Storage struct {
							Value string `json:"value"`
						} `json:"storage"`
					}(struct {
						Storage struct {
							Value string
						}
					}{
						Storage: struct{ Value string }{Value: "Page content 1"},
					}),
					History: struct {
						PreviousVersion struct{ Number int } `json:"previousVersion"`
					}(struct{ PreviousVersion struct{ Number int } }{PreviousVersion: struct{ Number int }{Number: 2}}),
					Links: map[string]string{
						"base":  "https://example.com",
						"webui": "/wiki/page",
					},
				},
				{
					Body: struct {
						Storage struct {
							Value string `json:"value"`
						} `json:"storage"`
					}(struct {
						Storage struct {
							Value string
						}
					}{
						Storage: struct{ Value string }{Value: "Page content 2"},
					}),
					History: struct {
						PreviousVersion struct{ Number int } `json:"previousVersion"`
					}(struct{ PreviousVersion struct{ Number int } }{PreviousVersion: struct{ Number int }{Number: 0}}),
					Links: map[string]string{
						"base":  "https://example.com",
						"webui": "/wiki/page",
					},
				},
				{
					Body: struct {
						Storage struct {
							Value string `json:"value"`
						} `json:"storage"`
					}(struct {
						Storage struct {
							Value string
						}
					}{
						Storage: struct{ Value string }{Value: "Page content 3"},
					}),
					History: struct {
						PreviousVersion struct{ Number int } `json:"previousVersion"`
					}(struct{ PreviousVersion struct{ Number int } }{PreviousVersion: struct{ Number int }{Number: 1}}),
					Links: map[string]string{
						"base":  "https://example.com",
						"webui": "/wiki/page",
					},
				},
			},
			historyEnabled: true,
			expectedErrors: nil,
			expectedItems: []item{
				{
					Content: ptrToString("Page content 1"),
					ID:      "confluence-spaceKey-pageID",
					Source:  "https://example.com/wiki/page",
				},
				{
					Content: ptrToString("Page content 3"),
					ID:      "confluence-spaceKey-pageID",
					Source:  "https://example.com/wiki/page",
				},
				{
					Content: ptrToString("Page content 2"),
					ID:      "confluence-spaceKey-pageID",
					Source:  "https://example.com/wiki/page",
				},
			},
		},
		{
			name: "scan with multiple versions and history disabled",
			mockPageContents: []*ConfluencePageContent{
				{
					Body: struct {
						Storage struct {
							Value string `json:"value"`
						} `json:"storage"`
					}(struct {
						Storage struct {
							Value string
						}
					}{
						Storage: struct{ Value string }{Value: "Page content 1"},
					}),
					History: struct {
						PreviousVersion struct{ Number int } `json:"previousVersion"`
					}(struct{ PreviousVersion struct{ Number int } }{PreviousVersion: struct{ Number int }{Number: 2}}),
					Links: map[string]string{
						"base":  "https://example.com",
						"webui": "/wiki/page",
					},
				},
				{
					Body: struct {
						Storage struct {
							Value string `json:"value"`
						} `json:"storage"`
					}(struct {
						Storage struct {
							Value string
						}
					}{
						Storage: struct{ Value string }{Value: "Page content 2"},
					}),
					History: struct {
						PreviousVersion struct{ Number int } `json:"previousVersion"`
					}(struct{ PreviousVersion struct{ Number int } }{PreviousVersion: struct{ Number int }{Number: 0}}),
					Links: map[string]string{
						"base":  "https://example.com",
						"webui": "/wiki/page",
					},
				},
				{
					Body: struct {
						Storage struct {
							Value string `json:"value"`
						} `json:"storage"`
					}(struct {
						Storage struct {
							Value string
						}
					}{
						Storage: struct{ Value string }{Value: "Page content 3"},
					}),
					History: struct {
						PreviousVersion struct{ Number int } `json:"previousVersion"`
					}(struct{ PreviousVersion struct{ Number int } }{PreviousVersion: struct{ Number int }{Number: 1}}),
					Links: map[string]string{
						"base":  "https://example.com",
						"webui": "/wiki/page",
					},
				},
			},
			historyEnabled: false,
			expectedErrors: nil,
			expectedItems: []item{
				{
					Content: ptrToString("Page content 1"),
					ID:      "confluence-spaceKey-pageID",
					Source:  "https://example.com/wiki/page",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockConfluenceClient{
				pageContentResponse: tt.mockPageContents,
			}

			errorsChan := make(chan error, 3)
			itemsChan := make(chan ISourceItem, 3)

			plugin := &ConfluencePlugin{
				client:     mockClient,
				errorsChan: errorsChan,
				itemsChan:  itemsChan,
				History:    tt.historyEnabled,
			}

			page := ConfluencePage{ID: "pageID"}
			space := ConfluenceSpaceResult{Key: "spaceKey"}

			var wg sync.WaitGroup
			wg.Add(1)
			go plugin.scanPageAllVersions(&wg, page, space)
			wg.Wait()

			if len(tt.expectedErrors) == 0 {
				assert.Empty(t, errorsChan)
			}

			assert.Equal(t, len(tt.expectedErrors), len(errorsChan))
			for _, expectedError := range tt.expectedErrors {
				actualError := <-errorsChan
				assert.Equal(t, expectedError, actualError)
			}

			assert.Equal(t, len(tt.expectedItems), len(itemsChan))
			for _, expectedItem := range tt.expectedItems {
				actualItem := <-itemsChan
				assert.Equal(t, &expectedItem, actualItem)
			}

			close(errorsChan)
			close(itemsChan)
		})
	}
}

func TestScanConfluenceSpace(t *testing.T) {
	tests := []struct {
		name                   string
		firstPagesRequestError error
		expectedError          error
		numberOfPages          int
		mockPageContent        *ConfluencePageContent
	}{
		{
			name:                   "getPages returns error",
			firstPagesRequestError: fmt.Errorf("some error before pagination is required"),
			expectedError: fmt.Errorf(
				"unexpected error creating an http request %w",
				fmt.Errorf("some error before pagination is required"),
			),
			numberOfPages: 1,
		},
		{
			name:                   "scan confluence space with multiple pages",
			firstPagesRequestError: nil,
			expectedError:          nil,
			numberOfPages:          3,
			mockPageContent: &ConfluencePageContent{
				Body: struct {
					Storage struct {
						Value string `json:"value"`
					} `json:"storage"`
				}(struct {
					Storage struct {
						Value string
					}
				}{
					Storage: struct{ Value string }{Value: "Page content"},
				}),
				History: struct {
					PreviousVersion struct{ Number int } `json:"previousVersion"`
				}(struct {
					PreviousVersion struct {
						Number int
					}
				}{PreviousVersion: struct{ Number int }{Number: 1}}),
				Links: map[string]string{
					"base":  "https://example.com",
					"webui": "/wiki/page",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockConfluenceClient{
				firstPagesRequestError: tt.firstPagesRequestError,
				numberOfPages:          tt.numberOfPages,
				pageContentResponse:    []*ConfluencePageContent{tt.mockPageContent},
			}

			errorsChan := make(chan error, 1)
			itemsChan := make(chan ISourceItem, 3)

			plugin := Plugin{
				Limit: make(chan struct{}, confluenceMaxRequests),
			}

			confluencePlugin := &ConfluencePlugin{
				Plugin:     plugin,
				client:     mockClient,
				errorsChan: errorsChan,
				itemsChan:  itemsChan,
			}

			space := ConfluenceSpaceResult{Key: "spaceKey"}
			var wg sync.WaitGroup
			wg.Add(1)

			go confluencePlugin.scanConfluenceSpace(&wg, space)

			wg.Wait()

			close(errorsChan)
			close(itemsChan)

			if tt.expectedError != nil {
				actualError := <-errorsChan
				assert.Equal(t, tt.expectedError, actualError)
			} else {
				assert.Empty(t, errorsChan)
				var actualItems []ISourceItem
				for i := 0; i < tt.numberOfPages; i++ {
					actualItem := <-itemsChan
					actualItems = append(actualItems, actualItem)
				}
				sort.Slice(actualItems, func(i, j int) bool {
					return actualItems[i].GetID() < actualItems[j].GetID()
				})
				for i := 0; i < tt.numberOfPages; i++ {
					expectedItem := item{
						Content: ptrToString("Page content"),
						ID:      fmt.Sprintf("confluence-spaceKey-%d", i),
						Source:  "https://example.com/wiki/page",
					}
					assert.Equal(t, &expectedItem, actualItems[i])
				}
			}
		})
	}
}

func TestScanConfluence(t *testing.T) {
	tests := []struct {
		name                    string
		firstSpacesRequestError error
		expectedError           error
		numberOfSpaces          int
		numberOfPages           int
		mockPageContent         *ConfluencePageContent
	}{
		{
			name:                    "getSpaces returns error",
			firstSpacesRequestError: fmt.Errorf("some error before pagination is required"),
			expectedError:           fmt.Errorf("some error before pagination is required"),
			numberOfPages:           1,
		},
		{
			name:                    "scan confluence with multiple spaces and pages",
			firstSpacesRequestError: nil,
			expectedError:           nil,
			numberOfSpaces:          3,
			numberOfPages:           3,
			mockPageContent: &ConfluencePageContent{
				Body: struct {
					Storage struct {
						Value string `json:"value"`
					} `json:"storage"`
				}(struct {
					Storage struct {
						Value string
					}
				}{
					Storage: struct{ Value string }{Value: "Page content"},
				}),
				History: struct {
					PreviousVersion struct{ Number int } `json:"previousVersion"`
				}(struct {
					PreviousVersion struct {
						Number int
					}
				}{PreviousVersion: struct{ Number int }{Number: 1}}),
				Links: map[string]string{
					"base":  "https://example.com",
					"webui": "/wiki/page",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockConfluenceClient{
				firstSpacesRequestError: tt.firstSpacesRequestError,
				numberOfPages:           tt.numberOfPages,
				numberOfSpaces:          tt.numberOfSpaces,
				pageContentResponse:     []*ConfluencePageContent{tt.mockPageContent},
			}

			errorsChan := make(chan error, 1)
			itemsChan := make(chan ISourceItem, 3)

			plugin := Plugin{
				Limit: make(chan struct{}, confluenceMaxRequests),
			}

			confluencePlugin := &ConfluencePlugin{
				Plugin:     plugin,
				client:     mockClient,
				errorsChan: errorsChan,
				itemsChan:  itemsChan,
			}

			wg := &sync.WaitGroup{}

			go confluencePlugin.scanConfluence(wg)

			wg.Wait()

			if tt.expectedError != nil {
				actualError := <-errorsChan
				assert.Equal(t, tt.expectedError, actualError)
			} else {
				assert.Empty(t, errorsChan)
				var actualItems []ISourceItem
				for i := 0; i < tt.numberOfSpaces; i++ {
					for j := 0; j < tt.numberOfPages; j++ {
						actualItem := <-itemsChan
						actualItems = append(actualItems, actualItem)
					}
				}
				sort.Slice(actualItems, func(i, j int) bool {
					splitID := func(id string) (string, string) {
						parts := strings.Split(id, "-")
						return parts[1], parts[2]
					}

					spaceKey1, pageID1 := splitID(actualItems[i].GetID())
					spaceKey2, pageID2 := splitID(actualItems[j].GetID())

					if spaceKey1 != spaceKey2 {
						return spaceKey1 < spaceKey2
					}
					return pageID1 < pageID2
				})
				for i := 0; i < tt.numberOfSpaces; i++ {
					for j := 0; j < tt.numberOfPages; j++ {
						expectedItem := item{
							Content: ptrToString("Page content"),
							ID:      fmt.Sprintf("confluence-%d-%d", i, j),
							Source:  "https://example.com/wiki/page",
						}
						assert.Equal(t, &expectedItem, actualItems[i*tt.numberOfPages+j])
					}
				}
			}
		})
	}
}

func TestInitializeConfluence(t *testing.T) {
	tests := []struct {
		name        string
		urlArg      string
		username    string
		token       string
		expectURL   string
		expectLimit int
		expectWarn  bool
	}{
		{
			name:        "Valid credentials",
			urlArg:      "https://example.com/",
			username:    "user",
			token:       "token",
			expectURL:   "https://example.com",
			expectLimit: confluenceMaxRequests,
			expectWarn:  false,
		},
		{
			name:        "No credentials provided",
			urlArg:      "https://example.com/",
			username:    "",
			token:       "",
			expectURL:   "https://example.com",
			expectLimit: confluenceMaxRequests,
			expectWarn:  true,
		},
		{
			name:        "URL without trailing slash",
			urlArg:      "https://example.com",
			username:    "user",
			token:       "token",
			expectURL:   "https://example.com",
			expectLimit: confluenceMaxRequests,
			expectWarn:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			log.Logger = zerolog.New(&logBuf)

			username = tt.username
			token = tt.token

			p := &ConfluencePlugin{}

			p.initialize(tt.urlArg)

			assert.NotNil(t, p.client)
			client, ok := p.client.(*confluenceClient)
			assert.True(t, ok, "Client should be of type *confluenceClient")

			assert.Equal(t, tt.expectURL, client.baseURL)

			assert.Equal(t, tt.username, client.username)
			assert.Equal(t, tt.token, client.token)

			assert.NotNil(t, p.Limit)
			assert.Equal(t, tt.expectLimit, cap(p.Limit))

			logOutput := logBuf.String()
			if tt.expectWarn {
				assert.Contains(t, logOutput, "confluence credentials were not provided", "Expected warning log missing")
			} else {
				assert.NotContains(t, logOutput, "confluence credentials were not provided", "Unexpected warning log found")
			}
		})
	}
}

func ptrToString(s string) *string {
	return &s
}
