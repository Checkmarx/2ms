package plugins

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"strconv"
	"sync"
	"testing"
)

type mockConfluenceClient struct {
	spaceResponse            *ConfluenceSpaceResponse
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
		spaces = append(spaces, ConfluenceSpaceResult{ID: i})
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
			expectedError:          fmt.Errorf("unexpected error creating an http request %w", fmt.Errorf("some error before pagination is required")),
		},
		{
			name:                    "error while getting pages after pagination is required",
			numberOfPages:           confluenceDefaultWindow + 2,
			secondPagesRequestError: fmt.Errorf("some error after pagination required"),
			expectedError:           fmt.Errorf("unexpected error creating an http request %w", fmt.Errorf("some error after pagination required")),
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mockConfluenceClient{
				numberOfSpaces:           tt.numberOfSpaces,
				firstSpacesRequestError:  tt.firstSpacesRequestError,
				secondSpacesRequestError: tt.secondSpacesRequestError,
			}
			plugin := &ConfluencePlugin{client: &mockClient}
			result, err := plugin.getSpaces()
			assert.Equal(t, tt.expectedError, err)
			if tt.expectedError == nil {
				var expectedResult []ConfluenceSpaceResult
				for i := 0; i < tt.numberOfSpaces; i++ {
					expectedResult = append(expectedResult, ConfluenceSpaceResult{ID: i})
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

func ptrToString(s string) *string {
	return &s
}

func countElementsInChannel(ch chan int) int {
	count := 0
	for range ch {
		count++
	}
	return count
}
