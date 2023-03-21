package plugins

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

const argConfluence = "confluence"
const argConfluenceSpaces = "confluence-spaces"
const argConfluenceUsername = "confluence-username"
const argConfluenceToken = "confluence-token"

type ConfluencePlugin struct {
	Plugin
	URL      string
	Token    string
	Username string
	Spaces   []string
}

func (p *ConfluencePlugin) IsEnabled() bool {
	return p.Enabled
}

func (p *ConfluencePlugin) DefineCommandLineArgs(cmd *cobra.Command) error {
	flags := cmd.Flags()
	flags.StringP(argConfluence, "", "", "scan confluence url")
	flags.StringP(argConfluenceSpaces, "", "", "confluence spaces")
	flags.StringP(argConfluenceUsername, "", "", "confluence username or email")
	flags.StringP(argConfluenceToken, "", "", "confluence token")
	return nil
}

func (p *ConfluencePlugin) Initialize(cmd *cobra.Command) error {
	flags := cmd.Flags()
	confluenceUrl, _ := flags.GetString(argConfluence)
	if confluenceUrl == "" {
		return nil
	}

	confluenceUrl = strings.TrimRight(confluenceUrl, "/")

	confluenceSpaces, _ := flags.GetString(argConfluenceSpaces)
	confluenceUsername, _ := flags.GetString(argConfluenceUsername)
	confluenceToken, _ := flags.GetString(argConfluenceToken)

	p.Token = confluenceToken
	p.Username = confluenceUsername
	p.URL = confluenceUrl
	p.Spaces = strings.Split(confluenceSpaces, ",")
	p.Enabled = true
	return nil
}

func (p *ConfluencePlugin) GetItems() (*[]Item, error) {
	var wg sync.WaitGroup

	items := make([]Item, 0)
	spaces, err := p.getTotalSpaces()
	if err != nil {
		return nil, err
	}

	for _, space := range spaces {
		limit := make(chan interface{}, 5)

		spacePages, err := p.getTotalPages(space)
		if err != nil {
			return nil, err
		}

		for _, page := range spacePages.Pages {
			limit <- struct{}{}
			wg.Add(1)
			go func() {
				pageContent, err := p.getContent(page, space)
				if err != nil {
					limit <- err
				}

				items = append(items, *pageContent)

				<-limit
				wg.Done()

			}()
			wg.Wait()

		}
	}

	log.Debug().Msg("Confluence plugin completed successfully")
	return &items, nil
}

func (p *ConfluencePlugin) getTotalSpaces() ([]ConfluenceSpaceResult, error) {
	var count int32 = 1
	var mutex sync.Mutex
	var wg sync.WaitGroup

	totalSpaces, err := p.getSpaces(0)
	if err != nil {
		return nil, err
	}

	if totalSpaces.Size == 25 {
		for threadCount := 0; threadCount < 4; threadCount++ {
			wg.Add(1)
			go p.threadGetSpaces(&count, &totalSpaces, &mutex, &wg)
		}
	}
	wg.Wait()
	log.Info().Msgf(" Total of %d Spaces detected", len(totalSpaces.Results))

	return totalSpaces.Results, nil
}

func (p *ConfluencePlugin) threadGetSpaces(count *int32, totalSpaces *ConfluenceSpaceResponse, mutex *sync.Mutex, wg *sync.WaitGroup) {
	var moreSpaces []ConfluenceSpaceResult
	for {
		atomic.AddInt32(count, 1)
		lastSpaces, _ := p.getSpaces(int(*count-1) * 25)
		moreSpaces = append(moreSpaces, lastSpaces.Results...)

		if lastSpaces.Size == 0 {
			mutex.Lock()
			totalSpaces.Results = append(totalSpaces.Results, moreSpaces...)
			mutex.Unlock()
			wg.Done()
			break
		}
	}
}

func (p *ConfluencePlugin) getSpaces(start int) (ConfluenceSpaceResponse, error) {
	url := fmt.Sprintf("%s/rest/api/space?start=%d", p.URL, start)
	body, err := p.httpRequest(http.MethodGet, url)
	if err != nil {
		return ConfluenceSpaceResponse{}, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	response := ConfluenceSpaceResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		return ConfluenceSpaceResponse{}, fmt.Errorf("could not unmarshal response %w", err)
	}

	return response, nil
}

func (p *ConfluencePlugin) getTotalPages(space ConfluenceSpaceResult) (ConfluencePageResult, error) {
	var count int32 = 1
	var mutex sync.Mutex
	var wg sync.WaitGroup
	totalPages, err := p.getPages(space, 0)
	if err != nil {
		return ConfluencePageResult{}, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	if len(totalPages.Pages) == 25 {
		for threadCount := 0; threadCount < 20; threadCount++ {
			wg.Add(1)
			go p.threadGetPages(space, &count, &totalPages, &mutex, &wg)
		}
	}
	wg.Wait()
	log.Info().Msgf(" Space - %s have %d pages", space.Name, len(totalPages.Pages))

	return totalPages, nil
}

func (p *ConfluencePlugin) threadGetPages(space ConfluenceSpaceResult, count *int32, totalPages *ConfluencePageResult, mutex *sync.Mutex, wg *sync.WaitGroup) {
	var morePages ConfluencePageResult
	for {
		atomic.AddInt32(count, 1)
		lastPages, _ := p.getPages(space, int(*count-1)*25)
		morePages.Pages = append(morePages.Pages, lastPages.Pages...)

		if len(lastPages.Pages) == 0 {
			mutex.Lock()
			totalPages.Pages = append(totalPages.Pages, morePages.Pages...)
			mutex.Unlock()
			wg.Done()
			break
		}
	}
}

func (p *ConfluencePlugin) getPages(space ConfluenceSpaceResult, start int) (ConfluencePageResult, error) {
	url := fmt.Sprintf("%s/rest/api/space/%s/content?start=%d", p.URL, space.Key, start)
	body, err := p.httpRequest(http.MethodGet, url)

	if err != nil {
		return ConfluencePageResult{}, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	response := PageResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		return ConfluencePageResult{}, fmt.Errorf("could not unmarshal response %w", err)
	}

	return response.Results, nil
}

func (p *ConfluencePlugin) getContent(page ConfluencePage, space ConfluenceSpaceResult) (*Item, error) {
	url := p.URL + "/rest/api/content/" + page.ID + "?expand=body.storage,body.view.value,version,history.previousVersion"
	originalUrl := p.URL + "/spaces/" + space.Key + "/pages/" + page.ID
	request, err := p.httpRequest(http.MethodGet, url)

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	content := &Item{
		Content: string(request),
		Source:  url,
		ID:      originalUrl,
	}
	return content, nil
}

func (p *ConfluencePlugin) httpRequest(method string, url string) ([]byte, error) {
	var err error

	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	if p.Username != "" && p.Token != "" {
		request.SetBasicAuth(p.Username, p.Token)
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("unable to send http request %w", err)
	}

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("error calling http url \"%v\". status code: %v", url, response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unexpected error reading http response body %w", err)
	}

	return body, nil
}

type ConfluenceSpaceResult struct {
	ID    int               `json:"id"`
	Key   string            `json:"key"`
	Name  string            `json:"Name"`
	Links map[string]string `json:"_links"`
}

type ConfluenceSpaceResponse struct {
	Results []ConfluenceSpaceResult `json:"results"`
	Size    int                     `json:"size"`
}

type ConfluencePage struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
}

type ConfluencePageResult struct {
	Pages []ConfluencePage `json:"results"`
}

type PageResponse struct {
	Results ConfluencePageResult `json:"page"`
}
