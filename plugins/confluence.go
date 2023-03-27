package plugins

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const argConfluence = "confluence"
const argConfluenceSpaces = "confluence-spaces"
const argConfluenceUsername = "confluence-username"
const argConfluenceToken = "confluence-token"
const argConfluenceHistory = "history"

type ConfluencePlugin struct {
	Plugin
	URL      string
	Token    string
	Username string
	Spaces   []string
	History  bool
}

func (p *ConfluencePlugin) IsEnabled() bool {
	return p.Enabled
}

func (p *ConfluencePlugin) DefineCommandLineArgs(cmd *cobra.Command) error {
	flags := cmd.Flags()
	flags.StringP(argConfluence, "c", "", "scan confluence url")
	flags.StringP(argConfluenceSpaces, "", "", "confluence spaces")
	flags.StringP(argConfluenceUsername, "", "", "confluence username or email")
	flags.StringP(argConfluenceToken, "", "", "confluence token")
	flags.BoolP(argConfluenceHistory, "", false, "scan pages history")
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
	runHistory, _ := flags.GetBool(argConfluenceHistory)

	p.Token = confluenceToken
	p.Username = confluenceUsername
	p.URL = confluenceUrl
	p.Spaces = strings.Split(confluenceSpaces, ",")
	p.Enabled = true
	p.History = runHistory
	return nil
}

func (p *ConfluencePlugin) GetItems() (*[]Item, error) {
	var wg sync.WaitGroup
	items := make([]Item, 0)

	spaces, err := p.getTotalSpaces()
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}
	for _, space := range spaces {
		limit := make(chan interface{}, 5)

		spacePages, err := p.getTotalPages(space)
		if err != nil {
			log.Error().Msgf(err.Error())
			return nil, err
		}

		page := ConfluencePage{}
		for _, page = range spacePages.Pages {
			go p.threadGetContent(page, space, limit, &wg, &items)
		}
		wg.Wait()
	}

	log.Debug().Msgf("Confluence plugin completed successfully. Total of %d spaces detected", len(spaces))
	return &items, nil
}

func (p *ConfluencePlugin) threadGetContent(page ConfluencePage, space ConfluenceSpaceResult, limit chan interface{}, wg *sync.WaitGroup, items *[]Item) {
	limit <- struct{}{}
	wg.Add(1)
	go func() {
		pageContent, err := p.getContents(page, space)
		if err != nil {
			log.Error().Msgf(err.Error())
			limit <- err
		}
		*items = append(*items, *pageContent...)
		<-limit
		wg.Done()
	}()
}

func (p *ConfluencePlugin) getTotalSpaces() ([]ConfluenceSpaceResult, error) {
	var count int32 = 1
	var mutex sync.Mutex
	var wg sync.WaitGroup

	totalSpaces, err := p.getSpaces(0)
	if err != nil {
		log.Error().Msgf(err.Error())
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
		log.Error().Msgf(err.Error())
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
		log.Error().Msgf(err.Error())
		return ConfluencePageResult{}, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	if len(totalPages.Pages) == 25 {
		for threadCount := 0; threadCount < 4; threadCount++ {
			wg.Add(1)
			go p.threadGetPages(space, &count, &totalPages, &mutex, &wg)
		}
	}
	wg.Wait()
	log.Debug().Msgf(" Space - %s have %d pages", space.Name, len(totalPages.Pages))

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
		log.Error().Msgf(err.Error())
		return ConfluencePageResult{}, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	response := PageResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		return ConfluencePageResult{}, fmt.Errorf("could not unmarshal response %w", err)
	}

	return response.Results, nil
}

func (p *ConfluencePlugin) getContents(page ConfluencePage, space ConfluenceSpaceResult) (*[]Item, error) {
	items := make([]Item, 0)
	actualPage, actualVersion, err := p.getContent(page, space)
	if err != nil {
		return nil, err
	}

	items = append(items, *actualPage)

	// If older versions exist & run history is true
	if actualVersion > 1 && p.History {
		for actualVersion > 1 {
			actualVersion--
			pageVersion, err := p.getContentbyVersion(page, space, actualVersion)
			if err != nil {
				return nil, err
			}

			items = append(items, *pageVersion)
		}
	}
	return &items, nil
}

func (p *ConfluencePlugin) getContent(page ConfluencePage, space ConfluenceSpaceResult) (*Item, int, error) {
	url := p.URL + "/rest/api/content/" + page.ID + "?expand=body.storage,version"
	originalUrl := p.URL + "/spaces/" + space.Key + "/pages/" + page.ID

	request, err := p.httpRequest(http.MethodGet, url)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, 1, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	latest := ConfluencePageLatestVersion{}
	jsonErr := json.Unmarshal(request, &latest)
	if jsonErr != nil {
		log.Error().Msg("Error on getting latest version on Confluence Page")
	}

	content := &Item{
		Content: latest.Body.Storage.Value,
		Source:  url,
		ID:      originalUrl,
	}
	return content, latest.Version.Number, nil
}

func (p *ConfluencePlugin) getContentbyVersion(page ConfluencePage, space ConfluenceSpaceResult, version int) (*Item, error) {
	url := p.URL + "/rest/api/content/" + page.ID + "?status=historical&version=" + strconv.Itoa(version) + "&expand=body.storage"

	request, err := p.httpRequest(http.MethodGet, url)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}
	pageVersion := ConfluencePageOldVersion{}
	jsonErr := json.Unmarshal(request, &pageVersion)
	if jsonErr != nil {
		log.Error().Msg("Error on getting latest version on Confluence Page")
	}

	content := &Item{
		Content: pageVersion.Body.Storage.Value,
		Source:  url,
		ID:      url,
	}
	return content, nil
}

func (p *ConfluencePlugin) httpRequest(method string, url string) ([]byte, error) {
	var err error
	//log.Log().Msg(url)
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	if p.Username != "" && p.Token != "" {
		request.SetBasicAuth(p.Username, p.Token)
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, fmt.Errorf("unable to send http request %w", err)
	}

	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("error calling http url \"%v\". status code: %v", url, response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Error().Msgf(err.Error())
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

type ConfluencePageLatestVersion struct {
	Body    ConfluencePageBody    `json:"body"`
	Version ConfluencePageVersion `json:"version"`
}

type ConfluencePageOldVersion struct {
	Body ConfluencePageBody `json:"body"`
}

type ConfluencePageBody struct {
	Storage ConfluencePageBodyStorage `json:"storage"`
}

type ConfluencePageBodyStorage struct {
	Value string `json:"value"`
}

type ConfluencePageVersion struct {
	Number int `json:"number"`
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
