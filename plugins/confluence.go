package plugins

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"strconv"
	"strings"
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
	flags.StringP(argConfluence, "", "", "scan confluence url")
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
	items := make([]Item, 0)
	spaces, err := p.getTotalSpaces()
	if err != nil {
		return nil, err
	}

	for _, space := range spaces {
		spacePages, err := p.getTotalPages(space)
		if err != nil {
			return nil, err
		}

		for _, page := range spacePages.Pages {
			pageContent, err := p.getContents(page, space)
			if err != nil {
				return nil, err
			}

			items = append(items, *pageContent...)
		}
	}

	log.Debug().Msg("Confluence plugin completed successfully")
	return &items, nil
}

func (p *ConfluencePlugin) getTotalSpaces() ([]ConfluenceSpaceResult, error) {
	totalSpaces, err := p.getSpaces(0)
	if err != nil {
		return nil, err
	}

	actualSize := totalSpaces.Size

	for actualSize != 0 {
		moreSpaces, err := p.getSpaces(totalSpaces.Size)
		if err != nil {
			return nil, err
		}

		totalSpaces.Results = append(totalSpaces.Results, moreSpaces.Results...)
		totalSpaces.Size += moreSpaces.Size
		actualSize = moreSpaces.Size
	}

	log.Info().Msgf(" Total of %d Spaces detected", len(totalSpaces.Results))

	return totalSpaces.Results, nil
}

func (p *ConfluencePlugin) getSpaces(start int) (*ConfluenceSpaceResponse, error) {
	url := fmt.Sprintf("%s/rest/api/space?start=%d", p.URL, start)
	body, err := p.httpRequest(http.MethodGet, url)
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	response := &ConfluenceSpaceResponse{}
	jsonErr := json.Unmarshal(body, response)
	if jsonErr != nil {
		return nil, fmt.Errorf("could not unmarshal response %w", err)
	}

	return response, nil
}

func (p *ConfluencePlugin) getTotalPages(space ConfluenceSpaceResult) (*ConfluencePageResult, error) {
	totalPages, err := p.getPages(space, 0)

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	actualSize := len(totalPages.Pages)

	for actualSize != 0 {
		morePages, err := p.getPages(space, len(totalPages.Pages))

		if err != nil {
			return nil, fmt.Errorf("unexpected error creating an http request %w", err)
		}

		totalPages.Pages = append(totalPages.Pages, morePages.Pages...)
		actualSize = len(morePages.Pages)
	}

	log.Info().Msgf(" Space - %s have %d pages", space.Name, len(totalPages.Pages))

	return totalPages, nil
}

func (p *ConfluencePlugin) getPages(space ConfluenceSpaceResult, start int) (*ConfluencePageResult, error) {
	url := fmt.Sprintf("%s/rest/api/space/%s/content?start=%d", p.URL, space.Key, start)
	body, err := p.httpRequest(http.MethodGet, url)

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	response := PageResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		return nil, fmt.Errorf("could not unmarshal response %w", err)
	}

	return &response.Results, nil
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
type ConfluencePageLatestVersion struct {
	Body struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Version struct {
		Number int `json:"number"`
	} `json:"version"`
}

type ConfluencePageOldVersion struct {
	Body struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
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
