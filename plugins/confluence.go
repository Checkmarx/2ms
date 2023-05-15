package plugins

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/checkmarx/2ms/lib"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	argUrl                  = "url"
	argSpaces               = "spaces"
	argUsername             = "username"
	argToken                = "token"
	argHistory              = "history"
	confluenceDefaultWindow = 25
	confluenceMaxRequests   = 500
)

type ConfluencePlugin struct {
	Plugin
	URL      string
	Token    string
	Username string
	Spaces   []string
	History  bool
}

func (p *ConfluencePlugin) GetName() string {
	return "confluence"
}

func (p *ConfluencePlugin) GetCredentials() (string, string) {
	return p.Username, p.Token
}

func (p *ConfluencePlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	var confluenceCmd = &cobra.Command{
		Use:   fmt.Sprintf("%s --%s URL", p.GetName(), argUrl),
		Short: "Scan Confluence server",
		Long:  "Scan Confluence server for sensitive information",
	}

	flags := confluenceCmd.Flags()
	flags.String(argUrl, "", "Confluence server URL (example: https://company.atlassian.net/wiki) [required]")
	flags.StringArray(argSpaces, []string{}, "Confluence spaces: The names or IDs of the spaces to scan")
	flags.String(argUsername, "", "Confluence user name or email for authentication")
	flags.String(argToken, "", "The Confluence API token for authentication")
	flags.Bool(argHistory, false, "Scan pages history")
	err := confluenceCmd.MarkFlagRequired(argUrl)
	if err != nil {
		return nil, fmt.Errorf("error while marking '%s' flag as required: %w", argUrl, err)
	}

	confluenceCmd.Run = func(cmd *cobra.Command, args []string) {
		err := p.initialize(cmd)
		if err != nil {
			channels.Errors <- fmt.Errorf("error while initializing confluence plugin: %w", err)
			return
		}

		p.getItems(channels.Items, channels.Errors, channels.WaitGroup)
	}

	return confluenceCmd, nil
}

func (p *ConfluencePlugin) initialize(cmd *cobra.Command) error {
	flags := cmd.Flags()
	url, err := flags.GetString(argUrl)
	if err != nil {
		return fmt.Errorf("error while getting '%s' flag value: %w", argUrl, err)
	}

	url = strings.TrimRight(url, "/")

	spaces, _ := flags.GetStringArray(argSpaces)
	username, _ := flags.GetString(argUsername)
	token, _ := flags.GetString(argToken)
	runHistory, _ := flags.GetBool(argHistory)

	if username == "" || token == "" {
		log.Warn().Msg("confluence credentials were not provided. The scan will be made anonymously only for the public pages")
	}

	p.Token = token
	p.Username = username
	p.URL = url
	p.Spaces = spaces
	p.History = runHistory
	p.Limit = make(chan struct{}, confluenceMaxRequests)
	return nil
}

func (p *ConfluencePlugin) getItems(items chan Item, errs chan error, wg *sync.WaitGroup) {
	p.getSpacesItems(items, errs, wg)
}

func (p *ConfluencePlugin) getSpacesItems(items chan Item, errs chan error, wg *sync.WaitGroup) {
	spaces, err := p.getSpaces()
	if err != nil {
		errs <- err
	}

	for _, space := range spaces {
		go p.getSpaceItems(items, errs, wg, space)
		wg.Add(1)
	}
}

func (p *ConfluencePlugin) getSpaceItems(items chan Item, errs chan error, wg *sync.WaitGroup, space ConfluenceSpaceResult) {
	defer wg.Done()

	pages, err := p.getPages(space)
	if err != nil {
		errs <- err
		return
	}

	for _, page := range pages.Pages {
		wg.Add(1)
		p.Limit <- struct{}{}
		go func(page ConfluencePage) {
			p.getPageItems(items, errs, wg, page, space)
			<-p.Limit
		}(page)
	}
}

func (p *ConfluencePlugin) getSpaces() ([]ConfluenceSpaceResult, error) {
	totalSpaces, err := p.getSpacesRequest(0)
	if err != nil {
		return nil, err
	}

	actualSize := totalSpaces.Size

	for actualSize == confluenceDefaultWindow {
		moreSpaces, err := p.getSpacesRequest(totalSpaces.Size)
		if err != nil {
			return nil, err
		}

		totalSpaces.Results = append(totalSpaces.Results, moreSpaces.Results...)
		totalSpaces.Size += moreSpaces.Size
		actualSize = moreSpaces.Size
	}

	if len(p.Spaces) == 0 {
		log.Info().Msgf(" Total of all %d Spaces detected", len(totalSpaces.Results))
		return totalSpaces.Results, nil
	}

	filteredSpaces := make([]ConfluenceSpaceResult, 0)
	if len(p.Spaces) > 0 {
		for _, space := range totalSpaces.Results {
			for _, spaceToScan := range p.Spaces {
				if space.Key == spaceToScan || space.Name == spaceToScan || fmt.Sprintf("%d", space.ID) == spaceToScan {
					filteredSpaces = append(filteredSpaces, space)
				}
			}
		}
	}

	log.Info().Msgf(" Total of filtered %d Spaces detected", len(filteredSpaces))
	return filteredSpaces, nil
}

func (p *ConfluencePlugin) getSpacesRequest(start int) (*ConfluenceSpaceResponse, error) {
	url := fmt.Sprintf("%s/rest/api/space?start=%d", p.URL, start)
	body, err := lib.HttpRequest(http.MethodGet, url, p)
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

func (p *ConfluencePlugin) getPages(space ConfluenceSpaceResult) (*ConfluencePageResult, error) {
	totalPages, err := p.getPagesRequest(space, 0)

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	actualSize := len(totalPages.Pages)

	for actualSize == confluenceDefaultWindow {
		morePages, err := p.getPagesRequest(space, len(totalPages.Pages))

		if err != nil {
			return nil, fmt.Errorf("unexpected error creating an http request %w", err)
		}

		totalPages.Pages = append(totalPages.Pages, morePages.Pages...)
		actualSize = len(morePages.Pages)
	}

	log.Info().Msgf(" Space - %s have %d pages", space.Name, len(totalPages.Pages))

	return totalPages, nil
}

func (p *ConfluencePlugin) getPagesRequest(space ConfluenceSpaceResult, start int) (*ConfluencePageResult, error) {
	url := fmt.Sprintf("%s/rest/api/space/%s/content?start=%d", p.URL, space.Key, start)
	body, err := lib.HttpRequest(http.MethodGet, url, p)

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	response := ConfluencePageResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		return nil, fmt.Errorf("could not unmarshal response %w", err)
	}

	return &response.Results, nil
}

func (p *ConfluencePlugin) getPageItems(items chan Item, errs chan error, wg *sync.WaitGroup, page ConfluencePage, space ConfluenceSpaceResult) {
	defer wg.Done()

	actualPage, previousVersion, err := p.getItem(page, space, 0)
	if err != nil {
		errs <- err
		return
	}
	items <- *actualPage

	// If older versions exist & run history is true
	for previousVersion > 0 && p.History {
		actualPage, previousVersion, err = p.getItem(page, space, previousVersion)
		if err != nil {
			errs <- err
			return
		}
		items <- *actualPage
	}
}

func (p *ConfluencePlugin) getItem(page ConfluencePage, space ConfluenceSpaceResult, version int) (*Item, int, error) {
	var url string
	var originalUrl string

	// If no version given get the latest, else get the specified version
	if version == 0 {
		url = fmt.Sprintf("%s/rest/api/content/%s?expand=body.storage.value,version,history.previousVersion", p.URL, page.ID)
		originalUrl = fmt.Sprintf("%s/spaces/%s/pages/%s", p.URL, space.Key, page.ID)

	} else {
		url = fmt.Sprintf("%s/rest/api/content/%s?status=historical&version=%d&expand=body.storage.value,version,history.previousVersion", p.URL, page.ID, version)
		originalUrl = fmt.Sprintf("%s/pages/viewpage.action?pageid=%spageVersion=%d", p.URL, page.ID, version)
	}

	request, err := lib.HttpRequest(http.MethodGet, url, p)
	if err != nil {
		return nil, 0, fmt.Errorf("unexpected error creating an http request %w", err)
	}
	pageContent := ConfluencePageContent{}
	jsonErr := json.Unmarshal(request, &pageContent)
	if jsonErr != nil {
		return nil, 0, jsonErr
	}

	content := &Item{
		Content: pageContent.Body.Storage.Value,
		Source:  url,
		ID:      originalUrl,
	}
	return content, pageContent.History.PreviousVersion.Number, nil
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

type ConfluencePageContent struct {
	Body struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	History struct {
		PreviousVersion struct {
			Number int
		} `json:"previousVersion"`
	} `json:"history"`
	Version struct {
		Number int `json:"number"`
	} `json:"version"`
}

type ConfluencePage struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
}

type ConfluencePageResult struct {
	Pages []ConfluencePage `json:"results"`
}

type ConfluencePageResponse struct {
	Results ConfluencePageResult `json:"page"`
}
