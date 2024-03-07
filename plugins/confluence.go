package plugins

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/checkmarx/2ms/lib/utils"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"net/url"
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

var (
	username string
	token    string
)

type ConfluencePlugin struct {
	Plugin
	Spaces  []string
	History bool
	client  IConfluenceClient
}

func (p *ConfluencePlugin) GetName() string {
	return "confluence"
}

func isValidURL(cmd *cobra.Command, args []string) error {
	urlStr := args[0]
	parsedURL, err := url.Parse(urlStr)
	if err != nil && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid URL format")
	}
	return nil
}

func (p *ConfluencePlugin) DefineCommand(items chan Item, errors chan error) (*cobra.Command, error) {
	var confluenceCmd = &cobra.Command{
		Use:     fmt.Sprintf("%s <URL>", p.GetName()),
		Short:   "Scan Confluence server",
		Long:    "Scan Confluence server for sensitive information",
		Example: fmt.Sprintf("  2ms %s https://checkmarx.atlassian.net/wiki", p.GetName()),
		Args:    cobra.MatchAll(cobra.ExactArgs(1), isValidURL),
		Run: func(cmd *cobra.Command, args []string) {
			err := p.initialize(args[0])
			if err != nil {
				errors <- fmt.Errorf("error while initializing confluence plugin: %w", err)
			}
			wg := &sync.WaitGroup{}
			p.scanConfluence(items, errors, wg)
			wg.Wait()
			close(items)
		},
	}

	flags := confluenceCmd.Flags()
	flags.StringSliceVar(&p.Spaces, argSpaces, []string{}, "Confluence spaces: The names or IDs of the spaces to scan")
	flags.StringVar(&username, argUsername, "", "Confluence user name or email for authentication")
	flags.StringVar(&token, argToken, "", "The Confluence API token for authentication")
	flags.BoolVar(&p.History, argHistory, false, "Scan pages history")

	return confluenceCmd, nil
}

func (p *ConfluencePlugin) initialize(urlArg string) error {

	url := strings.TrimRight(urlArg, "/")

	if username == "" || token == "" {
		log.Warn().Msg("confluence credentials were not provided. The scan will be made anonymously only for the public pages")
	}
	p.client = newConfluenceClient(url, token, username)

	p.Limit = make(chan struct{}, confluenceMaxRequests)
	return nil
}

func (p *ConfluencePlugin) scanConfluence(items chan Item, errs chan error, wg *sync.WaitGroup) {
	spaces, err := p.getSpaces()
	if err != nil {
		errs <- err
	}

	for _, space := range spaces {
		wg.Add(1)
		go p.scanConfluenceSpace(items, errs, wg, space)
	}
}

func (p *ConfluencePlugin) scanConfluenceSpace(items chan Item, errs chan error, wg *sync.WaitGroup, space ConfluenceSpaceResult) {
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
			p.pageVersionsToItem(items, errs, wg, page, space)
			<-p.Limit
		}(page)
	}
}

func (p *ConfluencePlugin) getSpaces() ([]ConfluenceSpaceResult, error) {
	totalSpaces, err := p.client.getSpacesRequest(0)
	if err != nil {
		return nil, err
	}

	actualSize := totalSpaces.Size

	for actualSize == confluenceDefaultWindow {
		moreSpaces, err := p.client.getSpacesRequest(totalSpaces.Size)
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

func (p *ConfluencePlugin) getPages(space ConfluenceSpaceResult) (*ConfluencePageResult, error) {
	totalPages, err := p.client.getPagesRequest(space, 0)

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	actualSize := len(totalPages.Pages)

	for actualSize == confluenceDefaultWindow {
		morePages, err := p.client.getPagesRequest(space, len(totalPages.Pages))

		if err != nil {
			return nil, fmt.Errorf("unexpected error creating an http request %w", err)
		}

		totalPages.Pages = append(totalPages.Pages, morePages.Pages...)
		actualSize = len(morePages.Pages)
	}

	log.Info().Msgf(" Space - %s have %d pages", space.Name, len(totalPages.Pages))

	return totalPages, nil
}

func (p *ConfluencePlugin) pageVersionsToItem(items chan Item, errs chan error, wg *sync.WaitGroup, page ConfluencePage, space ConfluenceSpaceResult) {
	defer wg.Done()

	actualPage, previousVersion, err := p.convertPageToItem(page, space, 0)
	if err != nil {
		errs <- err
		return
	}
	items <- *actualPage

	for previousVersion > 0 && p.History {
		actualPage, previousVersion, err = p.convertPageToItem(page, space, previousVersion)
		if err != nil {
			errs <- err
			return
		}
		items <- *actualPage
	}
}

func (p *ConfluencePlugin) convertPageToItem(page ConfluencePage, space ConfluenceSpaceResult, version int) (*Item, int, error) {
	pageContent, err := p.client.getPageContentRequest(page, version)
	if err != nil {
		return nil, 0, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	item := &Item{
		Content: pageContent.Body.Storage.Value,
		ID:      fmt.Sprintf("%s-%s-%s", p.GetName(), space.Key, page.ID),
		Source:  pageContent.Links["base"] + pageContent.Links["webui"],
	}
	return item, pageContent.History.PreviousVersion.Number, nil
}

/*
 * Confluence client
 */

type IConfluenceClient interface {
	getSpacesRequest(start int) (*ConfluenceSpaceResponse, error)
	getPagesRequest(space ConfluenceSpaceResult, start int) (*ConfluencePageResult, error)
	getPageContentRequest(page ConfluencePage, version int) (*ConfluencePageContent, error)
}

type confluenceClient struct {
	baseURL  string
	token    string
	username string
}

func newConfluenceClient(baseURL, token, username string) IConfluenceClient {
	return &confluenceClient{
		baseURL:  baseURL,
		token:    token,
		username: username,
	}
}

func (c *confluenceClient) GetCredentials() (string, string) {
	return c.username, c.token
}

func (c *confluenceClient) GetAuthorizationHeader() string {
	if c.username == "" || c.token == "" {
		return ""
	}
	return utils.CreateBasicAuthCredentials(c)
}

func (c *confluenceClient) getSpacesRequest(start int) (*ConfluenceSpaceResponse, error) {
	url := fmt.Sprintf("%s/rest/api/space?start=%d", c.baseURL, start)
	body, _, err := utils.HttpRequest(http.MethodGet, url, c, utils.RetrySettings{})
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

func (c *confluenceClient) getPagesRequest(space ConfluenceSpaceResult, start int) (*ConfluencePageResult, error) {
	url := fmt.Sprintf("%s/rest/api/space/%s/content?start=%d", c.baseURL, space.Key, start)
	body, _, err := utils.HttpRequest(http.MethodGet, url, c, utils.RetrySettings{})

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

func (c *confluenceClient) getPageContentRequest(page ConfluencePage, version int) (*ConfluencePageContent, error) {
	var url string

	// If no version given get the latest, else get the specified version
	if version == 0 {
		url = fmt.Sprintf("%s/rest/api/content/%s?expand=body.storage,version,history.previousVersion", c.baseURL, page.ID)

	} else {
		url = fmt.Sprintf("%s/rest/api/content/%s?status=historical&version=%d&expand=body.storage,version,history.previousVersion", c.baseURL, page.ID, version)
	}

	request, _, err := utils.HttpRequest(http.MethodGet, url, c, utils.RetrySettings{MaxRetries: 3, ErrorCodes: []int{500}})
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}
	pageContent := ConfluencePageContent{}
	jsonErr := json.Unmarshal(request, &pageContent)
	if jsonErr != nil {
		return nil, jsonErr
	}

	return &pageContent, nil
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
	Links map[string]string `json:"_links"`
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
