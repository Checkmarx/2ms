package plugins

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
)

func (p *Plugin) RunPlugin() ([]Content, error) {
	contents := []Content{}

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
			pageContent, err := p.getContent(page, space)
			if err != nil {
				return nil, err
			}

			contents = append(contents, *pageContent)
		}
	}

	log.Info().Msg("Confluence plugin completed successfully")
	return contents, nil
}

func (p *Plugin) getTotalSpaces() ([]SpaceResult, error) {
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

func (p *Plugin) getSpaces(start int) (*SpaceResponse, error) {
	url := fmt.Sprintf("%s/rest/api/space?start=%d", p.URL, start)
	body, err := p.httpRequest(http.MethodGet, url)
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	response := &SpaceResponse{}
	jsonErr := json.Unmarshal(body, response)
	if jsonErr != nil {
		return nil, fmt.Errorf("could not unmarshal response %w", err)
	}

	return response, nil
}

func (p *Plugin) getTotalPages(space SpaceResult) (*PageResult, error) {
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

func (p *Plugin) getPages(space SpaceResult, start int) (*PageResult, error) {
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

func (p *Plugin) getContent(page Page, space SpaceResult) (*Content, error) {
	url := p.URL + "/rest/api/content/" + page.ID + "?expand=body.storage,body.view.value,version,history.previousVersion"
	originalUrl := p.URL + "/spaces/" + space.Key + "/pages/" + page.ID
	request, err := p.httpRequest(http.MethodGet, url)

	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	content := &Content{
		Content:     string(request),
		Source:      url,
		OriginalUrl: originalUrl,
	}
	return content, nil
}

func (p *Plugin) httpRequest(method string, url string) ([]byte, error) {
	var err error

	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("unable to send http request %w", err)
	}

	if p.Email == "" && p.Token == "" {
		request.SetBasicAuth(p.Email, p.Token)
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

type SpaceResult struct {
	ID    int               `json:"id"`
	Key   string            `json:"key"`
	Name  string            `json:"Name"`
	Links map[string]string `json:"_links"`
}

type SpaceResponse struct {
	Results []SpaceResult `json:"results"`
	Size    int           `json:"size"`
}

type Page struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
}

type PageResult struct {
	Pages []Page `json:"results"`
}

type PageResponse struct {
	Results PageResult `json:"page"`
}
