package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/checkmarx/2ms/lib"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/time/rate"
)

const (
	paligoInstanceFlag = "instance"
	paligoUsernameFlag = "username"
	paligoTokenFlag    = "token"
	paligoFolderFlag   = "folder"
)

var (
	paligoInstanceArg string
	paligoFolderArg   int
)

type PaligoPlugin struct {
	Plugin
	Channels

	username string
	token    string

	paligoApi *PaligoClient
}

func (p *PaligoPlugin) GetCredentials() (string, string) {
	return p.username, p.token
}

func (p *PaligoPlugin) GetName() string {
	return "paligo"
}

func (p *PaligoPlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	p.Channels = channels

	command := &cobra.Command{
		Use: fmt.Sprintf("%s --%s %s --%s %s --%s %s",
			p.GetName(),
			paligoInstanceFlag, strings.ToUpper(paligoInstanceFlag),
			paligoUsernameFlag, strings.ToUpper(paligoUsernameFlag),
			paligoTokenFlag, strings.ToUpper(paligoTokenFlag)),
		Short: "Scan Paligo instance",
		Long:  "Scan Paligo instance for sensitive information.",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Paligo plugin started")
			p.getItems()
		},
	}

	command.Flags().StringVar(&paligoInstanceArg, paligoInstanceFlag, "", "Paligo instance name [required]")
	err := command.MarkFlagRequired(paligoInstanceFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", paligoInstanceFlag, err)
	}
	command.Flags().StringVar(&p.username, paligoUsernameFlag, "", "Paligo username [required]")
	err = command.MarkFlagRequired(paligoUsernameFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", paligoUsernameFlag, err)
	}
	command.Flags().StringVar(&p.token, paligoTokenFlag, "", "Paligo token [required]")
	err = command.MarkFlagRequired(paligoTokenFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", paligoTokenFlag, err)
	}
	command.Flags().IntVar(&paligoFolderArg, paligoFolderFlag, 0, "Paligo folder ID")

	return command, nil
}

func (p *PaligoPlugin) getItems() {
	p.paligoApi = newPaligoApi(paligoInstanceArg, p.username, p.token)

	foldersToProcess, err := p.getFirstProcessingFolders()
	if err != nil {
		p.Channels.Errors <- err
		return
	}

	itemsChan := p.processFolders(foldersToProcess)

	p.WaitGroup.Add(1)
	go func() {
		defer p.WaitGroup.Done()
		for item := range itemsChan {
			p.handleComponent(item)
		}
	}()
}

func (p *PaligoPlugin) getFirstProcessingFolders() ([]PaligoItem, error) {
	foldersToProcess := []PaligoItem{}

	if paligoFolderArg != 0 {
		foldersToProcess = append(foldersToProcess, PaligoItem{ID: paligoFolderArg, Name: "ID" + fmt.Sprint(paligoFolderArg)})
	} else {
		folders, err := p.paligoApi.listFolders()
		if err != nil {
			log.Error().Err(err).Msg("error while getting root folders")
			return nil, fmt.Errorf("error while getting root folders: %w", err)
		}
		for _, folder := range *folders {
			foldersToProcess = append(foldersToProcess, folder.PaligoItem)
		}
	}
	return foldersToProcess, nil
}

func (p *PaligoPlugin) processFolders(foldersToProcess []PaligoItem) chan PaligoItem {

	itemsChan := make(chan PaligoItem)

	p.WaitGroup.Add(1)
	go func() {
		defer p.WaitGroup.Done()

		for len(foldersToProcess) > 0 {
			folder := foldersToProcess[0]
			foldersToProcess = foldersToProcess[1:]

			log.Info().Msgf("Getting folder %s", folder.Name)
			folderInfo, err := p.paligoApi.showFolder(folder.ID)
			if err != nil {
				log.Error().Err(err).Msgf("error while getting %s '%s'", folder.Type, folder.Name)
				p.Channels.Errors <- err
				continue
			}

			for _, child := range folderInfo.Children {
				if child.Type == "component" {
					itemsChan <- child
				} else if child.Type == "folder" {
					foldersToProcess = append(foldersToProcess, child)
				}
			}
		}
		close(itemsChan)
	}()

	return itemsChan
}

func (p *PaligoPlugin) handleComponent(item PaligoItem) {

	log.Info().Msgf("Getting component %s", item.Name)
	document, err := p.paligoApi.showDocument(item.ID)
	if err != nil {
		log.Error().Err(err).Msgf("error while getting document '%s'", item.Name)
		p.Channels.Errors <- fmt.Errorf("error while getting document '%s': %w", item.Name, err)
		return
	}

	p.Items <- Item{
		Content: document.Content,
		Source:  item.Name,
		ID:      fmt.Sprint(item.ID),
	}
}

/**
 * Paligo API
 */

// https://paligo.net/docs/apidocs/en/index-en.html#UUID-a5b548af-9a37-d305-f5a8-11142d86fe20
const (
	PALIGO_RATE_LIMIT_CHECK_INTERVAL = 5 * time.Second
	PALIGO_DOCUMENT_SHOW_LIMIT       = 50
	PALIGO_FOLDER_SHOW_LIMIT         = 50
)

func rateLimitPerSecond(rateLimit int) rate.Limit {
	return rate.Every(time.Minute / time.Duration(rateLimit))
}

type PaligoItem struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Type string `json:"type"`
}

type Folder struct {
	PaligoItem
	Children []PaligoItem `json:"children"`
}

type EmptyFolder struct {
	PaligoItem
	Children string `json:"children"`
}

type Component struct {
	PaligoItem
	Subtype          string        `json:"subtype"`
	Creator          int           `json:"creator"`
	Owner            int           `json:"owner"`
	Author           int           `json:"author"`
	CreatedAt        int           `json:"created_at"`
	ModifiedAt       int           `json:"modified_at"`
	Checkout         bool          `json:"checkout"`
	CheckoutUser     string        `json:"checkout_user"`
	ParentResource   int           `json:"parent_resource"`
	Taxonomies       []interface{} `json:"taxonomies"`
	ReleaseStatus    string        `json:"release_status"`
	Content          string        `json:"content"`
	Languages        []string      `json:"languages"`
	External         []interface{} `json:"external"`
	CustomAttributes []interface{} `json:"custom_attributes"`
}

type ListFoldersResponse struct {
	Page       int           `json:"page"`
	NextPage   string        `json:"next_page"`
	TotalPages int           `json:"total_pages"`
	Folders    []EmptyFolder `json:"folders"`
}

type Document struct {
	PaligoItem
	Content   string   `json:"content"`
	Languages []string `json:"languages"`
}

type PaligoClient struct {
	Instance string
	Username string
	Token    string

	foldersLimiter   *rate.Limiter
	documentsLimiter *rate.Limiter
}

func reserveRateLimit(response *http.Response, lim *rate.Limiter, err error) error {
	if response.StatusCode != 429 {
		return err
	}

	rateLimit := response.Header.Get("Retry-After")
	if rateLimit == "" {
		return fmt.Errorf("Retry-After header not found")
	}
	seconds, err := strconv.Atoi(rateLimit)
	if err != nil {
		return err
	}
	log.Warn().Msgf("Rate limit exceeded, need to wait for %d seconds", seconds)
	lim.SetBurst(1)
	// We are not waiting for the exact time, because sometimes we get 429 even for fair use,
	// and sometimes it is released earlier than the specified time
	time.Sleep(PALIGO_RATE_LIMIT_CHECK_INTERVAL)
	return nil
}

func (p *PaligoClient) GetCredentials() (string, string) {
	return p.Username, p.Token
}

// TODO: make a PaligoClient that accept URL and do the job
func (p *PaligoClient) listFolders() (*[]EmptyFolder, error) {
	if err := p.foldersLimiter.Wait(context.TODO()); err != nil {
		log.Error().Msgf("Error waiting for rate limiter: %s", err)
	}

	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/folders", p.Instance)

	body, response, err := lib.HttpRequest("GET", url, p)
	if err != nil {
		if err := reserveRateLimit(response, p.foldersLimiter, err); err != nil {
			return nil, err
		}
		return p.listFolders()
	}

	var folders *ListFoldersResponse
	err = json.Unmarshal(body, &folders)

	return &folders.Folders, err
}

func (p *PaligoClient) showFolder(folderId int) (*Folder, error) {
	if err := p.foldersLimiter.Wait(context.TODO()); err != nil {
		log.Error().Msgf("Error waiting for rate limiter: %s", err)
	}

	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/folders/%d", p.Instance, folderId)

	body, response, err := lib.HttpRequest("GET", url, p)
	if err != nil {
		if err := reserveRateLimit(response, p.foldersLimiter, err); err != nil {
			return nil, err
		}
		return p.showFolder(folderId)
	}

	folder := &Folder{}
	err = json.Unmarshal(body, folder)

	return folder, err
}

func (p *PaligoClient) showDocument(documentId int) (*Document, error) {
	if err := p.documentsLimiter.Wait(context.TODO()); err != nil {
		log.Error().Msgf("Error waiting for rate limiter: %s", err)
	}

	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/documents/%d", p.Instance, documentId)

	body, response, err := lib.HttpRequest("GET", url, p)
	if err != nil {
		if err := reserveRateLimit(response, p.documentsLimiter, err); err != nil {
			return nil, err
		}
		return p.showDocument(documentId)
	}

	document := &Document{}
	err = json.Unmarshal(body, document)

	return document, err
}

func newPaligoApi(instance string, username string, token string) *PaligoClient {
	return &PaligoClient{
		Instance: instance,
		Username: username,
		Token:    token,

		foldersLimiter:   rate.NewLimiter(rateLimitPerSecond(PALIGO_FOLDER_SHOW_LIMIT), PALIGO_FOLDER_SHOW_LIMIT),
		documentsLimiter: rate.NewLimiter(rateLimitPerSecond(PALIGO_DOCUMENT_SHOW_LIMIT), PALIGO_DOCUMENT_SHOW_LIMIT),
	}
}
