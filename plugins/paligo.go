package plugins

import (
	"context"
	"encoding/json"
	"fmt"
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
	p.paligoApi = NewPaligoApi(paligoInstanceArg, p.username, p.token)

	if paligoFolderArg != 0 {
		p.WaitGroup.Add(1)
		go p.handleFolderChildren(PaligoItem{ID: paligoFolderArg, Name: "ID" + fmt.Sprint(paligoFolderArg)})
	} else {
		folders, err := p.paligoApi.ListFolders()
		if err != nil {
			log.Error().Err(err).Msg("error while getting folders")
			p.Channels.Errors <- err
			return
		}
		p.WaitGroup.Add(len(*folders))
		for _, folder := range *folders {
			go p.handleFolderChildren(folder.PaligoItem)
		}
	}
}

func (p *PaligoPlugin) handleFolderChildren(folder PaligoItem) {
	defer p.Channels.WaitGroup.Done()

	log.Info().Msgf("Getting folder %s", folder.Name)
	folderInfo, err := p.paligoApi.ShowFolder(folder.ID)
	if err != nil {
		log.Error().Err(err).Msgf("error while getting %s '%s'", folder.Type, folder.Name)
		p.Channels.Errors <- err
		return
	}

	for _, child := range folderInfo.Children {
		if child.Type == "component" {
			p.WaitGroup.Add(1)
			go p.handleComponent(child)
		} else if child.Type == "folder" {
			p.WaitGroup.Add(1)
			go p.handleFolderChildren(child)
		}
	}

}

func (p *PaligoPlugin) handleComponent(item PaligoItem) {
	defer p.Channels.WaitGroup.Done()

	log.Info().Msgf("Getting component %s", item.Name)
	document, err := p.paligoApi.ShowDocument(item.ID)
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
	PALIGO_DOCUMENT_SHOW_LIMIT = 50
	PALIGO_FOLDER_SHOW_LIMIT   = 50
	rateLimitDeviation         = 20
)

func rateLimitPerSecond(rateLimit int) rate.Limit {
	return rate.Every(time.Minute / (time.Duration(rateLimit) - rateLimitDeviation))
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

func (p *PaligoClient) GetCredentials() (string, string) {
	return p.Username, p.Token
}

func (p *PaligoClient) ListFolders() (*[]EmptyFolder, error) {
	if err := p.foldersLimiter.Wait(context.TODO()); err != nil {
		log.Error().Msgf("Error waiting for rate limiter: %s", err)
	}

	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/folders", p.Instance)

	req, _, err := lib.HttpRequest("GET", url, p)
	if err != nil {
		return nil, err
	}

	var folders *ListFoldersResponse
	err = json.Unmarshal(req, &folders)

	return &folders.Folders, err
}

func (p *PaligoClient) ShowFolder(folderId int) (*Folder, error) {
	if err := p.foldersLimiter.Wait(context.TODO()); err != nil {
		log.Error().Msgf("Error waiting for rate limiter: %s", err)
	}

	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/folders/%d", p.Instance, folderId)

	req, _, err := lib.HttpRequest("GET", url, p)
	if err != nil {
		return nil, err
	}

	folder := &Folder{}
	err = json.Unmarshal(req, folder)

	return folder, err
}

func (p *PaligoClient) ShowDocument(documentId int) (*Document, error) {
	if err := p.documentsLimiter.Wait(context.TODO()); err != nil {
		log.Error().Msgf("Error waiting for rate limiter: %s", err)
	}

	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/documents/%d", p.Instance, documentId)

	req, _, err := lib.HttpRequest("GET", url, p)
	if err != nil {
		return nil, err
	}

	document := &Document{}
	err = json.Unmarshal(req, document)

	return document, err
}

func NewPaligoApi(instance string, username string, token string) *PaligoClient {
	return &PaligoClient{
		Instance: instance,
		Username: username,
		Token:    token,

		foldersLimiter:   rate.NewLimiter(rateLimitPerSecond(PALIGO_FOLDER_SHOW_LIMIT), 1),
		documentsLimiter: rate.NewLimiter(rateLimitPerSecond(PALIGO_DOCUMENT_SHOW_LIMIT), 1),
	}
}
