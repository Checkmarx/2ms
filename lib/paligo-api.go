package lib

import (
	"encoding/json"
	"fmt"
)

type Item struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Type string `json:"type"`
}

type Folder struct {
	Item
	Children []Item `json:"children"`
}

type EmptyFolder struct {
	Item
	Children string `json:"children"`
}

type Component struct {
	Item
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
	Item
	Creator        int      `json:"creator"`
	Owner          int      `json:"owner"`
	Author         int      `json:"author"`
	CreatedAt      int      `json:"created_at"`
	ModifiedAt     int      `json:"modified_at"`
	Checkout       bool     `json:"checkout"`
	ParentResource int      `json:"parent_resource"`
	Content        string   `json:"content"`
	Languages      []string `json:"languages"`
}

type Paligo struct {
	Instance string
	Username string
	Token    string
}

func (p *Paligo) GetCredentials() (string, string) {
	return p.Username, p.Token
}

func (p *Paligo) ListFolders() (*[]EmptyFolder, error) {
	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/folders", p.Instance)

	req, err := HttpRequest("GET", url, p)
	if err != nil {
		return nil, err
	}

	var folders *ListFoldersResponse
	err = json.Unmarshal(req, &folders)

	return &folders.Folders, err
}

func (p *Paligo) ShowFolder(folderId int) (*Folder, error) {
	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/folders/%d", p.Instance, folderId)

	req, err := HttpRequest("GET", url, p)
	if err != nil {
		return nil, err
	}

	folder := &Folder{}
	err = json.Unmarshal(req, folder)

	return folder, err
}

func (p *Paligo) ShowDocument(documentId int) (*Document, error) {
	url := fmt.Sprintf("https://%s.paligoapp.com/api/v2/documents/%d", p.Instance, documentId)

	req, err := HttpRequest("GET", url, p)
	if err != nil {
		return nil, err
	}

	document := &Document{}
	err = json.Unmarshal(req, document)

	return document, err
}

func NewPaligoApi(instance string, username string, token string) *Paligo {
	return &Paligo{
		Instance: instance,
		Username: username,
		Token:    token,
	}
}
