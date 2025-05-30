package plugins

import (
	"sync"

	"github.com/spf13/cobra"
)

type ISourceItem interface {
	GetContent() *string
	GetID() string
	GetSource() string
	GetGitInfo() *GitInfo
}

type item struct {
	Content *string
	// Unique identifier of the item
	ID string
	// User friendly description and/or link to the item
	Source  string
	GitInfo *GitInfo
}

var _ ISourceItem = (*item)(nil)

func (i item) GetContent() *string {
	return i.Content
}

func (i item) GetID() string {
	return i.ID
}

func (i item) GetSource() string {
	return i.Source
}

func (i item) GetGitInfo() *GitInfo {
	return i.GitInfo
}

type Plugin struct {
	ID    string
	Limit chan struct{}
}

type Channels struct {
	Items     chan ISourceItem
	Errors    chan error
	WaitGroup *sync.WaitGroup
}

type IPlugin interface {
	GetName() string
	DefineCommand(items chan ISourceItem, errors chan error) (*cobra.Command, error)
}
