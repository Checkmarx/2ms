package plugins

import (
	"sync"

	"github.com/spf13/cobra"
)

type Item struct {
	Content string
	// Unique identifier of the item (page, document, file) with user-friendly content (e.g. URL, file path)
	ID string
}

type Plugin struct {
	ID    string
	Limit chan struct{}
}

type Channels struct {
	Items     chan Item
	Errors    chan error
	WaitGroup *sync.WaitGroup
}

type IPlugin interface {
	GetName() string
	DefineCommand(channels Channels) (*cobra.Command, error)
}
