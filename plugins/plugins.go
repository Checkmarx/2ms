package plugins

import (
	"github.com/spf13/cobra"
	"sync"
)

type Item struct {
	Content string
	Source  string
	ID      string
}

type Plugin struct {
	ID      string
	Enabled bool
	Limit   chan struct{}
}

type IPlugin interface {
	DefineCommandLineArgs(cmd *cobra.Command) error
	Initialize(cmd *cobra.Command) error
	GetItems(chan Item, chan error, *sync.WaitGroup)
	IsEnabled() bool
}
