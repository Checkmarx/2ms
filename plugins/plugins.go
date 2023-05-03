package plugins

import (
	"sync"

	"github.com/spf13/cobra"
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
	DefineCommandLineArgs(cmd *cobra.Command) *cobra.Command
	Initialize(cmd *cobra.Command) error
	GetItems(chan Item, chan error, *sync.WaitGroup)
	IsEnabled() bool
}
