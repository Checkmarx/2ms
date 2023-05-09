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
	ID    string
	Limit chan struct{}
}

type IPlugin interface {
	DefineSubCommand(cmd *cobra.Command) *cobra.Command
	Initialize(cmd *cobra.Command) error
	GetItems(chan Item, chan error, *sync.WaitGroup)
}
