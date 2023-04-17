package plugins

import "github.com/spf13/cobra"

type Item struct {
	Content string
	Source  string
	ID      string
}

type Plugin struct {
	ID      string
	Enabled bool
}

type IPlugin interface {
	DefineCommandLineArgs(cmd *cobra.Command) error
	Initialize(cmd *cobra.Command) error
	GetItems(chan Item)
	IsEnabled() bool
}
