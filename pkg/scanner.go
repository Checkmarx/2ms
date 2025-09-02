package scanner

import (
	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/checkmarx/2ms/v4/lib/reporting"
	"github.com/checkmarx/2ms/v4/plugins"
)

type ScanItem struct {
	Content *string
	// Unique identifier of the item
	ID string
	// User-friendly description and/or link to the item
	Source string
}

var _ plugins.ISourceItem = (*ScanItem)(nil)

func (i ScanItem) GetContent() *string {
	return i.Content
}

func (i ScanItem) GetID() string {
	return i.ID
}

func (i ScanItem) GetSource() string {
	return i.Source
}

func (i ScanItem) GetGitInfo() *plugins.GitInfo {
	return nil
}

type Scanner interface {
	Reset(scanConfig resources.ScanConfig, opts ...engine.EngineOption) error
	Scan(scanItems []ScanItem, scanConfig resources.ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error)
	// ScanDynamic performs a scans with custom input of items andoptional custom plugin channels.
	//
	// To provide custom plugin channels, use engine.WithPluginChannels:
	//
	//	pluginChannels := plugins.NewChannels(func(c *plugins.Channels) {
	//		c.Items = make(chan plugins.ISourceItem, 100)
	//	})
	//	s.ScanDynamic(ScanConfig{}, engine.WithPluginChannels(pluginChannels))
	ScanDynamic(itemsIn <-chan ScanItem, scanConfig resources.ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error)
}
