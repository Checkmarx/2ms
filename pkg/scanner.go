package scanner

import (
	"github.com/checkmarx/2ms/v5/engine"
	"github.com/checkmarx/2ms/v5/engine/rules/ruledefine"
	"github.com/checkmarx/2ms/v5/lib/reporting"
	"github.com/checkmarx/2ms/v5/plugins"
)

// ScanConfig contains configuration options for scanning.
type ScanConfig struct {
	IgnoreResultIds []string
	SelectRules     []string
	IgnoreRules     []string
	CustomRules     []*ruledefine.Rule
	WithValidation  bool
	PluginName      string

	// Limit settings
	MaxFindings               uint64 // Total findings limit across entire scan (0 = no limit)
	MaxRuleMatchesPerFragment uint64 // Regex matches limit per rule per fragment (0 = no limit)
	MaxSecretSize             uint64 // Maximum secret size in bytes (0 = no limit)
}

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
	Reset(scanConfig *ScanConfig, opts ...engine.EngineOption) error
	Scan(scanItems []ScanItem, scanConfig *ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error)
	// ScanDynamic performs a scans with custom input of items and optional custom plugin channels.
	//
	// To provide custom plugin channels, use engine.WithPluginChannels:
	//
	//	pluginChannels := plugins.NewChannels(func(c *plugins.Channels) {
	//		c.Items = make(chan plugins.ISourceItem, 100)
	//	})
	//	s.ScanDynamic(ScanConfig{}, engine.WithPluginChannels(pluginChannels))
	ScanDynamic(itemsIn <-chan ScanItem, scanConfig *ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error)
}
