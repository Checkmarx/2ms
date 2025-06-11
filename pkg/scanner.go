package scanner

import (
	"github.com/checkmarx/2ms/v3/lib/reporting"
	"github.com/checkmarx/2ms/v3/plugins"
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
	Scan(scanItems []ScanItem, scanConfig ScanConfig) (*reporting.Report, error)
	ScanDynamic(itemsIn <-chan ScanItem, scanConfig ScanConfig) (*reporting.Report, error)
}
