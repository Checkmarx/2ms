package scanner

import (
	"github.com/checkmarx/2ms/lib/reporting"
	"github.com/checkmarx/2ms/plugins"
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

type Scanner interface {
	Scan(scanItems []ScanItem, scanConfig ScanConfig) (reporting.Report, error)
}
