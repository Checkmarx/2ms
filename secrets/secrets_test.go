package secrets

import (
	"encoding/csv"
	"github.com/checkmarx/2ms/plugins"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"
)

func TestWrapper_RunScans(t *testing.T) {
	// Load items
	csvFile, err := os.Open("../testdata/items.csv")
	if err != nil {
		t.Error(err)
	}
	csvReader := csv.NewReader(csvFile)

	items := make([]plugins.Item, 0)

	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Error(err)
		}
		item := ItemFromCSV(row)
		items = append(items, item)
	}

	tags := []string{"all"}
	secrets := Init(tags)
	results := secrets.RunScans(items)

	require.NoError(t, err)
	require.Equal(t, len(results), 0)
}

func ItemFromCSV(row []string) plugins.Item {
	return plugins.Item{
		Content: row[0],
		Source:  row[1],
		ID:      row[2],
	}
}

func BenchmarkWrapper_RunScans(b *testing.B) {
	// Load items
	csvFile, err := os.Open("../testdata/items.csv")
	if err != nil {
		b.Error(err)
	}
	csvReader := csv.NewReader(csvFile)

	items := make([]plugins.Item, 0)

	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			b.Error(err)
		}
		item := ItemFromCSV(row)
		items = append(items, item)
	}

	tags := []string{"all"}
	secrets := Init(tags)
	results := secrets.RunScans(items)

	require.NoError(b, err)
	require.Equal(b, len(results), 0)
}

func TestLoadAllRules(t *testing.T) {
	rules, _ := loadAllRules()

	if len(rules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestIsAllFilter_AllFilterNotPresent(t *testing.T) {
	filters := []string{"token", "key"}

	isAllFilter := isAllFilter(filters)

	if isAllFilter {
		t.Errorf("all rules were not selected")
	}
}

func TestIsAllFilter_AllFilterPresent(t *testing.T) {
	filters := []string{"token", "key", "all"}

	isAllFilter := isAllFilter(filters)

	if !isAllFilter {
		t.Errorf("all filter selected")
	}
}

func TestIsAllFilter_OnlyAll(t *testing.T) {
	filters := []string{"all"}

	isAllFilter := isAllFilter(filters)

	if !isAllFilter {
		t.Errorf("all filter selected")
	}
}

func TestGetRules_AllFilter(t *testing.T) {
	rules, _ := loadAllRules()
	tags := []string{"all"}

	filteredRules := getRules(rules, tags)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_TokenFilter(t *testing.T) {
	rules, _ := loadAllRules()
	tags := []string{"api-token"}

	filteredRules := getRules(rules, tags)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_KeyFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"api-key"}

	filteredRules := getRules(rules, filters)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_IdFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"access-token"}

	filteredRules := getRules(rules, filters)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_IdAndKeyFilters(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"api-key", "access-token"}

	filteredRules := getRules(rules, filters)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}
