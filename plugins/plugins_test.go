package plugins

import (
	"encoding/csv"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestConfluencePlugin_GetItems(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "joao.cunhadesilva@checkmarx.com",
		Spaces:   []string{},
		History:  false,
	}

	items, err := confluencePlugin.GetItems()
	if err != nil {
		t.Error(err)
	}

	//writeToCSV("../testdata/items.csv", items, t)

	require.Equal(t, len(*items), 7)
	require.NoError(t, err)
}

func TestConfluencePlugin_GetItems_History(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "joao.cunhadesilva@checkmarx.com",
		Spaces:   []string{},
		History:  true,
	}

	items, err := confluencePlugin.GetItems()
	if err != nil {
		t.Error(err)
	}

	//writeToCSV("../testdata/items_history.csv", items, t)

	require.Equal(t, len(*items), 12)
	require.NoError(t, err)
}

func BenchmarkConfluencePlugin_GetItems(b *testing.B) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "joao.cunhadesilva@checkmarx.com",
		Spaces:   []string{},
	}

	items, err := confluencePlugin.GetItems()

	require.Equal(b, len(*items), 7)
	require.NoError(b, err)
}

func writeToCSV(filename string, items *[]Item, t *testing.T) {
	file, err := os.Create(filename)
	if err != nil {
		t.Error(err)
	}
	defer file.Close()

	csvwriter := csv.NewWriter(file)

	// Write the header
	if err := csvwriter.Write([]string{"Content", "Source", "ID"}); err != nil {
		t.Error(err)
	}

	// Write the Items
	for _, item := range *items {
		if err := csvwriter.Write([]string{item.Content, item.Source, item.ID}); err != nil {
			t.Error(err)
		}
	}
	csvwriter.Flush()
}
