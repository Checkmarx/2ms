package plugins

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConfluencePlugin_GetItems(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://checkmarx.atlassian.net/wiki/",
		Token:    "",
		Username: "",
		Spaces:   []string{},
	}

	items, err := confluencePlugin.GetItems()
	if err != nil {
		t.Error(err)
	}

	require.Equal(t, len(*items), 1870)
	require.NoError(t, err)
}

func BenchmarkConfluencePlugin_GetItems(b *testing.B) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://checkmarx.atlassian.net/wiki/",
		Token:    "",
		Username: "",
		Spaces:   []string{},
	}

	items, err := confluencePlugin.GetItems()

	require.Equal(b, len(*items), 1870)
	require.NoError(b, err)
}
