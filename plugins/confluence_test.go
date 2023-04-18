package plugins

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConfluencePlugin_GetItems(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{},
		History:  false,
	}

	items, err := confluencePlugin.GetItems()
	if err != nil {
		t.Error(err)
	}

	require.Equal(t, len(*items), 7)
	require.NoError(t, err)
}

func TestConfluencePlugin_GetItems_History(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{},
		History:  true,
	}

	items, err := confluencePlugin.GetItems()
	if err != nil {
		t.Error(err)
	}

	require.Equal(t, len(*items), 12)
	require.NoError(t, err)
}

func TestConfluencePlugin_GetItems_SpecificSpaces(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{"S1"},
		History:  true,
	}

	items, err := confluencePlugin.GetItems()
	if err != nil {
		t.Error(err)
	}

	require.Equal(t, len(*items), 11)
	require.NoError(t, err)
}

func TestConfluencePlugin_GetItems_SpecificSpaces2(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{"S2"},
		History:  true,
	}

	items, err := confluencePlugin.GetItems()
	if err != nil {
		t.Error(err)
	}

	require.Equal(t, len(*items), 1)
	require.NoError(t, err)
}

func BenchmarkConfluencePlugin_GetItems(b *testing.B) {
	confluencePlugin := ConfluencePlugin{
		Plugin:   Plugin{},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{},
	}

	items, err := confluencePlugin.GetItems()

	require.Equal(b, len(*items), 7)
	require.NoError(b, err)
}
