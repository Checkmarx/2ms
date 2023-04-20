package plugins

import (
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

const timeSleepInterval = 50

func TestConfluencePlugin_GetItems(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin: Plugin{
			ID:      "",
			Enabled: true,
			Limit:   make(chan struct{}, 100),
		},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{},
		History:  false,
	}

	var itemsChannel = make(chan Item)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var items []Item
	var error error

	wg.Add(1)
	go confluencePlugin.GetItems(itemsChannel, errorsChannel, &wg)

	go func() {
		for {
			select {
			case item := <-itemsChannel:
				items = append(items, item)
			case err, ok := <-errorsChannel:
				if !ok {
					break
				}
				error = err
			}

		}
	}()
	wg.Wait()
	time.Sleep(time.Millisecond * timeSleepInterval)
	require.Equal(t, len(items), 7)
	require.NoError(t, error)
}

func TestConfluencePlugin_GetItems_History(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin: Plugin{
			ID:      "",
			Enabled: true,
			Limit:   make(chan struct{}, 100),
		},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{},
		History:  true,
	}

	var itemsChannel = make(chan Item)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var items []Item
	var error error

	wg.Add(1)
	go confluencePlugin.GetItems(itemsChannel, errorsChannel, &wg)

	go func() {
		for {
			select {
			case item := <-itemsChannel:
				items = append(items, item)
			case err, ok := <-errorsChannel:
				if !ok {
					break
				}
				error = err
			}

		}
	}()
	wg.Wait()
	time.Sleep(time.Millisecond * timeSleepInterval)

	require.Equal(t, len(items), 13)
	require.NoError(t, error)
}

func TestConfluencePlugin_GetItems_SpecificSpaces(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin: Plugin{
			ID:      "",
			Enabled: true,
			Limit:   make(chan struct{}, 100),
		},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{"S1"},
		History:  true,
	}

	var itemsChannel = make(chan Item)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var items []Item
	var error error

	wg.Add(1)
	go confluencePlugin.GetItems(itemsChannel, errorsChannel, &wg)

	go func() {
		for {
			select {
			case item := <-itemsChannel:
				items = append(items, item)
			case err, ok := <-errorsChannel:
				if !ok {
					break
				}
				error = err
			}
		}
	}()
	wg.Wait()

	time.Sleep(time.Millisecond * timeSleepInterval)
	require.Equal(t, len(items), 12)
	require.NoError(t, error)
}

func TestConfluencePlugin_GetItems_SpecificSpaces2(t *testing.T) {
	confluencePlugin := ConfluencePlugin{
		Plugin: Plugin{
			ID:      "",
			Enabled: true,
			Limit:   make(chan struct{}, 100),
		},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{"S2"},
		History:  true,
	}

	var itemsChannel = make(chan Item)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var items []Item
	var error error

	wg.Add(1)
	go confluencePlugin.GetItems(itemsChannel, errorsChannel, &wg)

	go func() {
		for {
			select {
			case item := <-itemsChannel:
				items = append(items, item)
			case err, ok := <-errorsChannel:
				if !ok {
					break
				}
				error = err
			}
		}
	}()
	wg.Wait()

	time.Sleep(time.Millisecond * timeSleepInterval)
	require.Equal(t, len(items), 1)
	require.NoError(t, error)
}

func BenchmarkConfluencePlugin_GetItems(b *testing.B) {
	confluencePlugin := ConfluencePlugin{
		Plugin: Plugin{
			ID:      "",
			Enabled: true,
			Limit:   make(chan struct{}, 100),
		},
		URL:      "https://secrets-inside.atlassian.net/wiki",
		Token:    "",
		Username: "",
		Spaces:   []string{},
		History:  false,
	}

	var itemsChannel = make(chan Item)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var items []Item
	var error error

	wg.Add(1)
	go confluencePlugin.GetItems(itemsChannel, errorsChannel, &wg)

	go func() {
		for {
			select {
			case item := <-itemsChannel:
				items = append(items, item)
			case err, ok := <-errorsChannel:
				if !ok {
					break
				}
				error = err
			}
		}
	}()
	wg.Wait()
	time.Sleep(time.Millisecond * timeSleepInterval)
	require.Equal(b, len(items), 7)
	require.NoError(b, error)
}
