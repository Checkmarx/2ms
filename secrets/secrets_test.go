package secrets

import (
	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

const timeSleepInterval = 50

func TestWrapper_Detect(t *testing.T) {
	tags := []string{"all"}
	secrets := Init(tags)

	report := reporting.Report{}
	report.Results = make(map[string][]reporting.Secret)

	var secretsChannel = make(chan reporting.Secret)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var error error

	items := []plugins.Item{
		{
			ID:      "https://secrets-inside.atlassian.net/wiki/spaces/S1/pages/262424",
			Content: "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8\nEeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe\nBaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB\nAoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe\nThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT\ngmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip\nkRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8\nTpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ\nl98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+\neuJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx\nJPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT\n9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1\n4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==\n-----END RSA PRIVATE KEY-----",
			Source:  "https://secrets-inside.atlassian.net/wiki/rest/api/content/262424?expand=body.storage.value,version,history.previousVersion",
		},
		{
			ID:      "https://secrets-inside.atlassian.net/wiki/spaces/S1/pages/262424",
			Content: "-----BEGIN RSA PRIVATE KEY-----\nOLD_SECRETKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8\nEeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe\nBaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB\nAoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe\nThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT\ngmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip\nkRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8\nTpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ\nl98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+\neuJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx\nJPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT\n9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1\n4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==\n-----END RSA PRIVATE KEY-----",
			Source:  "https://secrets-inside.atlassian.net/wiki/rest/api/content/262424?expand=body.storage.value,version,history.previousVersion",
		},
	}

	for _, item := range items {
		wg.Add(1)
		go secrets.Detect(secretsChannel, item, &wg)
	}

	go func() {
		for {
			select {
			case secret := <-secretsChannel:
				report.TotalSecretsFound++
				report.Results[secret.ID] = append(report.Results[secret.ID], secret)
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

	require.NoError(t, error)
	require.Equal(t, report.TotalSecretsFound, 2)
	require.Equal(t, len(report.Results), 1)
}

func TestWrapper_Detect2(t *testing.T) {
	tags := []string{"all"}
	secrets := Init(tags)

	report := reporting.Report{}
	report.Results = make(map[string][]reporting.Secret)

	var secretsChannel = make(chan reporting.Secret)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var error error

	items := []plugins.Item{
		{
			ID:      "https://secrets-inside.atlassian.net/wiki/spaces/S1/pages/262424",
			Content: "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8\nEeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe\nBaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB\nAoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe\nThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT\ngmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip\nkRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8\nTpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ\nl98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+\neuJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx\nJPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT\n9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1\n4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==\n-----END RSA PRIVATE KEY-----",
			Source:  "https://secrets-inside.atlassian.net/wiki/rest/api/content/262424?expand=body.storage.value,version,history.previousVersion",
		},
		{
			ID:      "https://secrets-inside.atlassian.net/wiki/spaces/S1/pages/262425",
			Content: "-----BEGIN RSA PRIVATE KEY-----\nOLD_SECRETKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8\nEeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe\nBaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB\nAoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe\nThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT\ngmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip\nkRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8\nTpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ\nl98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+\neuJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx\nJPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT\n9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1\n4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==\n-----END RSA PRIVATE KEY-----",
			Source:  "https://secrets-inside.atlassian.net/wiki/rest/api/content/262425?expand=body.storage.value,version,history.previousVersion",
		},
	}

	for _, item := range items {
		wg.Add(1)
		go secrets.Detect(secretsChannel, item, &wg)
	}

	go func() {
		for {
			select {
			case secret := <-secretsChannel:
				report.TotalSecretsFound++
				report.Results[secret.ID] = append(report.Results[secret.ID], secret)
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

	require.NoError(t, error)
	require.Equal(t, report.TotalSecretsFound, 2)
	require.Equal(t, len(report.Results), 2)
}

func BenchmarkWrapper_RunScans(b *testing.B) {
	tags := []string{"all"}
	secrets := Init(tags)

	report := reporting.Report{}
	report.Results = make(map[string][]reporting.Secret)

	var secretsChannel = make(chan reporting.Secret)
	var errorsChannel = make(chan error)
	var wg sync.WaitGroup
	var error error

	items := []plugins.Item{
		{
			ID:      "https://secrets-inside.atlassian.net/wiki/spaces/S1/pages/262424",
			Content: "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8\nEeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe\nBaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB\nAoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe\nThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT\ngmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip\nkRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8\nTpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ\nl98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+\neuJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx\nJPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT\n9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1\n4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==\n-----END RSA PRIVATE KEY-----",
			Source:  "https://secrets-inside.atlassian.net/wiki/rest/api/content/262424?expand=body.storage.value,version,history.previousVersion",
		},
		{
			ID:      "https://secrets-inside.atlassian.net/wiki/spaces/S1/pages/262424",
			Content: "-----BEGIN RSA PRIVATE KEY-----\nOLD_SECRETKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8\nEeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe\nBaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB\nAoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe\nThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT\ngmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip\nkRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8\nTpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ\nl98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+\neuJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx\nJPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT\n9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1\n4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==\n-----END RSA PRIVATE KEY-----",
			Source:  "https://secrets-inside.atlassian.net/wiki/rest/api/content/262424?expand=body.storage.value,version,history.previousVersion",
		},
	}

	for _, item := range items {
		wg.Add(1)
		go secrets.Detect(secretsChannel, item, &wg)
	}

	go func() {
		for {
			select {
			case secret := <-secretsChannel:
				report.TotalSecretsFound++
				report.Results[secret.ID] = append(report.Results[secret.ID], secret)
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

	require.NoError(b, error)
	require.Equal(b, report.TotalSecretsFound, 2)
	require.Equal(b, len(report.Results), 1)
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
