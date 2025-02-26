package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/checkmarx/2ms/cmd"
	"github.com/checkmarx/2ms/lib/reporting"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const (
	githubPatPath                    = "testData/secrets/github-pat.txt"
	jwtPath                          = "testData/secrets/jwt.txt"
	expectedReportPath               = "testData/expectedReport.json"
	expectedReportResultsIgnoredPath = "testData/expectedReportWithIgnoredResults.json"
)

func TestScan(t *testing.T) {
	t.Run("Successful Scan with Multiple Items", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)

		githubPatBytes, err := os.ReadFile(githubPatPath)
		assert.NoError(t, err, "failed to read github-pat file")
		githubPatContent := string(githubPatBytes)

		jwtBytes, err := os.ReadFile(jwtPath)
		assert.NoError(t, err, "failed to read jwt file")
		jwtContent := string(jwtBytes)

		emptyContent := ""
		emptyMockPath := "mockPath"

		scanItems := []ScanItem{
			{
				Content: &githubPatContent,
				ID:      fmt.Sprintf("mock-%s", githubPatPath),
				Source:  githubPatPath,
			},
			{
				Content: &emptyContent,
				ID:      fmt.Sprintf("mock-%s", emptyMockPath),
				Source:  emptyMockPath,
			},
			{
				Content: &jwtContent,
				ID:      fmt.Sprintf("mock-%s", jwtPath),
				Source:  jwtPath,
			},
		}

		testScanner := NewScanner()
		actualReport, err := testScanner.Scan(scanItems, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err := os.ReadFile(expectedReportPath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}
		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		err = json.Unmarshal([]byte(actualReport), &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		if !cmp.Equal(expectedReport, actualReportMap) {
			t.Errorf("Scan report does not match the expected report:\n%s", cmp.Diff(expectedReport, actualReportMap))
		}
	})
	t.Run("Successful scan with multiple items and ignored results", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)

		githubPatBytes, err := os.ReadFile(githubPatPath)
		assert.NoError(t, err, "failed to read github-pat file")
		githubPatContent := string(githubPatBytes)

		jwtBytes, err := os.ReadFile(jwtPath)
		assert.NoError(t, err, "failed to read jwt file")
		jwtContent := string(jwtBytes)

		emptyContent := ""
		emptyMockPath := "mockPath"

		scanItems := []ScanItem{
			{
				Content: &githubPatContent,
				ID:      fmt.Sprintf("mock-%s", githubPatPath),
				Source:  githubPatPath,
			},
			{
				Content: &emptyContent,
				ID:      fmt.Sprintf("mock-%s", emptyMockPath),
				Source:  emptyMockPath,
			},
			{
				Content: &jwtContent,
				ID:      fmt.Sprintf("mock-%s", jwtPath),
				Source:  jwtPath,
			},
		}

		testScanner := NewScanner()
		actualReport, err := testScanner.Scan(scanItems, ScanConfig{
			IgnoreResultIds: []string{
				"a0cd293e6e122a1c7384d5a56781e39ba350c54b",
				"40483a2b07fa3beaf234d1a0b5d0931d7b7ae9f7",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err := os.ReadFile(expectedReportResultsIgnoredPath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}
		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		err = json.Unmarshal([]byte(actualReport), &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		if !cmp.Equal(expectedReport, actualReportMap) {
			t.Errorf("Scan report does not match the expected report:\n%s", cmp.Diff(expectedReport, actualReportMap))
		}
	})
	t.Run("error handling should work", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)

		emptyContent := ""
		scanItems := []ScanItem{
			{
				Content: &emptyContent,
				ID:      "",
				Source:  "",
			},
			{
				Content: &emptyContent,
				ID:      "",
				Source:  "",
			},
		}

		testScanner := NewScanner()
		cmd.Channels.Errors = make(chan error, 2)

		go func() {
			cmd.Channels.Errors <- fmt.Errorf("mock processing error 1")
			cmd.Channels.Errors <- fmt.Errorf("mock processing error 2")
		}()
		report, err := testScanner.Scan(scanItems, ScanConfig{})

		assert.Equal(t, "", report)
		assert.NotNil(t, err)
		assert.Equal(t, "error(s) processing scan items:\nmock processing error 1\nmock processing error 2", err.Error())
	})
	t.Run("scan with scanItems empty", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)

		testScanner := NewScanner()
		actualReport, err := testScanner.Scan([]ScanItem{}, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, "", actualReport)
	})
	t.Run("scan with scanItems nil", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)

		testScanner := NewScanner()
		actualReport, err := testScanner.Scan(nil, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, "", actualReport)
	})
}
