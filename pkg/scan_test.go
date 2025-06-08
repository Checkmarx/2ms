package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/checkmarx/2ms/v3/cmd"
	"github.com/checkmarx/2ms/v3/lib/reporting"
	"github.com/checkmarx/2ms/v3/lib/secrets"
	"github.com/checkmarx/2ms/v3/lib/utils"
	"github.com/checkmarx/2ms/v3/plugins"
	"github.com/stretchr/testify/assert"
)

const (
	githubPatPath                           = "testData/secrets/github-pat.txt"
	jwtPath                                 = "testData/secrets/jwt.txt"
	expectedReportPath                      = "testData/expectedReport.json"
	expectedReportWithValidationPath        = "testData/expectedReportWithValidation.json"
	expectedReportResultsIgnoredResultsPath = "testData/expectedReportWithIgnoredResults.json"
	expectedReportResultsIgnoredRulePath    = "testData/expectedReportWithIgnoredRule.json"
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

		// Marshal actual report and unmarshal back into a map.
		actualReportBytes, err := json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		// Normalize both expected and actual maps.
		normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
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

		expectedReportBytes, err := os.ReadFile(expectedReportResultsIgnoredResultsPath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		actualReportBytes, err := json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
	})
	t.Run("Successful scan with multiple items and ignored rule", func(t *testing.T) {
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
			IgnoreRules: []string{
				"github-pat",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err := os.ReadFile(expectedReportResultsIgnoredRulePath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		actualReportBytes, err := json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
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

		assert.Equal(t, &reporting.Report{}, report)
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
		assert.Equal(t, &reporting.Report{Results: map[string][]*secrets.Secret{}}, actualReport)
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
		assert.Equal(t, &reporting.Report{Results: map[string][]*secrets.Secret{}}, actualReport)
	})
}

func TestScanDynamic(t *testing.T) {
	t.Run("Successful ScanDynamic with Multiple Items", func(t *testing.T) {
		// Reset global channels and report.
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)
		cmd.Channels.WaitGroup = &sync.WaitGroup{}

		// Read file contents.
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

		// Create an input channel and feed it the scan items.
		itemsIn := make(chan ScanItem, len(scanItems))
		for _, item := range scanItems {
			itemsIn <- item
		}
		close(itemsIn)

		testScanner := NewScanner()
		actualReport, err := testScanner.ScanDynamic(itemsIn, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err := os.ReadFile(expectedReportPath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		actualReportBytes, err := json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		// Normalize both maps.
		normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
	})

	t.Run("Successful ScanDynamic with Multiple Items and Ignored Results", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)
		cmd.Channels.WaitGroup = &sync.WaitGroup{}

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

		itemsIn := make(chan ScanItem, len(scanItems))
		for _, item := range scanItems {
			itemsIn <- item
		}
		close(itemsIn)

		testScanner := NewScanner()
		actualReport, err := testScanner.ScanDynamic(itemsIn, ScanConfig{
			IgnoreResultIds: []string{
				"a0cd293e6e122a1c7384d5a56781e39ba350c54b",
				"40483a2b07fa3beaf234d1a0b5d0931d7b7ae9f7",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err := os.ReadFile(expectedReportResultsIgnoredResultsPath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		actualReportBytes, err := json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		// Normalize both maps.
		normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
	})
	t.Run("Successful ScanDynamic with Multiple Items and Ignored Rule", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)
		cmd.Channels.WaitGroup = &sync.WaitGroup{}

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

		itemsIn := make(chan ScanItem, len(scanItems))
		for _, item := range scanItems {
			itemsIn <- item
		}
		close(itemsIn)

		testScanner := NewScanner()
		actualReport, err := testScanner.ScanDynamic(itemsIn, ScanConfig{
			IgnoreRules: []string{
				"github-pat",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err := os.ReadFile(expectedReportResultsIgnoredRulePath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		actualReportBytes, err := json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		// Normalize both maps.
		normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
	})
	t.Run("error handling should work", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error, 2)
		cmd.Channels.WaitGroup = &sync.WaitGroup{}

		itemsIn := make(chan ScanItem)
		close(itemsIn)

		go func() {
			cmd.Channels.Errors <- fmt.Errorf("mock processing error 1")
			cmd.Channels.Errors <- fmt.Errorf("mock processing error 2")
		}()

		testScanner := NewScanner()
		report, err := testScanner.ScanDynamic(itemsIn, ScanConfig{})

		assert.Equal(t, &reporting.Report{}, report)
		assert.NotNil(t, err)
		expectedErrMsg := "error processing scan items: mock processing error 1"
		assert.Equal(t, expectedErrMsg, err.Error())
	})

	t.Run("scan with empty channel", func(t *testing.T) {
		cmd.Report = reporting.Init()
		cmd.SecretsChan = make(chan *secrets.Secret)
		cmd.SecretsExtrasChan = make(chan *secrets.Secret)
		cmd.ValidationChan = make(chan *secrets.Secret)
		cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
		cmd.Channels.Items = make(chan plugins.ISourceItem)
		cmd.Channels.Errors = make(chan error)
		cmd.Channels.WaitGroup = &sync.WaitGroup{}

		itemsIn := make(chan ScanItem)
		close(itemsIn)

		testScanner := NewScanner()
		actualReport, err := testScanner.ScanDynamic(itemsIn, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, &reporting.Report{Results: map[string][]*secrets.Secret{}}, actualReport)
	})
}

func TestScanWithValidation(t *testing.T) {
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
		actualReport, err := testScanner.ScanWithValidation(scanItems, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err := os.ReadFile(expectedReportWithValidationPath)
		assert.NoError(t, err, "failed to read expected report file")

		var expectedReport, actualReportMap map[string]interface{}

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		// Marshal actual report and unmarshal back into a map.
		actualReportBytes, err := json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		// Normalize both expected and actual maps.
		normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
	})
}
