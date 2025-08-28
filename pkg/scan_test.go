package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/checkmarx/2ms/v4/cmd"
	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/lib/reporting"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/checkmarx/2ms/v4/lib/utils"
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
				"335370e9c538452b10e69967f90ca64a1a9cf0c9",
				"a234461b998b6c9b9340f2543729ea9fc0ccdb4c",
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
		testScanner := NewScanner()
		actualReport, err := testScanner.Scan([]ScanItem{}, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, &reporting.Report{Results: map[string][]*secrets.Secret{}}, actualReport)
	})
	t.Run("scan with scanItems nil", func(t *testing.T) {
		testScanner := NewScanner()
		actualReport, err := testScanner.Scan(nil, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, &reporting.Report{Results: map[string][]*secrets.Secret{}}, actualReport)
	})
	t.Run("scan more than 1 time using the same scanner instance", func(t *testing.T) {
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

		// scan 1
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

		// scan 2
		actualReport, err = testScanner.Scan(scanItems, ScanConfig{
			IgnoreResultIds: []string{
				"335370e9c538452b10e69967f90ca64a1a9cf0c9",
				"a234461b998b6c9b9340f2543729ea9fc0ccdb4c",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err = os.ReadFile(expectedReportResultsIgnoredResultsPath)
		assert.NoError(t, err, "failed to read expected report file")

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		actualReportBytes, err = json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		normalizedExpectedReport, err = utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err = utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
	})
}

func TestScanDynamic(t *testing.T) {
	t.Run("Successful ScanDynamic with Multiple Items", func(t *testing.T) {
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
				"335370e9c538452b10e69967f90ca64a1a9cf0c9",
				"a234461b998b6c9b9340f2543729ea9fc0ccdb4c",
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
		content := "content"
		itemsIn := make(chan ScanItem, 1)
		itemsIn <- ScanItem{
			Content: &content,
			ID:      "id",
			Source:  "source",
		}
		close(itemsIn)

		// get rules to filter all and force an error
		defaultRules := rules.GetDefaultRules()
		var idOfRules []string
		for _, rule := range *defaultRules {
			idOfRules = append(idOfRules, rule.Rule.RuleID)
		}

		testScanner := NewScanner()
		report, err := testScanner.ScanDynamic(itemsIn, ScanConfig{IgnoreRules: idOfRules})

		assert.Error(t, err)
		assert.Equal(t, "error initializing engine: no rules were selected", err.Error())
		assert.Equal(t, &reporting.Report{
			TotalItemsScanned: 0,
			TotalSecretsFound: 0,
		}, report)
	})
	t.Run("scan with empty channel", func(t *testing.T) {
		itemsIn := make(chan ScanItem)
		close(itemsIn)

		testScanner := NewScanner()
		actualReport, err := testScanner.ScanDynamic(itemsIn, ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, &reporting.Report{Results: map[string][]*secrets.Secret{}}, actualReport)
	})
	t.Run("scan more than 1 time using the same scanner instance", func(t *testing.T) {
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
		itemsIn1 := make(chan ScanItem, len(scanItems))
		itemsIn2 := make(chan ScanItem, len(scanItems))
		for _, item := range scanItems {
			itemsIn1 <- item
			itemsIn2 <- item
		}
		close(itemsIn1)
		close(itemsIn2)

		testScanner := NewScanner()

		// scan 2
		actualReport, err := testScanner.ScanDynamic(itemsIn1, ScanConfig{})
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

		// scan 2
		actualReport, err = testScanner.ScanDynamic(itemsIn2, ScanConfig{
			IgnoreResultIds: []string{
				"335370e9c538452b10e69967f90ca64a1a9cf0c9",
				"a234461b998b6c9b9340f2543729ea9fc0ccdb4c",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		expectedReportBytes, err = os.ReadFile(expectedReportResultsIgnoredResultsPath)
		assert.NoError(t, err, "failed to read expected report file")

		err = json.Unmarshal(expectedReportBytes, &expectedReport)
		assert.NoError(t, err, "failed to unmarshal expected report JSON")

		actualReportBytes, err = json.Marshal(actualReport)
		assert.NoError(t, err, "failed to marshal actual report to JSON")
		err = json.Unmarshal(actualReportBytes, &actualReportMap)
		assert.NoError(t, err, "failed to unmarshal actual report JSON")

		// Normalize both maps.
		normalizedExpectedReport, err = utils.NormalizeReportData(expectedReport)
		assert.NoError(t, err, "Failed to normalize actual report")

		normalizedActualReport, err = utils.NormalizeReportData(actualReportMap)
		assert.NoError(t, err, "Failed to normalize actual report")

		assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
	})
}

func TestScanWithValidation(t *testing.T) {
	t.Run("Successful Scan with Multiple Items", func(t *testing.T) {
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
		actualReport, err := testScanner.Scan(scanItems, ScanConfig{WithValidation: true})
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
