package scanner

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/checkmarx/2ms/v4/lib/reporting"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/checkmarx/2ms/v4/lib/utils"
	"github.com/checkmarx/2ms/v4/plugins"
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

// Flag to update expected output files instead of comparing against them
var updateExpected = flag.Bool("update-test-data", false, "Update expected test output files instead of comparing against them")

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
		actualReport, err := testScanner.Scan(scanItems, resources.ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")

		// Use helper function to either update expected file or compare results
		compareOrUpdateTestData(t, actualReport, expectedReportPath)
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
		actualReport, err := testScanner.Scan(scanItems, resources.ScanConfig{
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
		actualReport, err := testScanner.Scan(scanItems, resources.ScanConfig{
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

		pluginChannels := plugins.NewChannels(func(c *plugins.Channels) {
			c.Errors = make(chan error, 2)
		})
		testScanner := NewScanner()

		go func() {
			errorsCh := pluginChannels.GetErrorsCh()
			errorsCh <- fmt.Errorf("mock processing error 1")
			errorsCh <- fmt.Errorf("mock processing error 2")
		}()
		report, err := testScanner.Scan(scanItems, resources.ScanConfig{}, engine.WithPluginChannels(pluginChannels))

		assert.Equal(t, &reporting.Report{}, report)
		assert.NotNil(t, err)
		assert.Equal(t, "error(s) processing scan items:\nmock processing error 1\nmock processing error 2", err.Error())
	})
	t.Run("scan with scanItems empty", func(t *testing.T) {
		testScanner := NewScanner()
		actualReport, err := testScanner.Scan([]ScanItem{}, resources.ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, &reporting.Report{Results: map[string][]*secrets.Secret{}}, actualReport)
	})
	t.Run("scan with scanItems nil", func(t *testing.T) {
		testScanner := NewScanner()
		actualReport, err := testScanner.Scan(nil, resources.ScanConfig{})
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
		actualReport, err := testScanner.Scan(scanItems, resources.ScanConfig{})
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
		actualReport, err = testScanner.Scan(scanItems, resources.ScanConfig{
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
		assert.NoError(t, err, "failed to create scanner")

		actualReport, err := testScanner.ScanDynamic(itemsIn, resources.ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")

		compareOrUpdateTestData(t, actualReport, expectedReportPath)
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

		actualReport, err := testScanner.ScanDynamic(itemsIn, resources.ScanConfig{
			IgnoreResultIds: []string{
				"335370e9c538452b10e69967f90ca64a1a9cf0c9",
				"a234461b998b6c9b9340f2543729ea9fc0ccdb4c",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		compareOrUpdateTestData(t, actualReport, expectedReportResultsIgnoredResultsPath)
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
		assert.NoError(t, err, "failed to create scanner")

		actualReport, err := testScanner.ScanDynamic(itemsIn, resources.ScanConfig{
			IgnoreRules: []string{
				"github-pat",
			},
		})
		assert.NoError(t, err, "scanner encountered an error")

		compareOrUpdateTestData(t, actualReport, expectedReportResultsIgnoredRulePath)
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
		for _, rule := range defaultRules {
			idOfRules = append(idOfRules, rule.Rule.RuleID)
		}

		testScanner := NewScanner()

		report, err := testScanner.ScanDynamic(itemsIn, resources.ScanConfig{IgnoreRules: idOfRules})

		assert.Error(t, err)
		assert.ErrorIs(t, err, engine.ErrNoRulesSelected)
		assert.Equal(t, &reporting.Report{
			TotalItemsScanned: 0,
			TotalSecretsFound: 0,
		}, report)
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
		actualReport, err := testScanner.ScanDynamic(itemsIn1, resources.ScanConfig{})
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
		actualReport, err = testScanner.ScanDynamic(itemsIn2, resources.ScanConfig{
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
		actualReport, err := testScanner.Scan(scanItems, resources.ScanConfig{WithValidation: true})
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

// compareOrUpdateTestData either updates the expected file with actual results or compares them
// This is a reusable helper function for other tests
func compareOrUpdateTestData(t *testing.T, actualReport reporting.IReport, expectedFilePath string) {
	// Marshal actual report to JSON
	actualReportBytes, err := json.Marshal(actualReport)
	assert.NoError(t, err, "failed to marshal actual report to JSON")

	var actualReportMap map[string]interface{}
	err = json.Unmarshal(actualReportBytes, &actualReportMap)
	assert.NoError(t, err, "failed to unmarshal actual report JSON")

	// Normalize actual report
	normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
	assert.NoError(t, err, "Failed to normalize actual report")

	// Update expected file if flag is set and return
	if *updateExpected {
		// Write the normalized actual report to the expected file
		normalizedActualBytes, err := json.MarshalIndent(normalizedActualReport, "", "  ")
		assert.NoError(t, err, "failed to marshal normalized actual report")

		err = os.WriteFile(expectedFilePath, normalizedActualBytes, 0644)
		assert.NoError(t, err, "failed to write expected report file")

		t.Logf("Updated expected file: %s", expectedFilePath)
		return
	}

	// Normal comparison mode
	expectedReportBytes, err := os.ReadFile(expectedFilePath)
	assert.NoError(t, err, "failed to read expected report file")

	var expectedReport map[string]any
	err = json.Unmarshal(expectedReportBytes, &expectedReport)
	assert.NoError(t, err, "failed to unmarshal expected report JSON")

	// Normalize expected report
	normalizedExpectedReport, err := utils.NormalizeReportData(expectedReport)
	assert.NoError(t, err, "Failed to normalize expected report")

	assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
}
