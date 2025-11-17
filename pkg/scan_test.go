package scanner

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/checkmarx/2ms/v4/lib/reporting"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/checkmarx/2ms/v4/lib/utils"
	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/stretchr/testify/assert"
)

const (
	githubPatPath                              = "testData/secrets/github-pat.txt"
	jwtPath                                    = "testData/secrets/jwt.txt"
	genericKeysPath                            = "testData/secrets/generic-api-keys.txt"
	expectedReportPath                         = "testData/expectedReports/expectedReport.json"
	expectedReportWithValidationPath           = "testData/expectedReports/expectedReportWithValidation.json"
	expectedReportResultsIgnoredResultsPath    = "testData/expectedReports/expectedReportWithIgnoredResults.json"
	expectedReportResultsIgnoredRulePath       = "testData/expectedReports/expectedReportWithIgnoredRule.json"
	expectedReportDefaultPlusAllCustomRules    = "testData/expectedReports/customRules/defaultPlusAllCustomRules.json"
	expectedReportOnlyCustomRules              = "testData/expectedReports/customRules/onlyCustomRules.json"
	expectedReportOnlyOverrideRules            = "testData/expectedReports/customRules/onlyOverrideRules.json"
	expectedReportDefaultPlusNonOverridesRules = "testData/expectedReports/customRules/defaultPlusNonOverrideRules.json"
	expectedReportOnlyCustomNoOverrideRules    = "testData/expectedReports/customRules/onlyCustomNoOverrideRules.json"
	expectedReportOnlyDefaultIgnoreCustomRules = "testData/expectedReports/customRules/onlyDefaultIgnoreCustomRules.json"
)

// Flag to update expected output files instead of comparing against them
var updateExpected = flag.Bool("update-test-data", false, "Update expected test output files instead of comparing against them")

// Rules to be used to test custom rules. Rules will be selected and ignored depending on the test case
var customRules = []*ruledefine.Rule{
	{
		RuleID:      "01ab7659-d25a-4a1c-9f98-dee9d0cf2e70",
		RuleName:    "Generic-Api-Key-Custom",
		Description: "Custom Generic Api Key override, should override the default one (very specific regex just for testing purposes)",
		Regex:       `(?i)\b\w*secret\w*\b\s*:?=\s*["']?([A-Za-z0-9/_+=-]{8,150})["']?`,
		Severity:    "Medium",
		Tags:        []string{"custom", "override"},
		ScoreParameters: ruledefine.ScoreParameters{
			Category: "General",
			RuleType: 4,
		},
	},
	{
		RuleID:      "b47a1995-6572-41bb-b01d-d215b43ab089",
		RuleName:    "Generic-Api-Key-Completely-New",
		Description: "Custom Generic Api key with different ruleId, should be considered different from the default one and should take priority if both rules run",
		Regex:       `(?i)\b\w*secret\w*\b\s*:?=\s*["']?([A-Za-z0-9/_+=-]{8,150})["']?`,
		Severity:    "Low",
		Tags:        []string{"custom"},
		ScoreParameters: ruledefine.ScoreParameters{
			Category: "General",
			RuleType: 4,
		},
	},
	{
		RuleID:      "b47a1995-6572-41bb-b01d-d215b43ab089",
		RuleName:    "Deprecated-Generic-Api-Key-Completely-New",
		Description: "Deprecated Custom Generic Api key with different ruleId, should be ignored regardless of --rule and --ignore-rule flags",
		Regex:       `(?i)\b\w*secret\w*\b\s*:?=\s*["']?([A-Za-z0-9/_+=-]{8,150})["']?`,
		Severity:    "Low",
		Tags:        []string{"custom"},
		Deprecated:  true,
	},
	{
		RuleID:      "16be2682-51ee-44f5-82dc-695f4d1eda45",
		RuleName:    "Mock-Custom-Rule",
		Description: "Rule that checks for a very specific string",
		Regex:       `very_secret_value`,
		Severity:    "Low",
		Tags:        []string{"custom"},
		ScoreParameters: ruledefine.ScoreParameters{
			Category: "General",
			RuleType: 4,
		},
	},
	{
		RuleID:            "9f24ac30-9e04-4dc2-bc32-26da201f87e5",
		RuleName:          "Github-Pat",
		Description:       "Github-Pat with DisableValidation set to true to test if validation is correctly disabled, resulting in Unknown validity instead of Invalid",
		Regex:             `ghp_[0-9a-zA-Z]{36}`,
		Severity:          "Low",
		Tags:              []string{"custom", "override"},
		DisableValidation: true,
		ScoreParameters: ruledefine.ScoreParameters{
			Category: "Development Platform",
			RuleType: 4,
		},
	},
}

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
				"efc9a9ee89f1d732c7321067eb701b9656e91f15",
				"c31705d99e835e4ac7bc3f688bd9558309e056ed",
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

		assert.Equal(t, 0, report.GetTotalItemsScanned())
		assert.Equal(t, 0, report.GetTotalSecretsFound())
		expectedResults := make(map[string][]*secrets.Secret)
		assert.Equal(t, expectedResults, report.GetResults())
		assert.NotNil(t, err)
		assert.Equal(t, "error(s) processing scan items:\nmock processing error 1\nmock processing error 2", err.Error())
	})
	t.Run("scan with scanItems empty", func(t *testing.T) {
		testScanner := NewScanner()
		actualReport, err := testScanner.Scan([]ScanItem{}, resources.ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, 0, actualReport.GetTotalItemsScanned())
		assert.Equal(t, 0, actualReport.GetTotalSecretsFound())
		expectedResults := make(map[string][]*secrets.Secret)
		assert.Equal(t, expectedResults, actualReport.GetResults())
	})
	t.Run("scan with scanItems nil", func(t *testing.T) {
		testScanner := NewScanner()
		actualReport, err := testScanner.Scan(nil, resources.ScanConfig{})
		assert.NoError(t, err, "scanner encountered an error")
		assert.Equal(t, 0, actualReport.GetTotalItemsScanned())
		assert.Equal(t, 0, actualReport.GetTotalSecretsFound())
		expectedResults := make(map[string][]*secrets.Secret)
		assert.Equal(t, expectedResults, actualReport.GetResults())
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
				"efc9a9ee89f1d732c7321067eb701b9656e91f15",
				"c31705d99e835e4ac7bc3f688bd9558309e056ed",
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

func TestScanAndScanDynamicWithCustomRules(t *testing.T) {
	githubPatBytes, err := os.ReadFile(githubPatPath)
	assert.NoError(t, err, "failed to read github-pat file")
	githubPatContent := string(githubPatBytes)

	jwtBytes, err := os.ReadFile(jwtPath)
	assert.NoError(t, err, "failed to read jwt file")
	jwtContent := string(jwtBytes)

	genericKeyBytes, err := os.ReadFile(genericKeysPath)
	assert.NoError(t, err, "failed to read generic-api-key file")
	genericKeysContent := string(genericKeyBytes)

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
		{
			Content: &genericKeysContent,
			ID:      fmt.Sprintf("mock-%s", genericKeysPath),
			Source:  genericKeysPath,
		},
	}

	tests := []struct {
		Name               string
		ScanConfig         resources.ScanConfig
		ScanItems          []ScanItem
		ExpectedReportPath string
		expectErrors       []error
	}{
		{
			Name: "Run all default + custom rules",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportDefaultPlusAllCustomRules,
			expectErrors:       nil,
		},
		{
			Name: "Run only custom rules",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				SelectRules:    []string{"custom"},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportOnlyCustomRules,
			expectErrors:       nil,
		},
		{
			Name: "Run only custom override rules",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				SelectRules:    []string{"override"},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportOnlyOverrideRules,
			expectErrors:       nil,
		},
		{
			Name: "Run default + non override rules",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				IgnoreRules:    []string{"override"},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportDefaultPlusNonOverridesRules,
			expectErrors:       nil,
		},
		{
			Name: "Run only custom rules and ignore overrides",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				SelectRules:    []string{"custom"},
				IgnoreRules:    []string{"override"},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportOnlyCustomNoOverrideRules,
			expectErrors:       nil,
		},
		{
			Name: "Run only default rules by ignoring custom rules",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				IgnoreRules:    []string{"custom"},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportOnlyDefaultIgnoreCustomRules,
			expectErrors:       nil,
		},
		{
			Name: "Run only custom rules by ignoring custom rules by id",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				SelectRules:    []string{"custom"},
				IgnoreRules: []string{
					"01ab7659-d25a-4a1c-9f98-dee9d0cf2e70",
					"9f24ac30-9e04-4dc2-bc32-26da201f87e5",
				},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportOnlyCustomNoOverrideRules,
			expectErrors:       nil,
		},
		{
			Name: "Run only custom rules by ignoring custom rules by name",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				SelectRules:    []string{"custom"},
				IgnoreRules: []string{
					"Generic-Api-Key-Custom",
					"Github-Pat",
				},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportOnlyCustomNoOverrideRules,
			expectErrors:       nil,
		},
		{
			Name: "Run only custom rules by ignoring override result Ids",
			ScanConfig: resources.ScanConfig{
				CustomRules:    customRules,
				WithValidation: true,
				SelectRules:    []string{"custom"},
				IgnoreResultIds: []string{
					"c31705d99e835e4ac7bc3f688bd9558309e056ed",
					"993b789425c810d4956c5ed8c84f02f90b0531ee",
					"63139b45c38f502bbbe15115a7995003d76b2a81",
				},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: expectedReportOnlyCustomNoOverrideRules,
			expectErrors:       nil,
		},
		{
			Name: "Rule name, id, regex missing",
			ScanConfig: resources.ScanConfig{
				CustomRules: []*ruledefine.Rule{
					{
						Description: "Match passwords",
					},
					{
						RuleID:      "b47a1995-6572-41bb-b01d-d215b43ab089",
						RuleName:    "mock-rule2",
						Description: "Match API keys",
						Regex:       "[A-Za-z0-9]{40}",
					},
				},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: "",
			expectErrors: []error{
				fmt.Errorf("rule#0: missing ruleID"),
				fmt.Errorf("rule#0: missing ruleName"),
				fmt.Errorf("rule#0: missing regex"),
			},
		},
		{
			Name: "Regex, severity and score parameters invalid",
			ScanConfig: resources.ScanConfig{
				CustomRules: []*ruledefine.Rule{
					{
						RuleID:      "db18ccf1-4fbf-49f6-aec1-939a2e5464c0",
						RuleName:    "mock-rule",
						Description: "Match passwords",
						Regex:       "[A-Za-z0-9]{32})",
						Severity:    "mockSeverity",
						ScoreParameters: ruledefine.ScoreParameters{
							Category: "mockCategory",
							RuleType: 10,
						},
					},
					{
						RuleID:      "b47a1995-6572-41bb-b01d-d215b43ab089",
						RuleName:    "mock-rule2",
						Description: "Match API keys",
						Regex:       "[A-Za-z0-9]{40}",
					},
				},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: "",
			expectErrors: []error{
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid regex"),
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid severity:" +
					" mockSeverity not one of ([Critical High Medium Low Info])"),
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid category:" +
					" mockCategory not an acceptable category of type RuleCategory"),
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid rule type: 10 not an acceptable uint8 value, maximum is 4"),
			},
		},
		{
			Name: "Rule id missing",
			ScanConfig: resources.ScanConfig{
				CustomRules: []*ruledefine.Rule{
					{
						RuleName:    "mock-rule",
						Description: "Match passwords",
						Regex:       "[A-Za-z0-9]{32})",
					},
					{
						RuleName:    "mock-rule2",
						Description: "Match API keys",
						Regex:       "[A-Za-z0-9]{40}",
					},
				},
			},
			ScanItems:          scanItems,
			ExpectedReportPath: "",
			expectErrors: []error{
				fmt.Errorf("rule#0;RuleName-mock-rule: missing ruleID"),
				fmt.Errorf("rule#1;RuleName-mock-rule2: missing ruleID"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			testScanner := NewScanner()

			// Test scan
			actualReport, err := testScanner.Scan(tc.ScanItems, tc.ScanConfig)

			for _, expectErr := range tc.expectErrors {
				assert.ErrorContains(t, err, expectErr.Error())
			}

			if tc.ExpectedReportPath != "" {
				compareOrUpdateTestData(t, actualReport, tc.ExpectedReportPath)
			}

			// Test scanDynamic
			itemsIn := make(chan ScanItem, len(tc.ScanItems))
			for _, item := range tc.ScanItems {
				itemsIn <- item
			}
			close(itemsIn)

			dynamicActualReport, err := testScanner.ScanDynamic(itemsIn, tc.ScanConfig)

			for _, expectErr := range tc.expectErrors {
				assert.ErrorContains(t, err, expectErr.Error())
			}

			if tc.ExpectedReportPath != "" {
				compareOrUpdateTestData(t, dynamicActualReport, tc.ExpectedReportPath)
			}
		})
	}
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
				"efc9a9ee89f1d732c7321067eb701b9656e91f15",
				"c31705d99e835e4ac7bc3f688bd9558309e056ed",
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
		defaultRules := rules.GetDefaultRules(false)
		var idOfRules []string
		for _, rule := range defaultRules {
			idOfRules = append(idOfRules, rule.RuleName)
		}

		testScanner := NewScanner()

		report, err := testScanner.ScanDynamic(itemsIn, resources.ScanConfig{IgnoreRules: idOfRules})

		assert.Error(t, err)
		assert.ErrorIs(t, err, engine.ErrNoRulesSelected)
		assert.Equal(t, 0, report.GetTotalItemsScanned())
		assert.Equal(t, 0, report.GetTotalSecretsFound())
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
				"efc9a9ee89f1d732c7321067eb701b9656e91f15",
				"c31705d99e835e4ac7bc3f688bd9558309e056ed",
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
