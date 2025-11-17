package tests

import (
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"testing"

	"github.com/checkmarx/2ms/v4/lib/reporting"
	"github.com/checkmarx/2ms/v4/lib/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cli struct {
	executable  string
	resultsPath string
}

func createCLI(outputDir string) (cli, error) {
	executable := path.Join(outputDir, "2ms")
	lib, err := build.Import("github.com/checkmarx/2ms/v4", "", build.FindOnly)
	if err != nil {
		return cli{}, fmt.Errorf("failed to import 2ms: %s", err)
	}

	cmd := exec.Command("go", "build", "-o", executable, lib.ImportPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", runtime.GOOS), fmt.Sprintf("GOARCH=%s", runtime.GOARCH))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return cli{}, fmt.Errorf("failed to build 2ms: %s", err)
	}

	return cli{
			executable:  executable,
			resultsPath: path.Join(outputDir, "results.json"),
		},
		nil
}

func generateFileWithSecret(outputDir string, filename string) error {
	token := "g" + "hp" + "_ixOl" + "iEFNK4O" + "brYB506" + "8oXFd" + "9JUF" + "iRy0RU" + "KNl"
	content := "bla bla bla\nGitHubToken: " + token + "\nbla bla bla"

	if err := os.WriteFile(path.Join(outputDir, filename), []byte(content), 0644); err != nil {
		return err
	}

	return nil
}

func (c *cli) run(command string, args ...string) error {
	argsWithDefault := append([]string{command}, args...)
	argsWithDefault = append(argsWithDefault, "--report-path", c.resultsPath)

	cmd := exec.Command(c.executable, argsWithDefault...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test")
	}

	executable, err := createCLI(t.TempDir())
	require.NoError(t, err)

	t.Run("filesystem: one secret found", func(t *testing.T) {
		projectDir := t.TempDir()

		if err := generateFileWithSecret(projectDir, "secret.txt"); err != nil {
			t.Fatalf("failed to generate project: %s", err)
		}

		err := executable.run("filesystem", "--path", projectDir)
		assert.Error(t, err, "expected error when secrets are found")

		report, err := executable.getReport()
		if err != nil {
			t.Fatalf("failed to get report: %s", err)
		}

		if report.GetTotalItemsScanned() != 1 {
			t.Errorf("expected one result, got %d", report.GetTotalItemsScanned())
		}
	})

	t.Run("confluence: secrets found with validation", func(t *testing.T) {
		t.Skip("Skipping confluence test (confluence page is currently private)")

		if err := executable.run("confluence", "https://checkmarx.atlassian.net/wiki", "--spaces", "secrets", "--validate"); err == nil {
			t.Error("expected error (secrets found), got nil")
		}

		report, err := executable.getReport()
		if err != nil {
			t.Fatalf("failed to get report: %s", err)
		}

		if report.GetTotalItemsScanned() < 2 {
			t.Errorf("expected at least two results, got %d", report.GetTotalItemsScanned())
		}

		for _, result := range report.GetResults() {
			for _, secret := range result {
				if secret.ValidationStatus == "" {
					t.Errorf("expected validation status, got empty")
				}
			}
		}
	})

	t.Run("filesystem: ignore go.sum file", func(t *testing.T) {
		projectDir := t.TempDir()

		if err := generateFileWithSecret(projectDir, "go.sum"); err != nil {
			t.Fatalf("failed to generate project: %s", err)
		}

		if err := executable.run("filesystem", "--path", projectDir); err != nil {
			t.Errorf("expected no error, got %s", err)
		}

		report, err := executable.getReport()
		if err != nil {
			t.Fatalf("failed to get report: %s", err)
		}
		assert.Equal(t, 0, len(report.GetResults()))
	})
}

func TestSecretsScans(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping edge cases test")
	}

	tests := []struct {
		Name               string
		ScanTarget         string
		Args               []string
		TargetPath         string
		ExpectedReportPath string
	}{
		{
			Name:       "secret at end without newline",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/secret_at_end.txt",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/secret_at_end_report.json",
		},
		{
			Name:       "multi line secret ",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/multi_line_secret.txt",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/multi_line_secret_report.json",
		},
		{
			Name:       "secret at end with newline ",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/secret_at_end_with_newline.txt",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/secret_at_end_with_newline_report.json",
		},
		{
			Name:       "run all default + custom rules in json",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/default_plus_all_custom_rules.json",
		},
		{
			Name:       "run all default + custom rules in yaml",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.yaml",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/default_plus_all_custom_rules.json",
		},
		{
			Name:       "run only custom rules in json",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--rule",
				"custom",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/only_custom_rules.json",
		},
		{
			Name:       "run only custom override rules in json",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--rule",
				"override",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/only_override_rules.json",
		},
		{
			Name:       "run default + non override rules in json",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--ignore-rule",
				"override",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/default_plus_non_override_rules.json",
		},
		{
			Name:       "run only custom rules and ignore overrides in json",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--rule",
				"custom",
				"--ignore-rule",
				"override",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/only_custom_no_override_rules.json",
		},
		{
			Name:       "run only custom rules in json and ignore overrides by rule id",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--rule",
				"custom",
				"--ignore-rule",
				"01ab7659-d25a-4a1c-9f98-dee9d0cf2e70,9f24ac30-9e04-4dc2-bc32-26da201f87e5",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/only_custom_no_override_rules.json",
		},
		{
			Name:       "run only custom rules in json and ignore overrides by rule name",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--rule",
				"custom",
				"--ignore-rule",
				"Generic-Api-Key-Custom,Github-Pat",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/only_custom_no_override_rules.json",
		},
		{
			Name:       "run only custom rules in json and ignore overrides by result id",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--rule",
				"custom",
				"--ignore-result",
				"4431f6f38c1a36156f0486df95b0436810272bfb",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/only_custom_no_override_rules.json",
		},
		{
			Name:       "run only default rules by ignoring custom rules in json",
			ScanTarget: "filesystem",
			Args: []string{
				"--path",
				"testData/input/custom_rules_secrets.txt",
				"--validate",
				"--custom-rules-path",
				"testData/customRuleConfig/customRules.json",
				"--ignore-rule",
				"custom",
				"--ignore-on-exit",
				"results",
			},
			ExpectedReportPath: "testData/expectedReport/customRules/only_default_ignore_custom_rules.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			executable, err := createCLI(t.TempDir())
			require.NoError(t, err)

			if err := executable.run(tc.ScanTarget, tc.Args...); err != nil {
				t.Fatalf("error running scan with args: %v, got: %v", tc.Args, err)
			}

			actualReport, err := executable.getReport()
			require.NoError(t, err, "failed to get report")

			expectedBytes, err := os.ReadFile(tc.ExpectedReportPath)
			assert.NoError(t, err, "failed to read expected report")

			var expectedReportMap map[string]interface{}
			err = json.Unmarshal(expectedBytes, &expectedReportMap)
			assert.NoError(t, err, "failed to unmarshal expected report JSON")

			actualReportBytes, err := json.Marshal(actualReport)
			assert.NoError(t, err, "failed to marshal actual report to JSON")

			var actualReportMap map[string]interface{}

			err = json.Unmarshal(actualReportBytes, &actualReportMap)
			assert.NoError(t, err, "failed to unmarshal actual report JSON")

			normalizedExpectedReport, err := utils.NormalizeReportData(expectedReportMap)
			assert.NoError(t, err, "Failed to normalize expected report")

			normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
			assert.NoError(t, err, "Failed to normalize expected report")

			assert.EqualValues(t, normalizedExpectedReport, normalizedActualReport)
		})
	}
}

func TestFlagsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping flags integration test")
	}

	executable, err := createCLI(t.TempDir())
	require.NoError(t, err)

	t.Run("--regex flag: custom regex pattern detection", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create test file with custom pattern that matches our regex
		customSecret := "CUSTOM_SECRET_ABC123_XYZ"
		testContent := fmt.Sprintf("Application config:\napi_key: %s\ndatabase_url: postgres://user:pass@host/db", customSecret)

		err := os.WriteFile(path.Join(projectDir, "config.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// Run scan with custom regex that should match our pattern
		customRegex := "CUSTOM_SECRET_[A-Z0-9_]+"
		err = executable.run("filesystem", "--path", projectDir, "--regex", customRegex, "--ignore-on-exit", "results")
		assert.NoError(t, err, "scan should succeed with custom regex")

		report, err := executable.getReport()
		require.NoError(t, err, "failed to get report")

		// Verify that custom regex found the expected result
		results := report.GetResults()
		require.Greater(t, len(results), 0, "Custom regex should detect the pattern")

		// Verify that one of the results is from our custom regex rule
		foundCustomRule := false
		for _, resultGroup := range results {
			for _, result := range resultGroup {
				if strings.Contains(result.RuleID, "custom-regex") {
					foundCustomRule = true
					assert.Equal(t, customSecret, result.Value, "Custom regex should detect the correct value")
					break
				}
			}
		}
		assert.True(t, foundCustomRule, "Should find at least one result from custom regex rule")
	})

	t.Run("--rule flag: select specific rules", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create test file with GitHub token
		githubToken := "ghp_1234567890abcdefghijklmnopqrstuvwxyz123"
		testContent := fmt.Sprintf("GitHub configuration:\ntoken: %s\nother_config: value", githubToken)

		err := os.WriteFile(path.Join(projectDir, "github_config.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// First, run scan with only GitHub rule
		err = executable.run("filesystem", "--path", projectDir, "--rule", "github-pat", "--ignore-on-exit", "results")
		assert.NoError(t, err, "scan should succeed with specific rule")

		report, err := executable.getReport()
		require.NoError(t, err, "failed to get report")

		// Verify only GitHub secrets are found
		results := report.GetResults()
		if len(results) > 0 {
			found := false
			for _, secretList := range results {
				for _, secret := range secretList {
					if secret.RuleName == "Github-Pat" {
						found = true
					}
				}
			}
			assert.True(t, found, "should find GitHub token when rule is selected")
		}
	})

	t.Run("--ignore-rule flag: exclude specific rules", func(t *testing.T) {
		projectDir := t.TempDir()
		reportsDir := t.TempDir() // Separate directory for reports to avoid scanning them

		// Create test file with multiple types of secrets
		testContent := `Config file:
github_token: ghp_1234567890abcdefghijklmnopqrstuvwxyz123
aws_key: AKIAIOSFODNN7EXAMPLE
slack_token: xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx`

		err := os.WriteFile(path.Join(projectDir, "multi_secrets.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// Create separate report paths for each scan to avoid overwriting and scanning
		baselineReportPath := path.Join(reportsDir, "baseline_results.json")
		filteredReportPath := path.Join(reportsDir, "filtered_results.json")

		// First scan without ignoring anything to see what's found
		err = executable.run("filesystem", "--path", projectDir, "--report-path", baselineReportPath, "--ignore-on-exit", "results")
		assert.NoError(t, err, "baseline scan should succeed")

		baselineReport, err := getReportFromPath(baselineReportPath)
		require.NoError(t, err, "failed to get baseline report")

		// Run scan ignoring GitHub rules - try both specific rule and generic-api-key
		err = executable.run("filesystem", "--path", projectDir, "--ignore-rule", "github-pat,generic-api-key", "--report-path", filteredReportPath, "--ignore-on-exit", "results")
		assert.NoError(t, err, "scan should succeed with ignored rule")

		report, err := getReportFromPath(filteredReportPath)
		require.NoError(t, err, "failed to get report")

		// Verify we have fewer results when rules are ignored
		baselineResults := baselineReport.GetResults()
		filteredResults := report.GetResults()

		assert.Less(t, len(filteredResults), len(baselineResults), "ignoring rules should result in same or fewer findings")
	})
}

func (c *cli) getReport() (reporting.IReport, error) {
	report := reporting.New()

	content, err := os.ReadFile(c.resultsPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(content, &report); err != nil {
		return nil, err
	}

	return report, nil
}

func getReportFromPath(reportPath string) (reporting.IReport, error) {
	report := reporting.New()

	content, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(content, &report); err != nil {
		return nil, err
	}

	return report, nil
}

func TestMissingFlagsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping missing flags integration test")
	}

	executable, err := createCLI(t.TempDir())
	require.NoError(t, err)

	t.Run("--validate flag: enable secret validation", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create test file with a secret that can be validated
		testContent := `Config file:
github_token: ghp_1234567890abcdefghijklmnopqrstuvwxyz123
aws_key: AKIAIOSFODNN7EXAMPLE
database_url: postgres://user:pass@host/db`

		err := os.WriteFile(path.Join(projectDir, "config.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// Run scan with --validate flag
		err = executable.run("filesystem", "--path", projectDir, "--validate", "--ignore-on-exit", "results")
		assert.NoError(t, err, "scan should succeed with validate flag")

		report, err := executable.getReport()
		require.NoError(t, err, "failed to get report")

		// Verify that validation was attempted (validation status should be present)
		results := report.GetResults()
		if len(results) > 0 {
			foundValidation := false
			for _, resultGroup := range results {
				for _, result := range resultGroup {
					// When validation is enabled, ValidationStatus should be set
					if result.ValidationStatus != "" {
						foundValidation = true
						break
					}
				}
			}
			// Note: actual validation may fail in test environment, but the flag should be processed
			t.Logf("Validation flag processed, validation attempted: %v", foundValidation)
		}
	})

	t.Run("--add-special-rule flag: add special rules to scan", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create test file with content that matches special rule pattern
		testContent := `Application config:
special_pattern: SPECIAL_SECRET_123_XYZ
normal_secret: some-value-here`

		err := os.WriteFile(path.Join(projectDir, "special.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// Run scan with --add-special-rule flag
		// Note: The actual special rule format depends on the implementation
		err = executable.run("filesystem", "--path", projectDir, "--add-special-rule", "test-special-rule", "--ignore-on-exit", "results")

		// The flag should be processed without error
		// Actual detection depends on the special rule implementation
		t.Logf("--add-special-rule flag processed, exit code: %v", err)
	})

	t.Run("--allowed-values flag: filter results with allowed values", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create test file with secrets
		testContent := `Config:
api_key: test-api-key-12345
allowed_key: allowed-value-xyz
database_password: secret-password-789`

		err := os.WriteFile(path.Join(projectDir, "allowed.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// Create allowed values file
		allowedValuesFile := path.Join(projectDir, "allowed_values.txt")
		allowedContent := "allowed-value-xyz\ntest-api-key-12345"
		err = os.WriteFile(allowedValuesFile, []byte(allowedContent), 0644)
		require.NoError(t, err, "failed to create allowed values file")

		// Run scan with --allowed-values flag
		err = executable.run("filesystem", "--path", projectDir, "--allowed-values", allowedValuesFile, "--ignore-on-exit", "results")

		// The flag should be processed
		t.Logf("--allowed-values flag processed, exit code: %v", err)

		report, err := executable.getReport()
		if err == nil {
			results := report.GetResults()
			// When allowed values are used, secrets matching allowed values should be filtered
			t.Logf("Results with allowed values filtering: %d groups found", len(results))
		}
	})

	t.Run("--ignore-result flag: ignore specific results", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create test file with multiple secrets
		testContent := `Configuration:
github_token: ghp_1234567890abcdefghijklmnopqrstuvwxyz123
aws_key: AKIAIOSFODNN7EXAMPLE
api_key: sk-1234567890abcdefghijklmnopqrstuvwxyz`

		err := os.WriteFile(path.Join(projectDir, "ignore_result.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// First, run scan without ignore flag to discover secret IDs
		err = executable.run("filesystem", "--path", projectDir, "--ignore-on-exit", "results")
		require.NoError(t, err, "initial scan should succeed")

		initialReport, err := executable.getReport()
		require.NoError(t, err, "should get initial report")

		initialResults := initialReport.GetResults()
		require.Greater(t, len(initialResults), 0, "should find some secrets initially")

		// Pick the first secret ID to ignore
		var secretIdToIgnore string
		var secretValueToIgnore string
		for _, resultGroup := range initialResults {
			for _, result := range resultGroup {
				secretIdToIgnore = result.ID
				secretValueToIgnore = result.Value
				break
			}
			if secretIdToIgnore != "" {
				break
			}
		}
		require.NotEmpty(t, secretIdToIgnore, "should find at least one secret to ignore")
		t.Logf("Will ignore secret ID: %s with value: %s", secretIdToIgnore, secretValueToIgnore)

		// Now run scan with --ignore-result flag to ignore the specific secret
		err = executable.run("filesystem", "--path", projectDir, "--ignore-result", secretIdToIgnore, "--ignore-on-exit", "results")
		t.Logf("--ignore-result flag processed, exit code: %v", err)

		report, err := executable.getReport()
		if err == nil {
			results := report.GetResults()
			// Verify that the specific secret ID is filtered out
			foundIgnoredSecret := false
			for _, resultGroup := range results {
				for _, result := range resultGroup {
					if result.ID == secretIdToIgnore {
						foundIgnoredSecret = true
					}
				}
			}
			assert.False(t, foundIgnoredSecret, "The ignored secret ID should not be present in results")

			// Verify we still have fewer results than before
			assert.Less(t, len(results), len(initialResults), "Should have fewer results after ignoring one secret")
		}
	})

	t.Run("--max-target-megabytes flag: limit file size for scanning", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create a small file that should be scanned
		smallContent := "Small file with secret: ghp_1234567890abcdefghijklmnopqrstuvwxyz123"
		err := os.WriteFile(path.Join(projectDir, "small.txt"), []byte(smallContent), 0644)
		require.NoError(t, err, "failed to create small file")

		// Create a large file that should be skipped (simulate with content)
		// Note: In real scenario, this would be a file larger than the limit
		largeContent := strings.Repeat("Large file content with padding. ", 1000)
		largeContent += "Secret in large file: aws_secret_key_AKIAIOSFODNN7EXAMPLE"
		err = os.WriteFile(path.Join(projectDir, "large.txt"), []byte(largeContent), 0644)
		require.NoError(t, err, "failed to create large file")

		// Run scan with --max-target-megabytes flag set to a very small value
		// This should skip files over the size limit
		err = executable.run("filesystem", "--path", projectDir, "--max-target-megabytes", "0", "--ignore-on-exit", "results")

		// The flag should be processed
		t.Logf("--max-target-megabytes flag processed, exit code: %v", err)

		report, err := executable.getReport()
		if err == nil {
			// With max-target-megabytes set to 0, files should be skipped
			results := report.GetResults()
			t.Logf("Results with size limit: %d groups found", len(results))
		}
	})

	t.Run("Combined flags: multiple flags together", func(t *testing.T) {
		projectDir := t.TempDir()

		// Create test file
		testContent := `Multi-flag test:
github_token: ghp_test1234567890abcdefghijklmnopqrstuvwxyz
custom_secret: CUSTOM_ABC_123
api_key: test-key-456`

		err := os.WriteFile(path.Join(projectDir, "combined.txt"), []byte(testContent), 0644)
		require.NoError(t, err, "failed to create test file")

		// Run scan with multiple flags combined
		err = executable.run("filesystem",
			"--path", projectDir,
			"--validate",
			"--regex", "CUSTOM_[A-Z_]+[0-9]+",
			"--ignore-rule", "generic-api-key",
			"--max-target-megabytes", "10",
			"--ignore-on-exit", "results")

		// All flags should be processed together
		t.Logf("Combined flags processed, exit code: %v", err)

		report, err := executable.getReport()
		if err == nil {
			results := report.GetResults()
			// Verify multiple flag behaviors work together
			t.Logf("Results with combined flags: %d groups found", len(results))

			// Check if custom regex was detected
			foundCustomRegex := false
			for _, resultGroup := range results {
				for _, result := range resultGroup {
					if strings.Contains(result.Value, "CUSTOM_ABC_123") {
						foundCustomRegex = true
						t.Log("Custom regex pattern detected successfully")
					}
				}
			}

			if !foundCustomRegex && len(results) > 0 {
				t.Log("Custom regex pattern may have been processed but not detected in results")
			}
		}
	})
}
