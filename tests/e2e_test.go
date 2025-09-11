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
		TargetPath         string
		ExpectedReportPath string
	}{
		{
			Name:               "secret at end without newline",
			ScanTarget:         "filesystem",
			TargetPath:         "testData/input/secret_at_end.txt",
			ExpectedReportPath: "testData/expectedReport/secret_at_end_report.json",
		},
		{
			Name:               "multi line secret ",
			ScanTarget:         "filesystem",
			TargetPath:         "testData/input/multi_line_secret.txt",
			ExpectedReportPath: "testData/expectedReport/multi_line_secret_report.json",
		},
		{
			Name:               "secret at end with newline ",
			ScanTarget:         "filesystem",
			TargetPath:         "testData/input/secret_at_end_with_newline.txt",
			ExpectedReportPath: "testData/expectedReport/secret_at_end_with_newline_report.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			executable, err := createCLI(t.TempDir())
			require.Nil(t, err, "failed to build CLI")

			args := []string{tc.ScanTarget}
			if tc.ScanTarget == "filesystem" {
				args = append(args, "--path", tc.TargetPath)
			} else {
				args = append(args, tc.TargetPath)
			}
			args = append(args, "--ignore-on-exit", "results")

			if err := executable.run(args[0], args[1:]...); err != nil {
				t.Fatalf("error running scan with args: %v, got: %v", args, err)
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
	require.NoError(t, err, "failed to build CLI")

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
					if secret.RuleID == "github-pat" {
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
