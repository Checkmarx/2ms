package tests

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/checkmarx/2ms/lib/utils"

	"github.com/stretchr/testify/assert"
)

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test")
	}

	executable, err := createCLI(t.TempDir())
	if err != nil {
		t.Fatalf("failed to build CLI: %s", err)
	}

	t.Run("filesystem: one secret found", func(t *testing.T) {
		projectDir := t.TempDir()

		if err := generateFileWithSecret(projectDir, "secret.txt"); err != nil {
			t.Fatalf("failed to generate project: %s", err)
		}

		if err := executable.run("filesystem", "--path", projectDir); err == nil {
			t.Error("expected error (secrets found), got nil")
		}

		report, err := executable.getReport()
		if err != nil {
			t.Fatalf("failed to get report: %s", err)
		}

		if len(report.Results) != 1 {
			t.Errorf("expected one result, got %d", len(report.Results))
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

		if len(report.Results) < 2 {
			t.Errorf("expected at least two results, got %d", len(report.Results))
		}

		for _, result := range report.Results {
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

		if len(report.Results) != 0 {
			t.Errorf("expected no results, got %d", len(report.Results))
		}
	})
}

func TestSecretsEdgeCases(t *testing.T) {
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
			Name:               "secret at end ",
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
			if err != nil {
				t.Fatalf("failed to build CLI: %s", err)
			}

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
			if err != nil {
				t.Fatalf("failed to get report: %s", err)
			}

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

			if err != nil {
				t.Fatalf("Failed to normalize expected report: %v", err)
			}

			normalizedActualReport, err := utils.NormalizeReportData(actualReportMap)
			if err != nil {
				t.Fatalf("Failed to normalize actual report: %v", err)
			}

			assert.EqualValuesf(t, normalizedExpectedReport, normalizedActualReport, "Test Fail")

		})
	}
}
