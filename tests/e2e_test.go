package tests

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/checkmarx/2ms/lib/reporting"
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
			Name:               "secret at end without newline (filesystem)",
			ScanTarget:         "filesystem",
			TargetPath:         "testData/input/secret_at_end.txt",
			ExpectedReportPath: "testData/expectedReport/report1.json",
		},
		{
			Name:               "secret at end with multiLine (filesystem)",
			ScanTarget:         "filesystem",
			TargetPath:         "testData/input/multi_line_secret.txt",
			ExpectedReportPath: "testData/expectedReport/report2.json",
		},
		{
			Name:               "secret at end with backspace in newline (filesystem)",
			ScanTarget:         "filesystem",
			TargetPath:         "testData/input/secret_at_end_with_newline.txt",
			ExpectedReportPath: "testData/expectedReport/report3.json",
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
			if err != nil {
				t.Fatalf("failed to read expected report: %s", err)
			}
			var expectedReport reporting.Report
			if err := json.Unmarshal(expectedBytes, &expectedReport); err != nil {
				t.Fatalf("failed to unmarshal expected report: %s", err)
			}

			assert.EqualValuesf(t, expectedReport, actualReport, "Test Fail")

		})
	}
}
