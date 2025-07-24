package tests

import (
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path"
	"runtime"
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

func (c *cli) getReport() (reporting.IReport, error) {
	report := reporting.Init()

	content, err := os.ReadFile(c.resultsPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(content, &report); err != nil {
		return nil, err
	}

	return report, nil
}
