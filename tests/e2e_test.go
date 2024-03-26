package tests

import "testing"

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
