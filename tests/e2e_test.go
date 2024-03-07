package tests

import "testing"

func TestFilesystemIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test")
	}

	executable, err := createCLI(t.TempDir())
	if err != nil {
		t.Fatalf("failed to build CLI: %s", err)
	}

	projectDir := t.TempDir()

	t.Run("one secret found", func(t *testing.T) {
		if err := generateProject(projectDir); err != nil {
			t.Fatalf("failed to generate project: %s", err)
		}

		if err := executable.run("filesystem", "--path", projectDir); err == nil {
			t.Error("expected error, got nil")
		}

		report, err := executable.getReport()
		if err != nil {
			t.Fatalf("failed to get report: %s", err)
		}

		if len(report.Results) != 1 {
			t.Errorf("expected one result, got %d", len(report.Results))
		}
	})
}
