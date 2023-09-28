package tests

import (
	"testing"
)

func TestLintIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	for path := range walkGoFiles() {
		if err := lintFile(path); err != nil {
			t.Errorf("lint error: %s", err)
		}
	}
}
