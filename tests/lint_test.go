package tests

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
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

func lintFile(path string) error { //nolint:unused
	if ignoreFiles.MatchString(path) {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck

	scanner := bufio.NewScanner(file)
	line := 1
	for scanner.Scan() {
		lineText := scanner.Text()
		for _, forbiddenPattern := range forbiddenPatterns {
			if forbiddenPattern.MatchString(lineText) && !ignoreComment.MatchString(lineText) {
				return fmt.Errorf("%s:%d: forbidden pattern found: %s", path, line, forbiddenPattern.String())
			}
		}
		line++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

var ignoreFiles = regexp.MustCompile(`_test\.go$`) //nolint:unused

var forbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`fmt\.Print`),
	regexp.MustCompile(`log\.Fatal\(\)`),
}
