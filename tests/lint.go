package tests

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var ignoreComment = regexp.MustCompile(`//\s*lint:ignore`)

func walkGoFiles() <-chan string {
	ignoredDirs := []string{
		".git",
		".github",
		".vscode",
		"vendor",
		"tests",
		".ci",
	}

	ch := make(chan string)

	go func() {
		defer close(ch)
		err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if filepath.Ext(path) == ".go" {
				ch <- path
			}

			if info.IsDir() {
				for _, ignoredDir := range ignoredDirs {
					if info.Name() == ignoredDir {
						return filepath.SkipDir
					}
				}
			}
			return nil
		})

		if err != nil {
			panic(err)
		}
	}()

	return ch
}

var forbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`fmt\.Print`),
	regexp.MustCompile(`log\.Fatal\(\)`),
}

var ignoreFiles = regexp.MustCompile(`_test\.go$`)

func lintFile(path string) error {
	if ignoreFiles.MatchString(path) {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

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
