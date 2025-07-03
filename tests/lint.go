package tests

import (
	"os"
	"path/filepath"
	"regexp"
)

var ignoreComment = regexp.MustCompile(`//\s*lint:ignore`) //nolint:unused

func walkGoFiles() <-chan string { //nolint:unused
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
