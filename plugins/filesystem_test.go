package plugins

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGetItem(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "TestGetItem")
	assert.NoError(t, err, "failed to create temp file")
	defer func(name string) {
		err := os.Remove(name)
		assert.NoError(t, err, "failed to remove temp file")
	}(tmpFile.Name())

	err = tmpFile.Close()
	assert.NoError(t, err, "failed to close temp file")

	plugin := &FileSystemPlugin{
		ProjectName: "TestProject",
	}

	it, err := plugin.getItem(tmpFile.Name())
	assert.NoError(t, err, "getItem returned an error")

	expectedID := fmt.Sprintf("%s-%s-%s", plugin.GetName(), plugin.ProjectName, tmpFile.Name())
	assert.Equal(t, expectedID, it.ID, "ID should match the expected format")
}

func TestGetItems(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "TestGetItems")
	assert.NoError(t, err, "failed to create temporary file")
	defer func(name string) {
		err := os.Remove(name)
		assert.NoError(t, err, "failed to remove temp file")
	}(tmpFile.Name())

	validContent := "valid mock content"
	_, err = tmpFile.WriteString(validContent)
	assert.NoError(t, err, "failed to write to temporary file")

	err = tmpFile.Close()
	assert.NoError(t, err, "failed to close temporary file")

	validFile := tmpFile.Name()
	fileList := []string{validFile}

	itemsChan := make(chan ISourceItem, len(fileList))
	errsChan := make(chan error, len(fileList))
	var wg sync.WaitGroup

	plugin := &FileSystemPlugin{
		ProjectName: "TestProject",
	}

	plugin.GetItems(itemsChan, errsChan, &wg, fileList)

	wg.Wait()

	close(itemsChan)
	close(errsChan)

	var items []ISourceItem
	for itm := range itemsChan {
		items = append(items, itm)
	}

	assert.Equal(t, 1, len(items), "should have one valid item")
	_, ok := items[0].(item)
	assert.True(t, ok, "item should be of type item")
}

func TestGetFiles(t *testing.T) {
	tests := []struct {
		name        string
		nonExistent bool
		setup       func(t *testing.T, baseDir string) (ignoredPatterns []string, expectedFiles []string, expectedErrCount int)
	}{
		{
			name:        "All valid files",
			nonExistent: false,
			setup: func(t *testing.T, baseDir string) ([]string, []string, int) {
				file1 := filepath.Join(baseDir, "file1.txt")
				err := os.WriteFile(file1, []byte("content1"), 0644)
				assert.NoError(t, err)
				file2 := filepath.Join(baseDir, "file2.txt")
				err = os.WriteFile(file2, []byte("content2"), 0644)
				assert.NoError(t, err)
				return []string{}, []string{file1, file2}, 0
			},
		},
		{
			name:        "Skip empty files",
			nonExistent: false,
			setup: func(t *testing.T, baseDir string) ([]string, []string, int) {
				empty := filepath.Join(baseDir, "empty.txt")
				err := os.WriteFile(empty, []byte(""), 0644)
				assert.NoError(t, err)
				valid := filepath.Join(baseDir, "file.txt")
				err = os.WriteFile(valid, []byte("content"), 0644)
				assert.NoError(t, err)
				return []string{}, []string{valid}, 0
			},
		},
		{
			name:        "Ignore folder via global ignoredFolders",
			nonExistent: false,
			setup: func(t *testing.T, baseDir string) ([]string, []string, int) {
				ignoredDir := filepath.Join(baseDir, "ignoredFolder")
				err := os.Mkdir(ignoredDir, 0755)
				assert.NoError(t, err)

				ignoredFile := filepath.Join(ignoredDir, "file.txt")
				err = os.WriteFile(ignoredFile, []byte("content"), 0644)
				assert.NoError(t, err)

				valid := filepath.Join(baseDir, "file.txt")
				err = os.WriteFile(valid, []byte("content"), 0644)
				assert.NoError(t, err)
				return []string{}, []string{valid}, 0
			},
		},
		{
			name:        "Ignore files by pattern",
			nonExistent: false,
			setup: func(t *testing.T, baseDir string) ([]string, []string, int) {
				ignoreFile := filepath.Join(baseDir, "skip.ignore")
				err := os.WriteFile(ignoreFile, []byte("ignored content"), 0644)
				assert.NoError(t, err)
				valid := filepath.Join(baseDir, "file.txt")
				err = os.WriteFile(valid, []byte("content"), 0644)
				assert.NoError(t, err)
				return []string{"*.ignore"}, []string{valid}, 0
			},
		},
		{
			name:        "Non-existent directory",
			nonExistent: true,
			setup: func(t *testing.T, baseDir string) ([]string, []string, int) {
				return []string{}, []string{}, 1
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var baseDir string
			var err error

			if !tc.nonExistent {
				baseDir, err = os.MkdirTemp("", "testfiles")
				assert.NoError(t, err)
				defer func(path string) {
					err := os.RemoveAll(path)
					assert.NoError(t, err)
				}(baseDir)
			}

			ignoredPatterns, expectedFiles, expectedErrCount := tc.setup(t, baseDir)

			plugin := &FileSystemPlugin{
				ProjectName: "TestProject",
				Path:        baseDir,
				Ignored:     ignoredPatterns,
			}

			itemsChan := make(chan ISourceItem, 10)
			errsChan := make(chan error, 10)
			var wg sync.WaitGroup

			plugin.GetFiles(itemsChan, errsChan, &wg)
			wg.Wait()
			close(itemsChan)
			close(errsChan)

			var collectedFiles []string
			for itm := range itemsChan {
				it, ok := itm.(item)
				assert.True(t, ok, "item should be of type item")
				collectedFiles = append(collectedFiles, it.Source)
			}

			expectedMap := make(map[string]bool)
			for _, f := range expectedFiles {
				expectedMap[f] = true
			}
			for _, f := range collectedFiles {
				delete(expectedMap, f)
			}
			assert.Equal(t, 0, len(expectedMap), "not all expected files were returned")

			var collectedErrs []error
			for e := range errsChan {
				collectedErrs = append(collectedErrs, e)
			}
			assert.Equal(t, expectedErrCount, len(collectedErrs), "unexpected number of errors")
		})
	}
}
