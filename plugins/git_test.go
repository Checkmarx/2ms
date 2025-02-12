package plugins

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildScanOptions(t *testing.T) {
	tests := []struct {
		name            string
		scanAllBranches bool
		depth           int
		expectedOptions string
	}{
		{
			name:            "Default: scan every commit from branch",
			scanAllBranches: false,
			depth:           0,
			expectedOptions: "--full-history",
		},
		{
			name:            "Scan all commits from all branches",
			scanAllBranches: true,
			depth:           0,
			expectedOptions: "--full-history --all",
		},
		{
			name:            "scan the last 10 commits from branch",
			scanAllBranches: false,
			depth:           10,
			expectedOptions: "--full-history -n 10",
		},
		{
			name:            "Scan the last 10 commits of all branches",
			scanAllBranches: true,
			depth:           10,
			expectedOptions: "--full-history --all -n 10",
		},
		{
			name:            "Negative depth: should not include depth option",
			scanAllBranches: true,
			depth:           -5,
			expectedOptions: "--full-history --all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &GitPlugin{
				scanAllBranches: tt.scanAllBranches,
				depth:           tt.depth,
			}
			result := p.buildScanOptions()
			assert.Equal(t, tt.expectedOptions, result)
		})
	}
}

func TestValidGitRepoArgs(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (string, error)
		expectedErr error
	}{
		{
			name: "Valid Git Repository",
			setup: func() (string, error) {
				tempDir, err := os.MkdirTemp("", "valid-repo-")
				if err != nil {
					return "", err
				}
				gitDir := filepath.Join(tempDir, ".git")
				if err = os.Mkdir(gitDir, 0500); err != nil {
					return "", err
				}
				return tempDir, nil
			},
			expectedErr: nil,
		},
		{
			name: "Path Does Not Exist",
			setup: func() (string, error) {
				return "/non/existent/path", nil
			},
			expectedErr: os.ErrNotExist,
		},
		{
			name: "Path Is Not a Directory",
			setup: func() (string, error) {
				tempFile, err := os.CreateTemp("", "not-a-dir-")
				if err != nil {
					return "", err
				}
				if err = os.Chmod(tempFile.Name(), 0400); err != nil {
					return "", err
				}
				err = tempFile.Close()
				assert.NoError(t, err)
				return tempFile.Name(), nil
			},
			expectedErr: fmt.Errorf("is not a directory"),
		},
		{
			name: "Missing .git Directory",
			setup: func() (string, error) {
				tempDir, err := os.MkdirTemp("", "no-git-dir-")
				if err != nil {
					return "", err
				}
				return tempDir, nil
			},
			expectedErr: fmt.Errorf("is not a git repository. Please make sure the root path of the provided directory contains a .git subdirectory"),
		},
		{
			name: ".git Is Not a Directory",
			setup: func() (string, error) {
				tempDir, err := os.MkdirTemp("", "git-not-dir-")
				if err != nil {
					return "", err
				}
				gitFile, err := os.Create(filepath.Join(tempDir, ".git"))
				if err != nil {
					return "", err
				}
				if err = os.Chmod(gitFile.Name(), 0400); err != nil {
					return "", err
				}
				err = gitFile.Close()
				assert.NoError(t, err)
				return tempDir, nil
			},
			expectedErr: fmt.Errorf("is not a git repository"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := tt.setup()
			assert.NoError(t, err, "Setup failed")
			defer func(path string) {
				err = os.RemoveAll(path)
				assert.NoError(t, err)
			}(path)

			cmd := &cobra.Command{}
			args := []string{path}

			err = validGitRepoArgs(cmd, args)
			if tt.expectedErr == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				if errors.Is(err, os.ErrNotExist) {
					assert.True(t, os.IsNotExist(err))
				} else {
					assert.Contains(t, err.Error(), tt.expectedErr.Error())
				}
			}
		})
	}
}
