package plugins

import (
	"errors"
	"fmt"
	"github.com/gitleaks/go-gitdiff/gitdiff"
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
			name:            "Default: scan every commit from checked in branch",
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
			name:            "scan the last 10 commits from checked in branch",
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

func TestGetGitStartAndEndLine(t *testing.T) {
	tests := []struct {
		name                  string
		gitInfo               *GitInfo
		localStartLine        int
		localEndLine          int
		expectedFileStartLine int
		expectedFileEndLine   int
	}{
		{
			name: "Secret in added content without context lines",
			gitInfo: &GitInfo{
				Hunks: []*gitdiff.TextFragment{
					{
						OldPosition:  9,
						OldLines:     0,
						NewPosition:  10,
						NewLines:     3,
						LinesAdded:   3,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  49,
						OldLines:     0,
						NewPosition:  53,
						NewLines:     3,
						LinesAdded:   3,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  55,
						OldLines:     0,
						NewPosition:  62,
						NewLines:     2,
						LinesAdded:   2,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  58,
						OldLines:     0,
						NewPosition:  67,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  103,
						OldLines:     11,
						NewPosition:  112,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 11,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
				},
				ContentType: AddedContent,
			},
			localStartLine:        9,
			localEndLine:          9,
			expectedFileStartLine: 112,
			expectedFileEndLine:   112,
		},
		{
			name: "Secret in removed content without context lines",
			gitInfo: &GitInfo{
				Hunks: []*gitdiff.TextFragment{
					{
						OldPosition:  10,
						OldLines:     2,
						NewPosition:  10,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 2,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  29,
						OldLines:     0,
						NewPosition:  29,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  46,
						OldLines:     8,
						NewPosition:  46,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 8,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  57,
						OldLines:     2,
						NewPosition:  50,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 2,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  63,
						OldLines:     2,
						NewPosition:  55,
						NewLines:     2,
						LinesAdded:   2,
						LinesDeleted: 2,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  106,
						OldLines:     0,
						NewPosition:  99,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  108,
						OldLines:     8,
						NewPosition:  101,
						NewLines:     3,
						LinesAdded:   3,
						LinesDeleted: 8,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
				},
				ContentType: RemovedContent,
			},
			localStartLine:        18,
			localEndLine:          18,
			expectedFileStartLine: 112,
			expectedFileEndLine:   112,
		},
		{
			name: "Secret in added content with context lines",
			gitInfo: &GitInfo{
				Hunks: []*gitdiff.TextFragment{
					{
						OldPosition:  7,
						OldLines:     8,
						NewPosition:  7,
						NewLines:     7,
						LinesAdded:   1,
						LinesDeleted: 2,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
						},
					},
					{
						OldPosition:  27,
						OldLines:     6,
						NewPosition:  26,
						NewLines:     7,
						LinesAdded:   1,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
						},
					},
				},
				ContentType: AddedContent,
			},
			localStartLine:        1,
			localEndLine:          1,
			expectedFileStartLine: 29,
			expectedFileEndLine:   29,
		},
		{
			name: "Secret in removed content with context lines",
			gitInfo: &GitInfo{
				Hunks: []*gitdiff.TextFragment{
					{
						OldPosition:  475,
						OldLines:     8,
						NewPosition:  475,
						NewLines:     8,
						LinesAdded:   2,
						LinesDeleted: 2,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
						},
					},
					{
						OldPosition:  512,
						OldLines:     8,
						NewPosition:  512,
						NewLines:     8,
						LinesAdded:   2,
						LinesDeleted: 2,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
							{
								Op: gitdiff.OpContext,
							},
						},
					},
				},
				ContentType: RemovedContent,
			},
			localStartLine:        3,
			localEndLine:          3,
			expectedFileStartLine: 516,
			expectedFileEndLine:   516,
		},
		{
			name: "validate skip hunk when secret is found immediately after the hunk before in added content",
			gitInfo: &GitInfo{
				Hunks: []*gitdiff.TextFragment{
					{
						OldPosition:  975,
						OldLines:     0,
						NewPosition:  976,
						NewLines:     3,
						LinesAdded:   3,
						LinesDeleted: 0,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
					{
						OldPosition:  977,
						OldLines:     4,
						NewPosition:  980,
						NewLines:     1,
						LinesAdded:   1,
						LinesDeleted: 4,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
				},
				ContentType: AddedContent,
			},
			localStartLine:        3,
			localEndLine:          3,
			expectedFileStartLine: 980,
			expectedFileEndLine:   980,
		},
		{
			name: "validate skip hunk when secret is found immediately after the hunk before in removed content",
			gitInfo: &GitInfo{
				Hunks: []*gitdiff.TextFragment{
					{
						OldPosition:  976,
						OldLines:     3,
						NewPosition:  975,
						NewLines:     0,
						LinesAdded:   0,
						LinesDeleted: 3,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpDelete,
							},
						},
					},
					{
						OldPosition:  980,
						OldLines:     1,
						NewPosition:  977,
						NewLines:     4,
						LinesAdded:   4,
						LinesDeleted: 1,
						Lines: []gitdiff.Line{
							{
								Op: gitdiff.OpDelete,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
							{
								Op: gitdiff.OpAdd,
							},
						},
					},
				},
				ContentType: RemovedContent,
			},
			localStartLine:        3,
			localEndLine:          3,
			expectedFileStartLine: 980,
			expectedFileEndLine:   980,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualFileStartLine, actualFileEndLine := GetGitStartAndEndLine(tt.gitInfo, tt.localStartLine, tt.localEndLine)
			assert.Equal(t, tt.expectedFileStartLine, actualFileStartLine)
			assert.Equal(t, tt.expectedFileEndLine, actualFileEndLine)
		})
	}
}
