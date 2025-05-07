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
					createMockHunk(9, 0, 10, 3, 3, 0, nil),
					createMockHunk(49, 0, 53, 3, 3, 0, nil),
					createMockHunk(55, 0, 62, 2, 2, 0, nil),
					createMockHunk(58, 0, 67, 1, 1, 0, nil),
					createMockHunk(103, 11, 112, 1, 1, 11, nil),
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
					createMockHunk(10, 2, 10, 1, 1, 2, nil),
					createMockHunk(29, 0, 29, 1, 1, 0, nil),
					createMockHunk(46, 8, 46, 1, 1, 8, nil),
					createMockHunk(57, 2, 50, 1, 1, 2, nil),
					createMockHunk(63, 2, 55, 2, 2, 2, nil),
					createMockHunk(106, 0, 99, 1, 1, 0, nil),
					createMockHunk(108, 8, 101, 3, 3, 8, nil),
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
					createMockHunk(7, 8, 7, 7, 1, 2, []gitdiff.Line{
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
					}),
					createMockHunk(27, 6, 26, 7, 1, 0, []gitdiff.Line{
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
					}),
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
					createMockHunk(475, 8, 475, 8, 2, 2, []gitdiff.Line{
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
					}),
					createMockHunk(512, 8, 512, 8, 2, 2, []gitdiff.Line{
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
					}),
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
					createMockHunk(975, 0, 976, 3, 3, 0, nil),
					createMockHunk(977, 4, 980, 1, 1, 4, nil),
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
					createMockHunk(976, 3, 975, 0, 0, 3, nil),
					createMockHunk(980, 1, 977, 4, 4, 1, nil),
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
			actualFileStartLine, actualFileEndLine, err := GetGitStartAndEndLine(tt.gitInfo, tt.localStartLine, tt.localEndLine)
			if err != nil {
				t.Fatalf("GetGitStartAndEndLine() error = %v", err)
			}
			assert.Equal(t, tt.expectedFileStartLine, actualFileStartLine)
			assert.Equal(t, tt.expectedFileEndLine, actualFileEndLine)
		})
	}
}

func createMockHunk(oldPos, oldLines, newPos, newLines, linesAdded, linesDeleted int64, lines []gitdiff.Line) *gitdiff.TextFragment {
	if lines == nil {
		for i := int64(0); i < linesDeleted; i++ {
			lines = append(lines, gitdiff.Line{Op: gitdiff.OpDelete})
		}
		for i := int64(0); i < linesAdded; i++ {
			lines = append(lines, gitdiff.Line{Op: gitdiff.OpAdd})
		}
	}
	return &gitdiff.TextFragment{
		OldPosition:  oldPos,
		OldLines:     oldLines,
		NewPosition:  newPos,
		NewLines:     newLines,
		LinesAdded:   linesAdded,
		LinesDeleted: linesDeleted,
		Lines:        lines,
	}
}
