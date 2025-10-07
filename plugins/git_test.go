package plugins

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestBuildScanOptions(t *testing.T) {
	tests := []struct {
		name            string
		scanAllBranches bool
		depth           int
		baseCommit      string
		expectedOptions string
	}{
		{
			name:            "Default: scan every commit from checked in branch",
			scanAllBranches: false,
			depth:           0,
			baseCommit:      "",
			expectedOptions: "--full-history",
		},
		{
			name:            "Scan all commits from all branches",
			scanAllBranches: true,
			depth:           0,
			baseCommit:      "",
			expectedOptions: "--full-history --all",
		},
		{
			name:            "scan the last 10 commits from checked in branch",
			scanAllBranches: false,
			depth:           10,
			baseCommit:      "",
			expectedOptions: "--full-history -n 10",
		},
		{
			name:            "Scan the last 10 commits of all branches",
			scanAllBranches: true,
			depth:           10,
			baseCommit:      "",
			expectedOptions: "--full-history --all -n 10",
		},
		{
			name:            "Negative depth: should not include depth option",
			scanAllBranches: true,
			depth:           -5,
			baseCommit:      "",
			expectedOptions: "--full-history --all",
		},
		{
			name:            "Base commit: scan commits between base and HEAD",
			scanAllBranches: false,
			depth:           0,
			baseCommit:      "abc123",
			expectedOptions: "--full-history abc123..HEAD",
		},
		{
			name:            "Base commit with all branches",
			scanAllBranches: true,
			depth:           0,
			baseCommit:      "def456",
			expectedOptions: "--full-history --all def456..HEAD",
		},
		{
			name:            "Base commit with depth: both flags are used",
			scanAllBranches: false,
			depth:           10,
			baseCommit:      "ghi789",
			expectedOptions: "--full-history ghi789..HEAD -n 10",
		},
		{
			name:            "Base commit with all branches and depth: all flags are used",
			scanAllBranches: true,
			depth:           15,
			baseCommit:      "jkl012",
			expectedOptions: "--full-history --all jkl012..HEAD -n 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &GitPlugin{
				scanAllBranches: tt.scanAllBranches,
				depth:           tt.depth,
				baseCommit:      tt.baseCommit,
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
			expectedErr: fmt.Errorf(
				"is not a git repository. Please make sure the root path of the provided directory contains a .git subdirectory",
			),
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

func TestGitChangesPool(t *testing.T) {
	pool := newGitChangesPool(0)

	// Test getting a slice
	slice1 := pool.getSlice()
	assert.NotNil(t, slice1)
	assert.Equal(t, 0, len(slice1))
	assert.GreaterOrEqual(t, cap(slice1), 16)

	// Add some data
	slice1 = append(slice1, gitdiffChunk{Added: "test", Removed: "old"})

	// Put it back
	pool.putSlice(slice1)

	// Get another slice
	slice2 := pool.getSlice()
	assert.NotNil(t, slice2)
	assert.Equal(t, 0, len(slice2)) // Should be reset

	// Test oversized slice discard
	largeSlice := make([]gitdiffChunk, 0, 100)
	pool.putSlice(largeSlice) // Should be discarded due to size

	// Check stats
	gets := pool.slicePoolGets.Load()
	puts := pool.slicePoolPuts.Load()
	discards := pool.slicePoolDiscards.Load()

	assert.Equal(t, int64(2), gets)
	assert.Equal(t, int64(1), puts)     // Only the first slice was put back
	assert.Equal(t, int64(1), discards) // Large slice was discarded
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

func TestExtractChanges(t *testing.T) {
	tests := []struct {
		name           string
		fragments      []*gitdiff.TextFragment
		expectedChunks int
		expectedError  error
		description    string
	}{
		{
			name:           "Large diff chunked properly",
			fragments:      createLargeTestFragments(2 * 1024 * 1024), // 2MB total
			expectedChunks: 8,
			description:    "Should create 8 chunks for 2MB of data with 256KB each",
		},
		{
			name:           "Small diff single chunk",
			fragments:      createSmallTestFragments(500 * 1024), // 500KB total
			expectedChunks: 1,
			description:    "Should create 2 chunks for 500KB",
		},
		{
			name:           "Empty fragments",
			fragments:      []*gitdiff.TextFragment{},
			expectedChunks: 0,
			description:    "Should create no chunks for empty fragments",
		},
		{
			name:           "Nil fragment handling",
			fragments:      []*gitdiff.TextFragment{nil, createSmallTestFragments(100)[0], nil},
			expectedChunks: 1,
			description:    "Should handle nil fragments gracefully",
		},
		{
			name:           "Mixed operations",
			fragments:      createMixedOperationFragments(256 * 1024), // 256KB each add/delete (total ~640KB)
			expectedChunks: 3,
			description:    "Should handle mixed add/delete operations in single chunk",
		},
		{
			name:           "File diff size exceeded",
			fragments:      createLargeTestFragments(51 * 1024 * 1024), // 51MB
			expectedChunks: 0,
			description:    "Should return error when file diff size exceeds limit",
			expectedError:  ErrFileDiffSizeExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changesPool := newGitChangesPool(0)
			chunks, err := extractChanges(changesPool, tt.fragments)

			assert.ErrorIs(t, err, tt.expectedError)
			assert.Equal(t, tt.expectedChunks, len(chunks), tt.description)

			if tt.expectedError == nil {
				// Verify memory is freed for non-nil fragments
				for _, fragment := range tt.fragments {
					if fragment != nil {
						for _, line := range fragment.Lines {
							assert.Empty(t, line.Line, "Line content should be cleared to free memory")
						}
					}
				}

				// Verify chunks contain expected content types
				for _, chunk := range chunks {
					if tt.expectedChunks > 0 {
						// At least one chunk should have some content
						hasContent := chunk.Added != "" || chunk.Removed != ""
						assert.True(t, hasContent, "Chunk should contain added or removed content")
					}
				}
			}
		})
	}
}

func TestProcessFileDiff(t *testing.T) {
	tests := []struct {
		name          string
		fragmentSize  int
		isBinary      bool
		isDelete      bool
		expectedItems int
	}{
		{
			name:          "normal file with small diff",
			fragmentSize:  2000, // 2KB
			expectedItems: 2,
		},
		{
			name:          "normal file with large diff under limit",
			fragmentSize:  2 * 1024 * 1024, // 2MiB
			expectedItems: 16,              // (2000 KiB /256 KiB = 8 chunks) x 2 (added and removed)
		},
		{
			name:          "file exceeding size limit",
			fragmentSize:  60 * 1024 * 1024, // 60MiB - exceeds 50MiB limit
			expectedItems: 0,
		},
		{
			name:          "binary file",
			fragmentSize:  1024,
			isBinary:      true,
			expectedItems: 0,
		},
		{
			name:          "deleted file",
			fragmentSize:  1024,
			isDelete:      true,
			expectedItems: 1,
		},
		{
			name:          "empty fragments",
			fragmentSize:  0,
			expectedItems: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &GitPlugin{
				Plugin:         Plugin{},
				projectName:    "test-project",
				gitChangesPool: newGitChangesPool(0),
			}

			// Create test file
			file := createTestFile("test-file", "abc123", tt.name, tt.fragmentSize, tt.isBinary, tt.isDelete)

			items := make(chan ISourceItem, 100)

			plugin.processFileDiff(file, items)
			close(items)

			// Collect all items
			var itemCount int
			var collectedItems []ISourceItem
			for item := range items {
				itemCount++
				collectedItems = append(collectedItems, item)
				assert.NotNil(t, item.GetContent(), "Item content should not be nil")
				assert.NotEmpty(t, item.GetID(), "Item ID should not be empty")
			}

			assert.Equal(t, tt.expectedItems, itemCount)
			if itemCount > 0 {
				for _, item := range collectedItems {
					assert.Contains(t, item.GetID(), "abc123", "Item ID should contain commit SHA")
					assert.Contains(t, item.GetID(), "test-file", "Item ID should contain file name")

					// Validate GitInfo
					if gitInfo := item.GetGitInfo(); gitInfo != nil {
						assert.NotNil(t, gitInfo.Hunks, "GitInfo should have hunks")
						assert.True(t, gitInfo.ContentType == AddedContent || gitInfo.ContentType == RemovedContent,
							"GitInfo should have valid content type")
					}
				}
			}
		})
	}
}

// createTestFile creates a gitdiff.File for testing with specified parameters
func createTestFile(fileName, commitSHA, commitTitle string, fragmentSize int, isBinary, isDelete bool) *gitdiff.File {
	file := &gitdiff.File{
		NewName: fileName,
		OldName: fileName,
		PatchHeader: &gitdiff.PatchHeader{
			SHA:   commitSHA,
			Title: commitTitle,
		},
		IsBinary: isBinary,
		IsDelete: isDelete,
	}

	// Only create fragments for non-binary files with content
	if !isBinary && fragmentSize > 0 {
		file.TextFragments = createLargeTestFragments(fragmentSize)
	}

	return file
}

func TestStringBuilderPool(t *testing.T) {
	pool := newStringBuilderPool(added, 1024, 64*1024, 0) // 1KB initial, 64KB max

	// Test basic get/put operations
	sb1 := pool.Get()
	assert.NotNil(t, sb1, "Should get valid string builder")
	assert.Equal(t, 0, sb1.Len(), "Builder should be empty/reset")

	sb1.WriteString("test content")
	pool.Put(sb1)

	// Get another builder (may or may not be the same instance)
	sb2 := pool.Get()
	assert.NotNil(t, sb2, "Should get valid string builder")
	assert.Equal(t, 0, sb2.Len(), "Builder should be empty/reset")

	pool.Put(sb2)

	// Check stats
	gets, puts, discards, news, efficiency := pool.Stats()
	assert.Equal(t, int64(2), gets, "Should track gets")
	assert.Equal(t, int64(2), puts, "Should track puts")
	// sync.Pool is non-deterministic - GC can clear the pool between Put() and Get()
	// If the pool is cleared, we'll create 2 new builders; otherwise, we'll reuse and only create 1
	assert.True(t, news >= 1 && news <= 2, "News should be 1 (reused) or 2 (GC cleared pool), got %d", news)
	assert.Equal(t, int64(0), discards, "Should have no discards for normal-sized builders")
	// Efficiency depends on whether the pool was cleared by GC
	assert.True(t, efficiency >= 50.0 && efficiency <= 100.0, "Efficiency should be between 50%% and 100%%, got %.1f", efficiency)
	t.Run("test oversize handling", func(t *testing.T) {
		pool := newStringBuilderPool(removed, 1024, 8*1024, 0) // 1KB initial, 8KB max

		sb := pool.Get()

		// Create content larger than max size
		largeContent := strings.Repeat("x", 16*1024) // 16KB > 8KB max
		sb.WriteString(largeContent)

		pool.Put(sb) // Should discard due to size

		gets, puts, discards, news, efficiency := pool.Stats()
		assert.Equal(t, int64(1), gets, "Should track gets")
		assert.Equal(t, int64(1), news, "Should track news")
		assert.Equal(t, int64(0), puts, "Should not put oversized builder")
		assert.Equal(t, int64(1), discards, "Should track discard")
		assert.Equal(t, 0.0, efficiency, "Should have 0% efficiency due to discard")
	})
}

func createLargeTestFragments(totalSize int) []*gitdiff.TextFragment {
	lineSize := 1024                                  // 1KiB per line
	numLines := (totalSize + lineSize - 1) / lineSize // Ceiling division
	lines := make([]gitdiff.Line, numLines)

	for i := range numLines {
		op := gitdiff.OpAdd
		if i%2 == 0 {
			op = gitdiff.OpDelete
		}
		lines[i] = gitdiff.Line{
			Op:   op,
			Line: strings.Repeat("a", lineSize),
		}
	}

	return []*gitdiff.TextFragment{
		{
			Lines: lines,
		},
	}
}

func createSmallTestFragments(totalSize int) []*gitdiff.TextFragment {
	line := strings.Repeat("x", totalSize)
	return []*gitdiff.TextFragment{
		{
			Lines: []gitdiff.Line{
				{Op: gitdiff.OpAdd, Line: line},
			},
		},
	}
}

func createMixedOperationFragments(sizePerOp int) []*gitdiff.TextFragment {
	return []*gitdiff.TextFragment{
		{
			Lines: []gitdiff.Line{
				{Op: gitdiff.OpAdd, Line: strings.Repeat("a", sizePerOp)},
				{Op: gitdiff.OpDelete, Line: strings.Repeat("d", sizePerOp)},
				{Op: gitdiff.OpContext, Line: "context line"},
				{Op: gitdiff.OpAdd, Line: strings.Repeat("a", sizePerOp/2)},
			},
		},
	}
}
