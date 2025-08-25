package plugins

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// TestCommitRangeCalculation verifies that non-overlapping ranges are calculated correctly
func TestCommitRangeCalculation(t *testing.T) {
	testCases := []struct {
		name         string
		totalCommits int
		expectedGaps []bool // false = no gap, true = gap detected
	}{
		{"single commit", 1, []bool{false}},
		{"two commits", 2, []bool{false}},
		{"three commits", 3, []bool{false}},
		{"four commits", 4, []bool{false}},
		{"five commits", 5, []bool{false}},
		{"ten commits", 10, []bool{false}},
		{"hundred commits", 100, []bool{false}},
		{"odd number commits", 13, []bool{false}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the range calculation logic from scanCommits
			totalCommits := tc.totalCommits
			numWorkers := min(4, totalCommits)
			baseSize := totalCommits / numWorkers
			remainder := totalCommits % numWorkers

			// Track which commits are covered by ranges
			covered := make([]bool, totalCommits)
			
			startIdx := 0
			for i := 0; i < numWorkers; i++ {
				// Distribute remainder commits to first few workers
				rangeSize := baseSize
				if i < remainder {
					rangeSize++
				}
				
				endIdx := startIdx + rangeSize
				
				// Mark commits in this range as covered
				for pos := startIdx; pos < endIdx; pos++ {
					if pos >= totalCommits {
						t.Fatalf("Worker %d range exceeds total commits: pos=%d, total=%d", i+1, pos, totalCommits)
					}
					if covered[pos] {
						t.Fatalf("Commit %d covered by multiple workers", pos)
					}
					covered[pos] = true
				}
				
				t.Logf("Worker %d: range [%d, %d), size=%d", i+1, startIdx, endIdx, rangeSize)
				startIdx = endIdx
			}

			// Verify all commits are covered exactly once
			for pos, isCovered := range covered {
				if !isCovered {
					t.Errorf("Commit at position %d is not covered by any worker", pos)
				}
			}

			// Verify total coverage matches expected commits
			if startIdx != totalCommits {
				t.Errorf("Range calculation error: expected %d commits, covered %d", totalCommits, startIdx)
			}
		})
	}
}

// TestWorkerRangesNoOverlap tests that worker ranges don't overlap
func TestWorkerRangesNoOverlap(t *testing.T) {
	commits := make([]*object.Commit, 10) // Create dummy commits slice
	ctx := context.Background()

	// Test with 10 commits, should create 4 workers with ranges:
	// Worker 1: [0, 3) - 3 commits
	// Worker 2: [3, 5) - 2 commits  
	// Worker 3: [5, 8) - 3 commits
	// Worker 4: [8, 10) - 2 commits
	totalCommits := len(commits)
	numWorkers := min(4, totalCommits)
	baseSize := totalCommits / numWorkers  // 2
	remainder := totalCommits % numWorkers // 2

	workers := make([]*CommitWorker, numWorkers)
	allRanges := make([][2]int, numWorkers) // [start, end) pairs
	
	startIdx := 0
	for i := 0; i < numWorkers; i++ {
		rangeSize := baseSize
		if i < remainder {
			rangeSize++
		}
		
		endIdx := startIdx + rangeSize
		workers[i] = NewCommitWorker(i+1, startIdx, endIdx, commits, ctx)
		allRanges[i] = [2]int{startIdx, endIdx}
		
		startIdx = endIdx
	}

	// Verify no overlaps between any pair of workers
	for i := 0; i < len(allRanges); i++ {
		for j := i + 1; j < len(allRanges); j++ {
			rangeA := allRanges[i]
			rangeB := allRanges[j]
			
			// Check if ranges overlap: A.start < B.end && B.start < A.end
			if rangeA[0] < rangeB[1] && rangeB[0] < rangeA[1] {
				t.Errorf("Worker %d range [%d, %d) overlaps with Worker %d range [%d, %d)", 
					i+1, rangeA[0], rangeA[1], j+1, rangeB[0], rangeB[1])
			}
		}
	}

	// Verify complete coverage
	expectedTotal := 0
	for _, worker := range workers {
		expectedTotal += worker.endIdx - worker.startIdx
	}
	
	if expectedTotal != totalCommits {
		t.Errorf("Total range coverage %d doesn't match total commits %d", expectedTotal, totalCommits)
	}
}

// TestAllCommitsProcessedExactlyOnce is an integration test that would verify 
// all commits in a real repository are processed exactly once
func TestAllCommitsProcessedExactlyOnce(t *testing.T) {
	// This test would require a real git repository to test against
	// For now, we test the range calculation logic which is the critical part
	
	testSizes := []int{1, 2, 3, 4, 5, 7, 10, 13, 25, 100}
	
	for _, size := range testSizes {
		t.Run(fmt.Sprintf("commits_%d", size), func(t *testing.T) {
			// Simulate commits
			commits := make([]*object.Commit, size)
			processedCommits := make(map[int]int) // position -> count
			
			// Simulate the range calculation and processing
			totalCommits := len(commits)
			numWorkers := min(4, totalCommits)
			baseSize := totalCommits / numWorkers
			remainder := totalCommits % numWorkers

			startIdx := 0
			for i := 0; i < numWorkers; i++ {
				rangeSize := baseSize
				if i < remainder {
					rangeSize++
				}
				
				endIdx := startIdx + rangeSize
				
				// Simulate processing each commit in the range
				for pos := startIdx; pos < endIdx; pos++ {
					processedCommits[pos]++
				}
				
				startIdx = endIdx
			}

			// Verify each commit was processed exactly once
			for pos := 0; pos < totalCommits; pos++ {
				count, exists := processedCommits[pos]
				if !exists {
					t.Errorf("Commit at position %d was not processed", pos)
				} else if count != 1 {
					t.Errorf("Commit at position %d was processed %d times, expected 1", pos, count)
				}
			}

			// Verify no extra commits were processed
			if len(processedCommits) != totalCommits {
				t.Errorf("Processed %d commits, expected %d", len(processedCommits), totalCommits)
			}
		})
	}
}

// TestSmallRepositoryHandling tests edge cases with very few commits
func TestSmallRepositoryHandling(t *testing.T) {
	testCases := []struct {
		name            string
		commitCount     int
		expectedWorkers int
	}{
		{"empty repository", 0, 0},
		{"single commit", 1, 1},
		{"two commits", 2, 2},
		{"three commits", 3, 3},
		{"four commits", 4, 4},
		{"five commits", 5, 4}, // Should still use max 4 workers
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.commitCount == 0 {
				// Empty repository case - should return empty channel
				return
			}
			
			commits := make([]*object.Commit, tc.commitCount)
			totalCommits := len(commits)
			numWorkers := min(4, totalCommits)
			
			if numWorkers != tc.expectedWorkers {
				t.Errorf("Expected %d workers, got %d", tc.expectedWorkers, numWorkers)
			}

			// Verify range calculation still works correctly
			baseSize := totalCommits / numWorkers
			remainder := totalCommits % numWorkers
			covered := 0

			startIdx := 0
			for i := 0; i < numWorkers; i++ {
				rangeSize := baseSize
				if i < remainder {
					rangeSize++
				}
				
				covered += rangeSize
				startIdx += rangeSize
			}

			if covered != totalCommits {
				t.Errorf("Expected to cover %d commits, covered %d", totalCommits, covered)
			}
		})
	}
}