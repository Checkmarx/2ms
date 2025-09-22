package semaphore

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeMemoryBudget(t *testing.T) {
	mib := 1024 * 1024  // 1MiB
	safety := 200 * mib // 200MiB

	type testCase struct {
		name           string
		hostMemory     uint64
		cgroupLimit    uint64
		expectedBudget int64
	}
	testCases := []testCase{
		{
			name:           "host memory only",
			hostMemory:     uint64(4 * 1024 * mib), // 4GiB
			cgroupLimit:    ^uint64(0),
			expectedBudget: int64((4*1024*mib - safety) / 2), // 2GiB - 200MiB
		},
		{
			name:           "cgroup tighter than host",
			hostMemory:     uint64(4 * 1024 * mib),           // 4GiB
			cgroupLimit:    uint64(2 * 1024 * mib),           // 2GiB
			expectedBudget: int64((2*1024*mib - safety) / 2), // 1GiB - 200MiB
		},
		{
			name:           "floor budget to 256MiB",
			hostMemory:     uint64(300 * mib), // 300MiB
			cgroupLimit:    0,
			expectedBudget: int64(256 * mib), // 256MiB
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			budget := computeMemoryBudget(tc.hostMemory, tc.cgroupLimit)
			assert.Equal(t, tc.expectedBudget, budget, "Expected budget does not match actual budget")
		})
	}
}

func TestAcquireReleaseMemoryWeight(t *testing.T) {
	weight := int64(1024)                     // 1KiB
	defaultMemoryBudget := int64(1024 * 1024) // 1MiB
	type testCase struct {
		name          string
		memoryBudget  int64
		expectedError error
	}

	testCases := []testCase{
		{
			name:         "successful acquisition and release",
			memoryBudget: defaultMemoryBudget,
		},
		{
			name:          "failed acquisition - over budget",
			memoryBudget:  weight - 1,
			expectedError: fmt.Errorf("buffer size %d exceeds memory budget %d", weight, weight-1),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sem := NewSemaphoreWithBudget(tc.memoryBudget)

			err := sem.AcquireMemoryWeight(context.Background(), weight)
			if err == nil {
				sem.ReleaseMemoryWeight(weight)
			} else {
				assert.Equal(t, tc.expectedError, err)
			}
		})
	}
}
