package semaphore

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
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
			name:           "host mememory only",
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
		context       context.Context
		expectedError error
	}

	testCases := []testCase{
		{
			name:         "successful acquisition and release",
			memoryBudget: defaultMemoryBudget,
			context:      context.Background(),
		},
		{
			name:          "failed acquisition - over budget",
			memoryBudget:  weight - 1,
			context:       context.Background(),
			expectedError: fmt.Errorf("buffer size %d exceeds memory budget %d", weight, weight-1),
		},
		{
			name:          "failed acquisition - context canceled",
			memoryBudget:  defaultMemoryBudget,
			context:       canceledContext(),
			expectedError: fmt.Errorf("failed to acquire semaphore: %w", context.Canceled),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sem := NewSemaphoreWithBudget(tc.memoryBudget)

			err := sem.AcquireMemoryWeight(tc.context, weight)
			if err == nil {
				sem.ReleaseMemoryWeight(weight)
			} else {
				assert.Equal(t, tc.expectedError, err)
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
