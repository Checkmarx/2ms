package workerpool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test that the pool creates the correct number of workers
func TestWorkerPool_Creation(t *testing.T) {
	pool := New("test-pool", 5)
	defer pool.Stop()

	// Give workers time to start
	time.Sleep(100 * time.Millisecond)

	var processedCount int32
	var wg sync.WaitGroup

	numTasks := 10
	wg.Add(numTasks)

	for i := 0; i < numTasks; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			defer wg.Done()
			atomic.AddInt32(&processedCount, 1)
			time.Sleep(50 * time.Millisecond) // Simulate work
			return nil
		})
		assert.NoError(t, err)
	}

	wg.Wait()

	assert.Equal(t, int32(numTasks), atomic.LoadInt32(&processedCount))
}

// Test that pool drains queue before shutting down
func TestWorkerPool_GracefulShutdown(t *testing.T) {
	pool := New("graceful-shutdown", 2)

	var completedTasks int32
	var cancelledTasks int32
	taskDuration := 100 * time.Millisecond
	numTasks := 4

	for i := 0; i < numTasks; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				atomic.AddInt32(&cancelledTasks, 1)
				return ctx.Err()
			case <-time.After(taskDuration):
				atomic.AddInt32(&completedTasks, 1)
				return nil
			}
		})
		if err != nil {
			t.Fatalf("Failed to submit task: %v", err)
		}
	}

	// Give tasks a moment to start processing
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	err := pool.Stop()
	assert.NoError(t, err)
	elapsed := time.Since(start)

	// All tasks should have completed without cancellation
	completed := atomic.LoadInt32(&completedTasks)
	cancelled := atomic.LoadInt32(&cancelledTasks)

	t.Logf("Completed: %d, Cancelled: %d, Elapsed: %v", completed, cancelled, elapsed)

	assert.Equal(t, int32(numTasks), completed)
	assert.Equal(t, int32(0), cancelled)
}

// Test that context is cancelled when tasks don't complete in time
// This simulates what would happen with a timeout by directly calling cancel
func TestWorkerPool_TimeoutSimulation(t *testing.T) {
	pool := New("timeout-test", 1)

	var startedTasks int32
	var cancelledTasks int32

	err := pool.Submit(func(ctx context.Context) error {
		atomic.AddInt32(&startedTasks, 1)

		// Simulate a very long task that checks context
		for i := 0; i < 100; i++ {
			select {
			case <-ctx.Done():
				atomic.AddInt32(&cancelledTasks, 1)
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				// Continue work
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to submit task: %v", err)
	}

	// Wait for task to start
	for atomic.LoadInt32(&startedTasks) == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	// Simulate timeout by directly cancelling context
	// This is what would happen in waitForTasksWithTimeout after 30s
	pool.cancel()

	// Give task time to react to cancellation
	time.Sleep(200 * time.Millisecond)

	// Task should have been cancelled
	assert.Equal(t, int32(1), atomic.LoadInt32(&cancelledTasks))

	// Clean up
	pool.Stop()
}

// Test that submitting after shutdown returns error
func TestWorkerPool_SubmitAfterShutdown(t *testing.T) {
	pool := New("submit-after-shutdown", 2)

	// Submit a task that takes some time
	err := pool.Submit(func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	assert.NoError(t, err)

	// Start shutdown in a goroutine
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- pool.Stop()
	}()

	// Give shutdown a moment to start
	time.Sleep(50 * time.Millisecond)

	// Try to submit while shutting down
	err = pool.Submit(func(ctx context.Context) error {
		return nil
	})
	assert.ErrorIs(t, err, ErrPoolShuttingDown)

	assert.NoError(t, <-shutdownDone)
}

// Test that task errors don't crash the worker
func TestWorkerPool_TaskError(t *testing.T) {
	pool := New("error-handling", 2)
	defer pool.Stop()

	expectedError := errors.New("task error")
	var errorCount int32
	var successCount int32

	var wg sync.WaitGroup
	wg.Add(4)

	// Submit tasks that error
	for i := 0; i < 2; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			defer wg.Done()
			atomic.AddInt32(&errorCount, 1)
			return expectedError
		})
		assert.NoError(t, err)
	}

	// Submit tasks that succeed
	for i := 0; i < 2; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			defer wg.Done()
			atomic.AddInt32(&successCount, 1)
			return nil
		})
		assert.NoError(t, err)
	}

	wg.Wait()

	assert.Equal(t, int32(2), atomic.LoadInt32(&errorCount))
	assert.Equal(t, int32(2), atomic.LoadInt32(&successCount))
}

// Test that multiple calls to Stop are safe
func TestWorkerPool_MultipleStopCalls(t *testing.T) {
	pool := New("multiple-stop", 2)

	// Submit a task
	err := pool.Submit(func(ctx context.Context) error {
		time.Sleep(50 * time.Millisecond)
		return nil
	})
	assert.NoError(t, err)

	// Call Stop multiple times concurrently
	var wg sync.WaitGroup
	errors := make([]error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = pool.Stop()
		}(i)
	}

	wg.Wait()

	// All Stop calls should succeed without panic
	for _, err := range errors {
		assert.NoError(t, err)
	}
}
