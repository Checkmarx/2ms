package workerpool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test that the pool creates the correct number of workers
func TestWorkerPool_Creation(t *testing.T) {
	t.Parallel()
	pool := New("test-pool", WithWorkers(5))
	defer pool.Stop()

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

	// wait until all tasks have been submitted and processed
	wg.Wait()

	assert.Equal(t, int32(numTasks), atomic.LoadInt32(&processedCount))
}

// Test that pool drains queue before shutting down
func TestWorkerPool_GracefulShutdown(t *testing.T) {
	t.Parallel()
	pool := New("graceful-shutdown", WithWorkers(2))

	var completedTasks int32
	var cancelledTasks chan struct{}
	// 1 second for each task, 2 workers, will make a total time of 2 seconds work
	taskDuration := 1 * time.Second
	numTasks := 4

	for i := 0; i < numTasks; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				cancelledTasks <- struct{}{}
				return nil
			case <-time.After(taskDuration):
				atomic.AddInt32(&completedTasks, 1)
				return nil
			}
		})
		if err != nil {
			t.Fatalf("Failed to submit task: %v", err)
		}
	}

	close := make(chan struct{})
	go func() {
		for {
			select {
			case <-cancelledTasks:
				assert.Fail(t, "task cancelled")
				return
			case <-close:
				return
			}
		}
	}()
	defer func() {
		close <- struct{}{}
	}()

	err := pool.Stop()
	assert.NoError(t, err)

	completed := atomic.LoadInt32(&completedTasks)
	assert.Equal(t, int32(numTasks), completed)
}

// Test that when the context is cancelled, the pool stops, all tasks are cancelled,
// the queue is closed and work submitted is ignored
func TestWorkerPool_Cancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	// number of tasks should be the same of the queue size so it doesnt block on the producer
	// since our tasks do infinite work
	numberOfTasks := 10
	numberOfWorkers := 2
	pool := New("timeout-test", WithWorkers(numberOfWorkers), WithQueueSize(numberOfTasks), WithContext(ctx), WithCancel(cancel))

	var cancelledTasks atomic.Int32
	var activeTasks atomic.Int32
	var submittedTasks atomic.Int32

	for i := 0; i < numberOfTasks; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			activeTasks.Add(1)
			for {
				select {
				case <-ctx.Done():
					cancelledTasks.Add(1)
					return ctx.Err()
				default:
					time.Sleep(100 * time.Millisecond)
				}
			}
		})
		submittedTasks.Add(1)
		assert.NoError(t, err)
	}
	for submittedTasks.Load() < int32(numberOfTasks) {
		time.Sleep(10 * time.Millisecond)
	}
	for activeTasks.Load() < int32(numberOfWorkers) {
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Println("active tasks", activeTasks.Load())

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if cancelledTasks.Load() == activeTasks.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	cancel()
	wg.Wait()
	// we sleep here to make sure the pool did shutdown the workers
	// and did not consume tasks from the queue in the time between the cancel and shutdown
	// otherwise, the assertion below will fail
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, cancelledTasks.Load(), activeTasks.Load())
}

// Test that submitting after shutdown returns error
func TestWorkerPool_SubmitAfterShutdown(t *testing.T) {
	t.Parallel()
	pool := New("submit-after-shutdown", WithWorkers(2))

	// Submit a task that takes some time
	err := pool.Submit(func(ctx context.Context) error {
		time.Sleep(10 * time.Second)
		return nil
	})
	assert.NoError(t, err)

	// Start shutdown in a goroutine since our Stop is graceful and it waits for tasks to complete
	go func() {
		fmt.Println("stopping pool")
		pool.Stop()
	}()

	// give some time for the goroutine to start and call the Stop method
	time.Sleep(100 * time.Millisecond)

	// Try to submit while shutting down
	err = pool.Submit(func(ctx context.Context) error {
		return nil
	})
	assert.ErrorIs(t, err, ErrPoolShuttingDown)
}

// Test that task errors don't crash the worker
func TestWorkerPool_TaskError(t *testing.T) {
	t.Parallel()
	pool := New("error-handling", WithWorkers(2))
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
	t.Parallel()
	pool := New("multiple-stop", WithWorkers(2))

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

// Test that Wait() blocks until all workers finish their tasks
func TestWorkerPool_Wait(t *testing.T) {
	t.Parallel()
	pool := New("wait-test", WithWorkers(3))
	defer pool.Stop()

	var completedTasks int32
	var startTime time.Time
	taskDuration := 200 * time.Millisecond
	numTasks := 6

	startTime = time.Now()

	// Submit tasks that take some time
	for i := 0; i < numTasks; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			time.Sleep(taskDuration)
			atomic.AddInt32(&completedTasks, 1)
			return nil
		})
		assert.NoError(t, err)
	}

	// Close the queue so the pool knows no more tasks are coming
	pool.CloseQueue()

	// Wait should block until all tasks complete
	pool.Wait()

	elapsed := time.Since(startTime)
	completed := atomic.LoadInt32(&completedTasks)

	// All tasks should be completed
	assert.Equal(t, int32(numTasks), completed)
	// Should take at least the time for 2 batches of tasks (since we have 3 workers and 6 tasks)
	assert.GreaterOrEqual(t, elapsed, 2*taskDuration)
}

// Test that Wait() works correctly with concurrent task submission
func TestWorkerPool_WaitWithConcurrentSubmission(t *testing.T) {
	t.Parallel()
	pool := New("wait-concurrent", WithWorkers(2))
	defer pool.Stop()

	var completedTasks int32
	numTasks := 10

	// Start submitting tasks in a goroutine
	go func() {
		for i := 0; i < numTasks; i++ {
			err := pool.Submit(func(ctx context.Context) error {
				time.Sleep(50 * time.Millisecond)
				atomic.AddInt32(&completedTasks, 1)
				return nil
			})
			if err != nil {
				t.Errorf("Failed to submit task: %v", err)
			}
			time.Sleep(10 * time.Millisecond) // Small delay between submissions
		}
		pool.CloseQueue()
	}()

	// Wait should block until all submitted tasks complete
	pool.Wait()

	completed := atomic.LoadInt32(&completedTasks)
	assert.Equal(t, int32(numTasks), completed)
}

// Test CloseQueue() prevents new task submission and triggers graceful shutdown
func TestWorkerPool_CloseQueue(t *testing.T) {
	t.Parallel()
	pool := New("cloese-queue", WithWorkers(2))

	var completedTasks int32
	var shutdownDetected int32
	taskDuration := 50 * time.Millisecond
	numTasks := 3

	// Submit tasks
	for i := 0; i < numTasks; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			time.Sleep(taskDuration)
			atomic.AddInt32(&completedTasks, 1)
			return nil
		})
		assert.NoError(t, err)
	}

	// Monitor for shutdown in a separate goroutine
	go func() {
		// Give some time for tasks to start
		time.Sleep(25 * time.Millisecond)

		// Close queue - this should trigger automatic shutdown when tasks finish
		pool.CloseQueue()

		// Wait and verify shutdown happened
		pool.Wait()
		atomic.AddInt32(&shutdownDetected, 1)
	}()

	// Give enough time for shutdown to occur
	time.Sleep(500 * time.Millisecond)

	completed := atomic.LoadInt32(&completedTasks)
	shutdown := atomic.LoadInt32(&shutdownDetected)

	assert.Equal(t, int32(numTasks), completed)
	assert.Equal(t, int32(1), shutdown)
}

// Test CloseQueue() can be called multiple times safely
func TestWorkerPool_CloseQueueMultipleCalls(t *testing.T) {
	t.Parallel()
	pool := New("multiple-close-queue", WithWorkers(2))

	var completedTasks int32
	numTasks := 2

	// Submit a few tasks
	for i := 0; i < numTasks; i++ {
		err := pool.Submit(func(ctx context.Context) error {
			time.Sleep(50 * time.Millisecond)
			atomic.AddInt32(&completedTasks, 1)
			return nil
		})
		assert.NoError(t, err)
	}

	// Call CloseQueue multiple times - should not panic
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Multiple calls should be safe
			pool.CloseQueue()
		}()
	}

	wg.Wait()
	pool.Wait()

	completed := atomic.LoadInt32(&completedTasks)
	assert.Equal(t, int32(numTasks), completed)
}
