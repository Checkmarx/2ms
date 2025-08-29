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

func TestWorkerPool(t *testing.T) {
	t.Parallel()
	t.Run("pool creates the correct number of workers", func(t *testing.T) {
		numWorkers := 5
		ctx, cancel := context.WithCancel(context.Background())
		pool := newWorkerPool("test-pool", &Config{
			workers: numWorkers,
			ctx:     ctx,
			cancel:  cancel,
		})
		defer pool.Stop()

		var processedCount int32
		var wg sync.WaitGroup

		numTasks := 10
		wg.Add(numTasks)

		for range numTasks {
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
		assert.Equal(t, numWorkers, pool.pool.MaxConcurrency())
	})
	t.Run("pool drains queue before shutting down", func(t *testing.T) {
		pool := newWorkerPool("graceful-shutdown", &Config{
			workers: 2,
			ctx:     context.Background(),
		})

		var completedTasks int32
		var cancelledTasks chan struct{}
		// 1 second for each task, 2 workers, will make a total time of 2 seconds work
		taskDuration := 1 * time.Second
		numTasks := 4

		for range numTasks {
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
			assert.NoError(t, err)
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
	})
	t.Run("pool shuts down when context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		// number of tasks should be the same of the queue size so it doesnt block on the producer
		// since our tasks do infinite work
		numberOfTasks := 10
		numberOfWorkers := 2
		pool := New("timeout-test", WithWorkers(numberOfWorkers), WithQueueSize(numberOfTasks), WithContext(ctx), WithCancel(cancel))

		var cancelledTasks atomic.Int32
		var activeTasks atomic.Int32
		var submittedTasks atomic.Int32

		for range numberOfTasks {
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
	})
	t.Run("submitting after shutdown returns error", func(t *testing.T) {
		pool := New("submit-after-shutdown", WithWorkers(2))

		err := pool.Submit(func(ctx context.Context) error {
			time.Sleep(10 * time.Second)
			return nil
		})
		assert.NoError(t, err)

		// Start shutdown in a goroutine since our Stop is graceful and it waits for tasks to complete
		go func() {
			pool.Stop()
		}()

		// give some time for the goroutine to start and call the Stop method
		time.Sleep(100 * time.Millisecond)

		// Try to submit while shutting down
		err = pool.Submit(func(ctx context.Context) error {
			return nil
		})
		assert.ErrorIs(t, err, ErrPoolShuttingDown)
	})

	t.Run("task errors don't crash the worker", func(t *testing.T) {
		pool := New("error-handling", WithWorkers(2))
		defer pool.Stop()

		expectedError := errors.New("task error")
		var errorCount int32
		var successCount int32

		var wg sync.WaitGroup
		wg.Add(4)

		// Submit tasks that error
		for range 2 {
			err := pool.Submit(func(ctx context.Context) error {
				defer wg.Done()
				atomic.AddInt32(&errorCount, 1)
				return expectedError
			})
			assert.NoError(t, err)
		}

		// Submit tasks that succeed
		for range 2 {
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
	})

	t.Run("multiple stop calls are safe", func(t *testing.T) {
		pool := New("multiple-stop", WithWorkers(2))

		err := pool.Submit(func(ctx context.Context) error {
			time.Sleep(50 * time.Millisecond)
			return nil
		})
		assert.NoError(t, err)

		// Call Stop multiple times concurrently
		var wg sync.WaitGroup
		errors := make([]error, 3)

		for i := range 3 {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				errors[idx] = pool.Stop()
			}(i)
		}

		wg.Wait()

		for _, err := range errors {
			assert.NoError(t, err)
		}
	})

	t.Run("close queue prevents new task submission and triggers graceful shutdown", func(t *testing.T) {
		pool := newWorkerPool("close-queue", &Config{
			workers: 2,
			ctx:     context.Background(),
		})

		var completedTasks int32
		taskDuration := 50 * time.Millisecond
		numTasks := 3

		for range numTasks {
			err := pool.Submit(func(ctx context.Context) error {
				time.Sleep(taskDuration)
				atomic.AddInt32(&completedTasks, 1)
				return nil
			})
			assert.NoError(t, err)
		}

		// Close queue - this should trigger automatic shutdown when tasks finish
		pool.CloseQueue()
		assert.True(t, pool.queueClosed.Load())
		// wait enough time so the pool has time to initiate the shutdown
		time.Sleep(2 * time.Second)
		assert.True(t, pool.isShuttingDown.Load())

		completed := atomic.LoadInt32(&completedTasks)
		assert.Equal(t, int32(numTasks), completed)
	})

	t.Run("close queue can be called multiple times", func(t *testing.T) {
		pool := New("multiple-close-queue", WithWorkers(2))

		var completedTasks int32
		numTasks := 2

		for range numTasks {
			err := pool.Submit(func(ctx context.Context) error {
				time.Sleep(50 * time.Millisecond)
				atomic.AddInt32(&completedTasks, 1)
				return nil
			})
			assert.NoError(t, err)
		}

		// Call CloseQueue multiple times - should not panic
		var wg sync.WaitGroup
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pool.CloseQueue()
			}()
		}

		wg.Wait()
		time.Sleep(100 * time.Millisecond)

		completed := atomic.LoadInt32(&completedTasks)
		assert.Equal(t, int32(numTasks), completed)
	})
}
