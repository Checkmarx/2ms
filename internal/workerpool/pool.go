package workerpool

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/checkmarx/2ms/v3/lib/utils"
	"github.com/rs/zerolog"
)

var (
	// ErrPoolShuttingDown is returned when trying to submit a task to a shutting down pool
	ErrPoolShuttingDown = fmt.Errorf("worker pool is shutting down")
)

// Task represents a unit of work that can return an error
type Task func(ctx context.Context) error

// WorkerPool manages a fixed number of workers processing tasks
type WorkerPool struct {
	name           string
	workers        int
	taskQueue      chan Task
	queueClosed    atomic.Bool
	wg             sync.WaitGroup
	logger         zerolog.Logger
	activeTasks    int32
	shutdownOnce   sync.Once
	isShuttingDown int32
	ctx            context.Context
	cancel         context.CancelFunc
}

// New creates a new worker pool with the specified number of workers
func New(name string, workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &WorkerPool{
		name:      name,
		workers:   workers,
		taskQueue: make(chan Task, workers*2), // Buffered queue
		logger:    utils.CreateLogger(zerolog.InfoLevel).With().Str("workerpool", name).Logger(),
		ctx:       ctx,
		cancel:    cancel,
	}
	pool.start()
	return pool
}

func (p *WorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.work(i)
	}
}

func (p *WorkerPool) work(workerID int) {
	defer p.wg.Done()
	p.logger.Debug().Int("workerID", workerID).Msg("Worker started")

	for {
		if p.queueClosed.Load() && atomic.LoadInt32(&p.activeTasks) == 0 {
			return
		}

		task, ok := <-p.taskQueue
		if !ok {
			p.logger.Debug().Int("workerID", workerID).Msg("Task queue closed, worker exiting")
			return
		}

		atomic.AddInt32(&p.activeTasks, 1)
		if err := task(p.ctx); err != nil {
			p.logger.Error().Err(err).Int("workerID", workerID).Msg("Error doing work in workerpool")
		}
		atomic.AddInt32(&p.activeTasks, -1)
	}
}

// Submit adds a task to the queue
// Returns ErrPoolShuttingDown if the pool is shutting down
func (p *WorkerPool) Submit(task Task) error {
	if atomic.LoadInt32(&p.isShuttingDown) == 1 {
		return ErrPoolShuttingDown
	}

	select {
	case p.taskQueue <- task:
		return nil
	default:
		// Non-blocking check if we're shutting down
		if atomic.LoadInt32(&p.isShuttingDown) == 1 {
			return ErrPoolShuttingDown
		}
		// If not shutting down, block until we can submit
		p.taskQueue <- task
		return nil
	}
}

// Stop gracefully shuts down the pool
// It stops accepting new tasks and waits for active tasks to complete
// Returns an error if shutdown times out
func (p *WorkerPool) Stop() error {
	var shutdownErr error

	p.shutdownOnce.Do(func() {
		p.logger.Info().Msg("Initiating graceful shutdown")

		atomic.StoreInt32(&p.isShuttingDown, 1)

		shutdownErr = p.waitForTasksWithTimeout(30 * time.Second)

		if !p.queueClosed.Load() {
			close(p.taskQueue)
		}

		p.wg.Wait()

		p.logger.Info().Msg("Worker pool shutdown complete")
	})

	return shutdownErr
}

func (p *WorkerPool) waitForTasksWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.cancel()
			return ctx.Err()
		case <-p.ctx.Done():
			return p.ctx.Err()
		case <-ticker.C:
			if atomic.LoadInt32(&p.activeTasks) == 0 {
				return nil
			}
		}
	}
}

func (p *WorkerPool) CloseQueue() {
	close(p.taskQueue)
	p.queueClosed.Store(true)
}

// Wait waits for all workers to finish their tasks but it's the caller's responsibility to close the queue
// If the queue is not closed, the workers will wait indefinitely
func (p *WorkerPool) Wait() {
	p.wg.Wait()
}
