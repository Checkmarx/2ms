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

	defaultWorkers = 10
)

// Task represents a unit of work that can return an error
type Task func(ctx context.Context) error

type Pool interface {
	Submit(task Task) error
	Stop() error
	Wait()
	CloseQueue()
}

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
	isShuttingDown atomic.Bool
	ctx            context.Context
	cancel         context.CancelFunc
	ticker         *time.Ticker
}

type WorkerPoolConfig struct {
	workers   int
	queueSize int
	ctx       context.Context
	cancel    context.CancelFunc
}

type Option func(*WorkerPoolConfig)

// New creates a new worker pool with the specified number of workers
func New(name string, opts ...Option) Pool {
	ctx, cancel := context.WithCancel(context.Background())
	config := &WorkerPoolConfig{
		workers:   defaultWorkers,
		queueSize: defaultWorkers * 10,
		ctx:       ctx,
		cancel:    cancel,
	}
	for _, opt := range opts {
		opt(config)
	}
	return newWorkerPool(name, config)
}

func newWorkerPool(name string, config *WorkerPoolConfig) *WorkerPool {
	pool := &WorkerPool{
		name:      name,
		workers:   config.workers,
		taskQueue: make(chan Task, config.queueSize), // Buffered queue
		logger:    utils.CreateLogger(zerolog.InfoLevel).With().Str("workerpool", name).Logger(),
		ctx:       config.ctx,
		cancel:    config.cancel,
		ticker:    time.NewTicker(100 * time.Millisecond),
	}
	pool.start()
	return pool
}

func WithWorkers(workers int) Option {
	return func(config *WorkerPoolConfig) {
		config.workers = workers
	}
}

func WithQueueSize(queueSize int) Option {
	return func(config *WorkerPoolConfig) {
		config.queueSize = queueSize
	}
}

func WithContext(ctx context.Context) Option {
	return func(config *WorkerPoolConfig) {
		config.ctx = ctx
	}
}

func WithCancel(cancel context.CancelFunc) Option {
	return func(config *WorkerPoolConfig) {
		config.cancel = cancel
	}
}

func (p *WorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.work(i)
	}
	go p.startTicker()
}

func (p *WorkerPool) work(workerID int) {
	defer p.wg.Done()
	p.logger.Debug().Int("workerID", workerID).Msg("Worker started")

	for {
		select {
		case <-p.ctx.Done():
			return
		case task, ok := <-p.taskQueue:
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
}

// Submit adds a task to the queue
// Returns ErrPoolShuttingDown if the pool is shutting down
func (p *WorkerPool) Submit(task Task) error {
	if p.isShuttingDown.Load() {
		return ErrPoolShuttingDown
	}

	p.taskQueue <- task
	return nil
}

// Stop gracefully shuts down the pool
// It stops accepting new tasks and waits for active tasks to complete in 30 seconds
// Returns an error if shutdown times out
func (p *WorkerPool) Stop() error {
	var shutdownErr error

	p.shutdownOnce.Do(func() {
		p.logger.Info().Msg("Initiating graceful shutdown")

		p.isShuttingDown.Store(true)

		shutdownErr = p.waitForTasksWithTimeout(30 * time.Second)

		if !p.queueClosed.Load() {
			close(p.taskQueue)
		}

		p.cancel()

		p.logger.Info().Msg("Worker pool shutdown complete")
	})

	return shutdownErr
}

// waitForTasksWithTimeout waits for the pool to finish all tasks in queue until the timeout is reached
// It returns an error if the timeout is reached or if the context is canceled
func (p *WorkerPool) waitForTasksWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if p.workIsDone() {
			return nil
		}

		select {
		case <-ctx.Done():
			p.cancel()
			return ctx.Err()
		case <-p.ctx.Done():
			p.cancel()
			return p.ctx.Err()
		case <-ticker.C:
			if atomic.LoadInt32(&p.activeTasks) == 0 {
				return nil
			}
		}
	}
}

// CloseQueue closes the task queue and sets the queueClosed flag to true
// This will eventually trigger the pool to shutdown when the work is finished
func (p *WorkerPool) CloseQueue() {
	if p.queueClosed.Load() {
		return
	}

	close(p.taskQueue)
	p.queueClosed.Store(true)
}

// startTicker starts a ticker that monitors the pool to shutdown when the work is done
func (p *WorkerPool) startTicker() {
	defer p.ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			err := p.Stop()
			if err != nil {
				p.logger.Error().Err(err).Msg("error during graceful shutdown")
			}
			return
		case <-p.ticker.C:
			// Check if we're already shutting down
			if p.isShuttingDown.Load() {
				return
			}

			if p.workIsDone() {
				if err := p.Stop(); err != nil {
					p.logger.Error().Err(err).Msg("error during graceful shutdown")
				}
				return
			}
		}
	}
}

func (p *WorkerPool) workIsDone() bool {
	return p.queueClosed.Load() && atomic.LoadInt32(&p.activeTasks) == 0
}

// Wait waits for all workers to finish their work
func (p *WorkerPool) Wait() {
	p.wg.Wait()
}
