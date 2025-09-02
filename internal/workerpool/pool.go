package workerpool

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/checkmarx/2ms/v4/lib/utils"
	"github.com/rs/zerolog"
)

var (
	// ErrPoolShuttingDown is returned when trying to submit a task to a shutting down pool
	ErrPoolShuttingDown = fmt.Errorf("worker pool is shutting down")

	// ErrQueueClosed is returned when trying to submit a task to a closed queue
	ErrQueueClosed = fmt.Errorf("queue is closed")

	defaultWorkers = 10
)

// Task represents a unit of work that can return an error
type Task func(ctx context.Context) error

type Pool interface {
	Submit(task Task) error
	Stop() error
	CloseQueue()
	BeforeShutdown(func() error)
	Wait()
}

// workerPool wraps pond.Pool to implement our Pool interface
type workerPool struct {
	pool           pond.Pool
	ctx            context.Context
	cancel         context.CancelFunc
	queueClosed    atomic.Bool
	isShuttingDown atomic.Bool
	shutdownOnce   sync.Once
	logger         zerolog.Logger
	name           string

	// Track submitted and completed tasks
	submittedTasks atomic.Int32
	completedTasks atomic.Int32

	// Event-driven synchronization
	allTasksDone  chan struct{}
	completionMux sync.Mutex

	// Monitor goroutine control
	stopMonitor chan struct{}
	monitorDone chan struct{}

	// Hook to run a function before shutdown
	beforeShutdown func() error
}

type Config struct {
	workers   int
	queueSize int
	ctx       context.Context
	cancel    context.CancelFunc
}

type Option func(*Config)

// New creates a new worker pool with the specified number of workers
func New(name string, opts ...Option) Pool {
	ctx, cancel := context.WithCancel(context.Background())
	config := &Config{
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

func newWorkerPool(name string, config *Config) *workerPool {
	// Create pond pool with equivalent configuration
	pondOpts := []pond.Option{
		pond.WithContext(config.ctx),
	}

	// Set queue size if specified (pond defaults to unbounded)
	if config.queueSize > 0 {
		pondOpts = append(pondOpts, pond.WithQueueSize(config.queueSize))
	}

	wp := &workerPool{
		pool:         pond.NewPool(config.workers, pondOpts...),
		ctx:          config.ctx,
		cancel:       config.cancel,
		logger:       utils.CreateLogger(zerolog.InfoLevel).With().Str("workerpool", name).Logger(),
		name:         name,
		allTasksDone: make(chan struct{}, 1),
		stopMonitor:  make(chan struct{}),
		monitorDone:  make(chan struct{}),
	}

	// Start monitoring goroutine for CloseQueue() behavior
	go wp.monitorShutdown()

	return wp
}

func WithWorkers(workers int) Option {
	return func(config *Config) {
		config.workers = workers
	}
}

func WithQueueSize(queueSize int) Option {
	return func(config *Config) {
		config.queueSize = queueSize
	}
}

func WithContext(ctx context.Context) Option {
	return func(config *Config) {
		config.ctx = ctx
	}
}

func WithCancel(cancel context.CancelFunc) Option {
	return func(config *Config) {
		config.cancel = cancel
	}
}

// Submit adds a task to the queue
// Returns ErrPoolShuttingDown if the pool is shutting down
func (p *workerPool) Submit(task Task) error {
	// Wrap task to handle context and error logging
	pondTask := func() error {
		defer func() {
			completed := p.completedTasks.Add(1)
			// Signal completion when all tasks are done
			if completed == p.submittedTasks.Load() {
				p.completionMux.Lock()
				select {
				case p.allTasksDone <- struct{}{}:
				default:
					// Channel already signaled
				}
				p.completionMux.Unlock()
			}
		}()

		defer func() {
			if r := recover(); r != nil {
				p.logger.Error().Interface("panic", r).Str("pool", p.name).Msg("Recovered from task panic")
			}
		}()

		// Check if context is already canceled
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		if err := task(p.ctx); err != nil {
			p.logger.Error().Err(err).Str("pool", p.name).Msg("Error doing work in workerpool")
			return err
		}
		return nil
	}

	if p.isShuttingDown.Load() {
		return ErrPoolShuttingDown
	}
	if p.queueClosed.Load() {
		return ErrQueueClosed
	}

	p.submittedTasks.Add(1)

	// Submit to pond pool
	// SubmitErr returns a Task, not an error
	// We don't need to wait for the task, just submit it
	p.pool.SubmitErr(pondTask)

	return nil
}

// CloseQueue closes the task queue which is a soft shutdown since
// Monitoring goroutine will detect this and trigger shutdown when tasks are done
func (p *workerPool) CloseQueue() {
	if p.queueClosed.Load() {
		return
	}

	p.queueClosed.Store(true)
}

func (p *workerPool) Wait() {
	// Check if already complete before waiting
	if p.submittedTasks.Load() == p.completedTasks.Load() {
		return
	}

	// Wait for completion signal
	<-p.allTasksDone
}

// Stop gracefully shuts down the pool
// It stops accepting new tasks and waits for active tasks to complete in 30 seconds
// Returns an error if shutdown times out
func (p *workerPool) Stop() error {
	var shutdownErr error

	p.shutdownOnce.Do(func() {
		p.logger.Info().Msg("Initiating graceful shutdown")
		p.isShuttingDown.Store(true)

		// Signal monitor to stop if it's running
		select {
		case <-p.stopMonitor:
			// Already closed
		default:
			close(p.stopMonitor)
		}

		// Wait for graceful shutdown with timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		done := make(chan struct{})
		go func() {
			p.pool.StopAndWait()
			close(done)
		}()

		select {
		case <-done:
			// Graceful shutdown completed
		case <-shutdownCtx.Done():
			// Timeout - force cancellation
			p.cancel()
			shutdownErr = shutdownCtx.Err()
		}

		// Wait for monitor goroutine to finish
		select {
		case <-p.monitorDone:
		case <-time.After(1 * time.Second):
			// Don't wait forever for monitor
		}

		// Run before shutdown hook
		if p.beforeShutdown != nil {
			if err := p.beforeShutdown(); err != nil {
				p.logger.Error().Err(err).Msg("error during before shutdown hook")
			}
		}

		p.logger.Info().Msg("Worker pool shutdown complete")
	})

	return shutdownErr
}

// monitorShutdown implements CloseQueue() auto-shutdown behavior
func (p *workerPool) monitorShutdown() {
	defer close(p.monitorDone)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopMonitor:
			return
		case <-p.ctx.Done():
			// Context canceled, initiate shutdown
			go func() {
				if err := p.Stop(); err != nil {
					p.logger.Error().Err(err).Msg("error during graceful shutdown")
				}
			}()
			return
		case <-ticker.C:
			// Check if already shutting down
			if p.isShuttingDown.Load() {
				return
			}

			// Check if queue is closed and all tasks are completed
			if p.queueClosed.Load() {
				submitted := p.submittedTasks.Load()
				completed := p.completedTasks.Load()

				// If all submitted tasks are completed (or no tasks were ever submitted), trigger shutdown
				if submitted == completed {
					go func() {
						if err := p.Stop(); err != nil {
							p.logger.Error().Err(err).Msg("error during graceful shutdown")
						}
					}()
					return
				}
			}
		}
	}
}

func (p *workerPool) BeforeShutdown(fn func() error) {
	p.beforeShutdown = fn
}
