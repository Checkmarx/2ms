package workerpool

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/checkmarx/2ms/v5/lib/utils"
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
	waitOnce       sync.Once
	logger         zerolog.Logger
	name           string

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
		pool:   pond.NewPool(config.workers, pondOpts...),
		ctx:    config.ctx,
		cancel: config.cancel,
		logger: utils.CreateLogger(zerolog.InfoLevel).With().Str("workerpool", name).Logger(),
		name:   name,
	}

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
// Returns ErrQueueClosed if the queue has been closed
func (p *workerPool) Submit(task Task) error {
	if p.isShuttingDown.Load() {
		return ErrPoolShuttingDown
	}
	if p.queueClosed.Load() {
		return ErrQueueClosed
	}

	// Wrap task to handle context and error logging
	pondTask := func() error {
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

	// Submit to pond pool
	// SubmitErr returns a Task, not an error
	// We don't need to wait for the task, just submit it
	p.pool.SubmitErr(pondTask)

	return nil
}

// CloseQueue closes the task queue, preventing new tasks from being submitted
// After calling CloseQueue, Submit will return ErrQueueClosed
// Use Wait() to block until all previously submitted tasks complete
func (p *workerPool) CloseQueue() {
	if p.queueClosed.Load() {
		return
	}

	p.queueClosed.Store(true)
	p.logger.Debug().Msg("Queue closed, no new tasks will be accepted")
}

// Wait blocks until all submitted tasks have completed
// Should be called after CloseQueue to ensure a clean shutdown
func (p *workerPool) Wait() {
	p.waitOnce.Do(func() {
		p.pool.StopAndWait()
		p.logger.Debug().Msg("All tasks completed")
	})
}

// Stop gracefully shuts down the pool
// It stops accepting new tasks and waits for active tasks to complete with a 5 second timeout
// Returns an error if shutdown times out
func (p *workerPool) Stop() error {
	var shutdownErr error

	p.shutdownOnce.Do(func() {
		p.logger.Debug().Msg("Initiating graceful shutdown")
		p.isShuttingDown.Store(true)
		p.queueClosed.Store(true)

		// Wait for graceful shutdown with timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		done := make(chan struct{})
		go func() {
			p.Wait() // This will call StopAndWait internally
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

		// Run before shutdown hook
		if p.beforeShutdown != nil {
			if err := p.beforeShutdown(); err != nil {
				p.logger.Error().Err(err).Msg("error during before shutdown hook")
			}
		}

		p.logger.Debug().Msg("Worker pool shutdown complete")
	})

	return shutdownErr
}

func (p *workerPool) BeforeShutdown(fn func() error) {
	p.beforeShutdown = fn
}
