package main

import (
	"context"
	"net"
	"sync"
)

// Job represents a task to be processed by the worker pool.
type Job struct {
	Conn    net.Conn
	Handler func(net.Conn)
}

// WorkerPool defines the interface for a task distribution system.
type WorkerPool interface {
	Submit(job Job) bool
}

// channelWorkerPool implements WorkerPool using Go channels.
type channelWorkerPool struct {
	jobQueue chan Job
	ctx      context.Context
	wg       *sync.WaitGroup
}

// NewWorkerPool creates and starts a new worker pool.
func NewWorkerPool(ctx context.Context, maxWorkers, queueSize int, wg *sync.WaitGroup) WorkerPool {
	if maxWorkers <= 0 {
		maxWorkers = 1
	}

	if queueSize <= 0 {
		queueSize = 1
	}

	if wg == nil {
		wg = &sync.WaitGroup{}
	}

	wp := &channelWorkerPool{
		jobQueue: make(chan Job, queueSize),
		ctx:      ctx,
		wg:       wg,
	}

	for range maxWorkers {
		wg.Add(1)
		go wp.worker()
	}

	return wp
}

func (wp *channelWorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobQueue:
			if !ok {
				return
			}
			job.Handler(job.Conn)
		}
	}
}

func (wp *channelWorkerPool) Submit(job Job) bool {
	select {
	case <-wp.ctx.Done():
		return false
	case wp.jobQueue <- job:
		return true
	}
}
