package main

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		processed atomic.Int32
		wg        sync.WaitGroup
		handlerWg sync.WaitGroup
	)

	maxWorkers := 2
	queueSize := 5
	wp := NewWorkerPool(ctx, maxWorkers, queueSize, &wg)

	handler := func(conn net.Conn) {
		defer handlerWg.Done()
		processed.Add(1)
		time.Sleep(10 * time.Millisecond) // Simulate work
	}

	// Submit jobs
	for i := range 10 {
		handlerWg.Add(1)
		job := Job{Conn: nil, Handler: handler}
		if !wp.Submit(job) {
			t.Errorf("Failed to submit job %d", i)
			handlerWg.Done()
		}
	}

	handlerWg.Wait()

	if processed.Load() != 10 {
		t.Errorf("Expected 10 processed jobs, got %d", processed.Load())
	}

	cancel() // Shutdown WorkerPool
	wg.Wait()
}

func TestWorkerPoolBackPressure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	maxWorkers := 1
	queueSize := 1
	wp := NewWorkerPool(ctx, maxWorkers, queueSize, &wg)

	handler := func(conn net.Conn) {
		time.Sleep(50 * time.Millisecond) // Block the worker
	}

	// First job: occupies the worker
	wp.Submit(Job{Conn: nil, Handler: handler})
	// Second job: occupies the queue (size 1)
	wp.Submit(Job{Conn: nil, Handler: handler})

	// Third job: should block until one is done
	start := time.Now()
	done := make(chan bool)
	go func() {
		wp.Submit(Job{Conn: nil, Handler: handler})
		done <- true
	}()

	select {
	case <-done:
		if time.Since(start) < 20*time.Millisecond {
			t.Error("Submit should have blocked due to full queue")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Submit blocked too long or hung")
	}

	cancel()
	wg.Wait()
}
