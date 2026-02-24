package main

import (
	"runtime"
	"testing"
)

func TestWorkerPoolDefaults(t *testing.T) {
	cfg := &Config{
		Server: Server{
			Listen: []Listen{
				{
					Kind:    "socket_map",
					Name:    "test",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    23450,
				},
			},
		},
	}

	err := cfg.HandleConfig()
	if err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	numCPU := runtime.GOMAXPROCS(0)
	expectedMaxWorkers := numCPU * 2
	expectedMaxQueue := expectedMaxWorkers * 10

	if cfg.Server.WorkerPool.MaxWorkers != expectedMaxWorkers {
		t.Errorf("Expected MaxWorkers %d, got %d", expectedMaxWorkers, cfg.Server.WorkerPool.MaxWorkers)
	}

	if cfg.Server.WorkerPool.MaxQueue != expectedMaxQueue {
		t.Errorf("Expected MaxQueue %d, got %d", expectedMaxQueue, cfg.Server.WorkerPool.MaxQueue)
	}
}

func TestWorkerPoolPartialDefaults(t *testing.T) {
	cfg := &Config{
		Server: Server{
			WorkerPool: WorkerPoolConfig{
				MaxWorkers: 5,
			},
			Listen: []Listen{
				{
					Kind:    "socket_map",
					Name:    "test",
					Type:    "tcp",
					Address: "127.0.0.1",
					Port:    23450,
					WorkerPool: WorkerPoolConfig{
						MaxWorkers: 3,
					},
				},
			},
		},
	}

	err := cfg.HandleConfig()
	if err != nil {
		t.Fatalf("HandleConfig failed: %v", err)
	}

	if cfg.Server.WorkerPool.MaxWorkers != 5 {
		t.Errorf("Expected MaxWorkers 5, got %d", cfg.Server.WorkerPool.MaxWorkers)
	}
	if cfg.Server.WorkerPool.MaxQueue != 50 {
		t.Errorf("Expected MaxQueue 50, got %d", cfg.Server.WorkerPool.MaxQueue)
	}

	if cfg.Server.Listen[0].WorkerPool.MaxWorkers != 3 {
		t.Errorf("Expected per-listener MaxWorkers 3, got %d", cfg.Server.Listen[0].WorkerPool.MaxWorkers)
	}
	if cfg.Server.Listen[0].WorkerPool.MaxQueue != 30 {
		t.Errorf("Expected per-listener MaxQueue 30, got %d", cfg.Server.Listen[0].WorkerPool.MaxQueue)
	}
}
