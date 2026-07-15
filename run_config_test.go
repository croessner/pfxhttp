package main

import "testing"

func TestLegacyWorkerPoolWarningDetectionUsesActualLegacyInput(t *testing.T) {
	if legacyWorkerPoolConfigured(&Config{Server: Server{WorkerPool: WorkerPoolConfig{MaxWorkers: 10}}}) {
		t.Fatal("normalized values without the legacy marker must not trigger a warning")
	}

	if !legacyWorkerPoolConfigured(&Config{Server: Server{LegacyWorkerPool: true}}) {
		t.Fatal("server legacy worker_pool input was not detected")
	}

	if !legacyWorkerPoolConfigured(&Config{Server: Server{Listen: []Listen{{LegacyWorkerPool: true}}}}) {
		t.Fatal("listener legacy worker_pool input was not detected")
	}
}

func TestRestartOnlyConfigChanges(t *testing.T) {
	current := &Config{Server: Server{RunAsUser: testPfxhttpClientID, RunAsGroup: testPfxhttpClientID}}

	next := &Config{Server: current.Server}
	if restartOnlyConfigChanged(current, next) {
		t.Fatal("identical configuration requires restart")
	}

	next.Server.RunAsUser = "other"
	if !restartOnlyConfigChanged(current, next) {
		t.Fatal("run_as_user change must require restart")
	}

	next.Server.RunAsUser = current.Server.RunAsUser
	next.Server.Observability.PrometheusEnabled = true

	if !restartOnlyConfigChanged(current, next) {
		t.Fatal("observability lifecycle change must require restart")
	}

	next.Server.Observability = current.Server.Observability
	next.Server.HTTPClient.Timeout++

	if restartOnlyConfigChanged(current, next) {
		t.Fatal("reloadable HTTP client change was classified restart-only")
	}
}
