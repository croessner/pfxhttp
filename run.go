package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/fx"
)

type ctxKey string

const loggerKey ctxKey = "logging"

// RunServer starts the server lifecycle managed by fx.
func RunServer(lc fx.Lifecycle, deps *Deps) {
	cfg := deps.GetConfig()

	if cfg == nil {
		return
	}

	serverCtx, cancelServer := context.WithCancel(context.Background())
	done := make(chan struct{})

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				defer close(done)
				runServerLoop(serverCtx, deps)
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			deps.GetLogger().Info("Server stopping...")
			cancelServer()
			<-done

			return nil
		},
	})
}

func runServerLoop(ctx context.Context, deps *Deps) {
	cfg := deps.GetConfig()

	deps.GetLogger().Info("Starting server", slog.String("version", version))

	registry := NewListenerRegistry()

	// Create global worker pool if configured
	var globalWorkerPool WorkerPool

	if cfg.Server.WorkerPool.MaxWorkers > 0 {
		globalWorkerPool = NewWorkerPool(ctx, cfg.Server.WorkerPool.MaxWorkers, cfg.Server.WorkerPool.MaxQueue, nil)
	}

	// Start initial listeners
	for _, instance := range cfg.Server.Listen {
		if err := registry.startListener(ctx, deps, instance, globalWorkerPool, deps.GetLogger()); err != nil {
			deps.GetLogger().Error("Failed to start listener", slog.String("error", err.Error()))

			registry.StopAll()

			return
		}
	}

	// Drop privileges after all listeners are bound
	if cfg.Server.RunAsUser != "" || cfg.Server.RunAsGroup != "" {
		if err := DropPrivileges(cfg.Server.RunAsUser, cfg.Server.RunAsGroup, deps.GetLogger()); err != nil {
			deps.GetLogger().Error("Failed to drop privileges", slog.String("error", err.Error()))

			registry.StopAll()

			return
		}
	}

	if len(cfg.Server.Listen) == 0 {
		deps.GetLogger().Error("No listen instances configured")

		return
	}

	// Set up SIGHUP handler for reload
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	defer signal.Stop(sighup)

	for {
		select {
		case <-ctx.Done():
			deps.GetLogger().Info("Shutting down all listeners...")
			registry.StopAll()
			deps.GetLogger().Info("Server stopped", slog.String("version", version))

			return

		case <-sighup:
			handleReload(ctx, deps, registry, globalWorkerPool)
		}
	}
}

// handleReload re-reads configuration and applies changes to listeners and settings.
func handleReload(ctx context.Context, deps *Deps, registry *ListenerRegistry, globalWorkerPool WorkerPool) {
	logger := deps.GetLogger()
	logger.Info("Received SIGHUP, reloading configuration...")

	newCfg, err := ReloadConfig()
	if err != nil {
		logger.Error("Failed to reload configuration, keeping current settings", slog.String("error", err.Error()))

		return
	}

	// Diff listeners
	diff := registry.Diff(newCfg.Server.Listen)

	logger.Info("Listener diff computed",
		slog.Int("added", len(diff.Added)),
		slog.Int("removed", len(diff.Removed)),
		slog.Int("changed", len(diff.Changed)),
		slog.Int("unchanged", len(diff.Unchanged)),
	)

	// Stop removed listeners
	for _, key := range diff.Removed {
		logger.Info("Stopping removed listener", slog.String("listener", key))
		registry.Remove(key)
	}

	// Stop changed listeners (they will be restarted with new config)
	for _, listenCfg := range diff.Changed {
		key := listenKey(listenCfg)
		logger.Info("Restarting changed listener", slog.String("listener", key))
		registry.Remove(key)
	}

	// Apply new settings (config, logger, HTTP client, response cache)
	newLogger := ProvideLogger(newCfg)
	newHTTPClient := ProvideHTTPClient(newCfg)
	newRespCache := ProvideResponseCache(newCfg)

	deps.Reload(newCfg, newLogger, newHTTPClient, newRespCache)

	// Use the new logger from now on
	logger = newLogger

	// Start changed listeners with new config
	for _, listenCfg := range diff.Changed {
		if err := registry.startListener(ctx, deps, listenCfg, globalWorkerPool, logger); err != nil {
			logger.Error("Failed to restart changed listener", slog.String("listener", listenKey(listenCfg)), slog.String("error", err.Error()))
		}
	}

	// Start new listeners
	for _, listenCfg := range diff.Added {
		logger.Info("Starting new listener", slog.String("listener", listenKey(listenCfg)))

		if err := registry.startListener(ctx, deps, listenCfg, globalWorkerPool, logger); err != nil {
			logger.Error("Failed to start new listener", slog.String("listener", listenKey(listenCfg)), slog.String("error", err.Error()))
		}
	}

	// Log unchanged listeners
	for _, key := range diff.Unchanged {
		logger.Debug("Listener unchanged, keeping active", slog.String("listener", key))
	}

	logger.Info("Configuration reload complete")
}
