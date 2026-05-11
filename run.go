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
			if obs := deps.GetObservability(); obs != nil {
				if err := obs.StartPrometheusServer(); err != nil {
					return err
				}
			}

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

			if pool := deps.GetGRPCConnPool(); pool != nil {
				pool.CloseAll()
			}

			if obs := deps.GetObservability(); obs != nil {
				return obs.Shutdown(ctx)
			}

			return nil
		},
	})
}

func runServerLoop(ctx context.Context, deps *Deps) {
	cfg := deps.GetConfig()

	deps.GetLogger().Info("Starting server", slog.String("version", version))

	registry := NewListenerRegistry()

	systemdSockets, err := NewSystemdSocketSet(deps.GetLogger())
	if err != nil {
		deps.GetLogger().Error("Failed to initialize systemd socket activation", slog.String("error", err.Error()))

		return
	}

	// Resolve user/group credentials before chroot (needs /etc/passwd and /etc/group)
	var creds *Credentials

	if cfg.Server.RunAsUser != "" || cfg.Server.RunAsGroup != "" {
		creds, err = ResolveCredentials(cfg.Server.RunAsUser, cfg.Server.RunAsGroup)
		if err != nil {
			deps.GetLogger().Error("Failed to resolve credentials", slog.String("error", err.Error()))

			return
		}
	}

	// Create global worker pool if configured
	var globalWorkerPool WorkerPool

	if cfg.Server.WorkerPool.MaxWorkers > 0 {
		globalWorkerPool = NewWorkerPool(ctx, cfg.Server.WorkerPool.MaxWorkers, cfg.Server.WorkerPool.MaxQueue, nil)
	}

	// Start initial listeners
	for _, instance := range cfg.Server.Listen {
		if err := registry.startListener(ctx, deps, instance, globalWorkerPool, systemdSockets, deps.GetLogger()); err != nil {
			deps.GetLogger().Error("Failed to start listener", slog.String("error", err.Error()))

			registry.StopAll()

			return
		}
	}

	// Perform chroot after binding listeners but before dropping privileges
	if cfg.Server.Chroot != "" {
		if err := PerformChroot(cfg.Server.Chroot, deps.GetLogger()); err != nil {
			deps.GetLogger().Error("Failed to chroot", slog.String("error", err.Error()))

			registry.StopAll()

			return
		}
	}

	// Drop privileges using pre-resolved credentials
	if creds != nil {
		if err := DropPrivileges(creds, deps.GetLogger()); err != nil {
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
			handleReload(ctx, deps, registry, globalWorkerPool, systemdSockets)
		}
	}
}

// handleReload re-reads configuration and applies changes to listeners and settings.
func handleReload(ctx context.Context, deps *Deps, registry *ListenerRegistry, globalWorkerPool WorkerPool, systemdSockets *SystemdSocketSet) {
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

	if registry.DiffTouchesSystemdSockets(diff) {
		logger.Error("SIGHUP reload cannot add, remove, or change systemd-activated listeners; keeping current configuration. Restart the service while the .socket units stay active to apply listener changes.")

		return
	}

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

	logger = reloadDependencies(deps, newCfg)
	retainReloadedGRPCConnections(deps, newCfg)

	// Start changed listeners with new config
	for _, listenCfg := range diff.Changed {
		if err := registry.startListener(ctx, deps, listenCfg, globalWorkerPool, systemdSockets, logger); err != nil {
			logger.Error("Failed to restart changed listener", slog.String("listener", listenKey(listenCfg)), slog.String("error", err.Error()))
		}
	}

	// Start new listeners
	for _, listenCfg := range diff.Added {
		logger.Info("Starting new listener", slog.String("listener", listenKey(listenCfg)))

		if err := registry.startListener(ctx, deps, listenCfg, globalWorkerPool, systemdSockets, logger); err != nil {
			logger.Error("Failed to start new listener", slog.String("listener", listenKey(listenCfg)), slog.String("error", err.Error()))
		}
	}

	// Log unchanged listeners
	for _, key := range diff.Unchanged {
		logger.Debug("Listener unchanged, keeping active", slog.String("listener", key))
	}

	logger.Info("Configuration reload complete")
}

// reloadDependencies rebuilds reloadable dependencies and swaps them into the shared dependency holder.
func reloadDependencies(deps *Deps, cfg *Config) *slog.Logger {
	logger := ProvideLogger(cfg)
	httpClient := InitializeHTTPClient(cfg, deps.GetObservability())
	respCache := ProvideResponseCache(cfg)

	deps.Reload(cfg, logger, httpClient, respCache)

	return logger
}

// retainReloadedGRPCConnections drops pooled gRPC connections for entries no longer backed by gRPC.
func retainReloadedGRPCConnections(deps *Deps, cfg *Config) {
	pool := deps.GetGRPCConnPool()
	if pool == nil {
		return
	}

	keep := make(map[string]struct{}, len(cfg.DovecotSASL))
	for name, entry := range cfg.DovecotSASL {
		if entry.Transport == transportGRPC {
			keep[name] = struct{}{}
		}
	}

	pool.RetainOnly(keep)
}
