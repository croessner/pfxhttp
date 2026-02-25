package main

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"go.uber.org/fx"
)

type ctxKey string

const loggerKey ctxKey = "logging"

type serverTask struct {
	server  GenericServer
	handler func(conn net.Conn)
}

// RunServer starts the server lifecycle managed by fx.
func RunServer(lc fx.Lifecycle, deps *Deps) {
	cfg := deps.Config
	logger := deps.Logger

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
			logger.Info("Server stopping...")
			cancelServer()
			<-done

			return nil
		},
	})
}

func runServerLoop(ctx context.Context, deps *Deps) {
	cfg := deps.Config
	logger := deps.Logger

	var (
		wg               sync.WaitGroup
		globalWorkerPool WorkerPool
		tasks            []serverTask
	)

	logger.Info("Starting server", slog.String("version", version))

	if cfg.Server.WorkerPool.MaxWorkers > 0 {
		globalWorkerPool = NewWorkerPool(ctx, cfg.Server.WorkerPool.MaxWorkers, cfg.Server.WorkerPool.MaxQueue, &wg)
	}

	for _, instance := range cfg.Server.Listen {
		srv := NewMultiServer(ctx, deps, globalWorkerPool)
		if err := srv.Listen(instance); err != nil {
			logger.Error("Failed to listen", slog.String("kind", instance.Kind), slog.String("name", instance.Name), slog.String("error", err.Error()))

			return
		}

		var handler func(conn net.Conn)
		switch instance.Kind {
		case "socket_map":
			handler = srv.HandleNetStringConnection
		case "policy_service":
			if instance.Name == "" {
				logger.Error("Policy service requires a name")
				return
			}
			handler = srv.HandlePolicyServiceConnection
		case "dovecot_sasl":
			if instance.Name == "" {
				logger.Error("Dovecot SASL requires a name")
				return
			}
			handler = srv.HandleDovecotSASLConnection
		default:
			logger.Error("Invalid listen instance", slog.String("instance", instance.Kind))
			return
		}

		tasks = append(tasks, serverTask{
			server:  srv,
			handler: handler,
		})
	}

	// All listeners are ready, now drop privileges if configured
	if cfg.Server.RunAsUser != "" || cfg.Server.RunAsGroup != "" {
		if err := DropPrivileges(cfg.Server.RunAsUser, cfg.Server.RunAsGroup, logger); err != nil {
			logger.Error("Failed to drop privileges", slog.String("error", err.Error()))

			return
		}
	}

	if len(tasks) > 0 {
		for _, task := range tasks {
			wg.Add(1)
			go func(t serverTask) {
				defer wg.Done()

				go func() {
					<-ctx.Done()
					t.server.Stop()
				}()

				if err := t.server.Start(t.handler); err != nil {
					logger.Error("Server error", slog.String("error", err.Error()))
				}
			}(task)
		}

		wg.Wait()
		logger.Info("Server stopped", slog.String("version", version))
	} else {
		logger.Error("No listen instances configured")
	}
}
