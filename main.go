package main

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/viper"
)

var version = "dev"

type ctxKey string

const loggerKey ctxKey = "logging"

func loadConfig(ctx *Context) *Config {
	cfg, err := NewConfigFile()

	inititalizeLogger(ctx, cfg)

	logger := ctx.Value(loggerKey).(*slog.Logger)

	if err != nil {
		if !errors.Is(err, viper.ConfigFileNotFoundError{}) {
			logger.Error("Error loading config", "error", err)

			os.Exit(1)
		}
	}

	return cfg
}

func inititalizeLogger(ctx *Context, cfg *Config) {
	handlerOpts := &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelInfo,
	}

	if cfg != nil {
		switch cfg.Server.Logging.Level {
		case "none":
			ctx.Set(loggerKey, slog.New(slog.DiscardHandler))

			return
		case "debug":
			handlerOpts.Level = slog.LevelDebug
			handlerOpts.AddSource = true
		case "info":
			handlerOpts.Level = slog.LevelInfo
		case "error":
			handlerOpts.Level = slog.LevelError
		default:
			ctx.Set(loggerKey, slog.New(slog.DiscardHandler))

			return
		}

		if cfg.Server.Logging.JSON {
			ctx.Set(loggerKey, slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts)))

			return
		}
	}

	ctx.Set(loggerKey, slog.New(slog.NewTextHandler(os.Stdout, handlerOpts)))
}

type serverTask struct {
	server  GenericServer
	handler func(conn net.Conn)
}

func runServer(ctx *Context, cfg *Config) {
	if cfg == nil {
		return
	}

	// Create a context that is canceled on interrupt signals (Go 1.26 idiomatic)
	ctx.ctx, _ = signal.NotifyContext(ctx.ctx, os.Interrupt, syscall.SIGTERM)

	logger := ctx.Value(loggerKey).(*slog.Logger)

	go func() {
		<-ctx.Done()
		logger.Info("Received signal, shutting down...")
	}()

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
		srv := NewMultiServer(ctx, cfg, globalWorkerPool)
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

func main() {
	ctx := NewContext()
	cfg := loadConfig(ctx)

	InitializeHttpClient(cfg)

	// Initialize response cache if enabled
	if cfg.Server.ResponseCache.Enabled && cfg.Server.ResponseCache.TTL > 0 {
		respCache = NewInMemoryResponseCache(cfg.Server.ResponseCache.TTL)
	}

	// Initialize OIDC manager
	InitOIDCManager()

	runServer(ctx, cfg)
}
