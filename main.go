package main

import (
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

type ctxKey string

const loggerKey ctxKey = "logging"

const (
	socketMapKind     = "socket_map"
	policyServiceKind = "policy_service"
)

func loadConfig(ctx *Context) *Config {
	cfg, err := NewConfigFile()

	inititalizeLogger(ctx, cfg)

	logger := ctx.Value(loggerKey).(*slog.Logger)

	if err != nil {
		logger.Error(
			"Error loading config",
			"error", err,
		)

		return nil
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
		case "debug":
			handlerOpts.Level = slog.LevelDebug
			handlerOpts.AddSource = true
		case "error":
			handlerOpts.Level = slog.LevelError
		default:
			handlerOpts.Level = slog.LevelInfo
		}

		if cfg.Server.Logging.JSON {
			ctx.Set(loggerKey, slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts)))

			return
		}
	}

	ctx.Set(loggerKey, slog.New(slog.NewTextHandler(os.Stdout, handlerOpts)))
}

func handleSignals(server GenericServer) {
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	logger := server.GetContext().Value(loggerKey).(*slog.Logger)

	go func() {
		sig := <-signalChan
		logger.Debug("Received signal", slog.String("signal", sig.String()))

		if server != nil {
			server.Stop()
		}

		os.Exit(0)
	}()
}

func runServer(ctx *Context, cfg *Config) {
	logger := ctx.Value(loggerKey).(*slog.Logger)

	logger.Info("Starting server", slog.String("version", version))

	startServer := func(listenConfig Listen, handler func(conn net.Conn)) {
		server := NewServer(ctx, cfg)

		handleSignals(server)

		err := server.Start(listenConfig, handler)

		if err != nil {
			logger.Error("Failed to start server", slog.String("kind", listenConfig.Kind), slog.String("error", err.Error()))
		}
	}

	for _, listenConfig := range cfg.Server.Listen {
		switch listenConfig.Kind {
		case socketMapKind:
			go startServer(listenConfig, NewServer(ctx, cfg).HandleNetStringConnection)
		case policyServiceKind:
			if listenConfig.Name == "" {
				logger.Error("Policy service requires a valid name")

				return
			}

			go startServer(listenConfig, NewServer(ctx, cfg).HandlePolicyServiceConnection)
		default:
			logger.Error("Unsupported listen kind", slog.String("kind", listenConfig.Kind))

			return
		}
	}

	select {} // Block indefinitely
}

func main() {
	ctx := NewContext()
	cfg := loadConfig(ctx)

	if cfg != nil {
		InitializeHttpClient(cfg)
		runServer(ctx, cfg)
	}
}
