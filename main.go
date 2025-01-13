package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

type ctxKey string

const loggerKey ctxKey = "logging"

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

func newNetStringServerInstance(instance Listen, ctx *Context, cfg *Config) {
	logger := ctx.Value(loggerKey).(*slog.Logger)
	server := NewMultiServer(ctx, cfg)

	handleSignals(server)

	err := server.Start(instance, server.HandleNetStringConnection)
	if err != nil {
		logger.Error("Server error", slog.String("error", err.Error()))

		return
	}
}

func newPolicyServiceInstance(instance Listen, ctx *Context, cfg *Config) {
	logger := ctx.Value(loggerKey).(*slog.Logger)
	server := NewMultiServer(ctx, cfg)

	handleSignals(server)

	err := server.Start(instance, server.HandlePolicyServiceConnection)
	if err != nil {
		logger.Error("Server error", slog.String("error", err.Error()))

		return
	}
}

func runServer(ctx *Context, cfg *Config) {
	logger := ctx.Value(loggerKey).(*slog.Logger)

	logger.Info("Starting server", slog.String("version", version))

	for _, instance := range cfg.Server.Listen {
		if instance.Kind == "socket_map" {
			go newNetStringServerInstance(instance, ctx, cfg)
		} else if instance.Kind == "policy_service" {
			if instance.Name != "" {
				go newPolicyServiceInstance(instance, ctx, cfg)
			} else {
				logger.Error("Policy service requires a name")

				return
			}
		} else {
			logger.Error("Invalid listen instance", slog.String("instance", instance.Kind))

			return
		}
	}

	select {}
}

func main() {
	ctx := NewContext()
	cfg := loadConfig(ctx)

	if cfg != nil {
		InitializeHttpClient(cfg)
		runServer(ctx, cfg)
	}
}
