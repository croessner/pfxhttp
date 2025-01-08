package main

import (
	"context"
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
		logger.Info("Received signal", slog.String("signal", sig.String()))

		if server != nil {
			server.Stop()
		}

		os.Exit(0)
	}()
}

func runServer(ctx context.Context, cfg *Config) {
	server := NewNetStringServer(ctx, cfg)

	handleSignals(server)

	err := server.Start()
	if err != nil {
		logger := server.GetContext().Value(loggerKey).(*slog.Logger)

		logger.Error("Server error", slog.String("error", err.Error()))
	}
}

func main() {
	ctx := NewContext()
	cfg := loadConfig(ctx)

	if cfg != nil {
		InitializeHttpClient(cfg)
		runServer(ctx, cfg)
	}
}
