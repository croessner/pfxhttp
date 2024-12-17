package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

var logger *slog.Logger

func init() {
	logger = slog.Default()
}

func loadConfig() *Config {
	cfg, err := NewConfigFile()

	if err != nil {
		logger.Error(
			"Error loading config",
			"error", err,
		)

		return nil
	}

	return cfg
}

func handleSignals(server *TCPNetStringServer) {
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

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
	server := NewTCPNetStringServer(ctx, cfg, logger)

	handleSignals(server)

	err := server.Start()
	if err != nil {
		logger.Error("Server error", slog.String("error", err.Error()))
	}
}

func main() {
	ctx := context.Background()
	cfg := loadConfig()

	if cfg != nil {
		InitializeHttpClient(cfg)
		runServer(ctx, cfg)
	}
}
