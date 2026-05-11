package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/viper"
)

// ProvideConfig loads the configuration file and returns the Config.
func ProvideConfig() (*Config, error) {
	cfg, err := NewConfigFile()
	if err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			return nil, fmt.Errorf("error loading config: %w", err)
		}
	}

	return cfg, nil
}

// ProvideLogger creates a structured logger based on the configuration.
// Also used during reload via CreateLogger.
func ProvideLogger(cfg *Config) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelInfo,
	}

	if cfg != nil {
		switch cfg.Server.Logging.Level {
		case "none":
			return slog.New(slog.DiscardHandler)
		case "debug":
			handlerOpts.Level = slog.LevelDebug
			handlerOpts.AddSource = true
		case "info":
			handlerOpts.Level = slog.LevelInfo
		case "error":
			handlerOpts.Level = slog.LevelError
		default:
			return slog.New(slog.DiscardHandler)
		}

		if cfg.Server.Logging.UseSystemd {
			handlerOpts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
				if len(groups) == 0 && a.Key == slog.TimeKey {
					return slog.Attr{}
				}

				return a
			}
		}

		if cfg.Server.Logging.JSON {
			return slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts))
		}
	}

	return slog.New(slog.NewTextHandler(os.Stdout, handlerOpts))
}

// ProvideObservability creates the process-wide metrics and tracing runtime.
func ProvideObservability(cfg *Config, logger *slog.Logger) (*Observability, error) {
	return NewObservability(context.Background(), cfg.Server.Observability, version, logger)
}

// ProvideHTTPClient creates the HTTP client from the configuration.
func ProvideHTTPClient(cfg *Config, obs *Observability) *http.Client {
	return InitializeHTTPClient(cfg, obs)
}

// ProvideOIDCManager creates a new OIDCManager with the HTTP client.
func ProvideOIDCManager(httpClient *http.Client) *OIDCManager {
	return NewOIDCManager(httpClient)
}

// ProvideResponseCache creates a response cache if enabled in the configuration.
func ProvideResponseCache(cfg *Config) ResponseCache {
	if cfg.Server.ResponseCache.Enabled && cfg.Server.ResponseCache.TTL > 0 {
		return NewInMemoryResponseCache(cfg.Server.ResponseCache.TTL)
	}

	return nil
}

// ProvideGRPCConnPool creates the shared connection pool used by gRPC SASL
// authenticators.
func ProvideGRPCConnPool() *GRPCConnPool {
	return NewGRPCConnPool()
}

// ProvideDeps bundles all dependencies into a single Deps struct.
func ProvideDeps(
	cfg *Config,
	logger *slog.Logger,
	httpClient *http.Client,
	oidcManager *OIDCManager,
	respCache ResponseCache,
	grpcPool *GRPCConnPool,
	obs *Observability,
) *Deps {
	return &Deps{
		Config:        cfg,
		Logger:        logger,
		HTTPClient:    httpClient,
		OIDCManager:   oidcManager,
		RespCache:     respCache,
		GRPCConnPool:  grpcPool,
		Observability: obs,
	}
}
