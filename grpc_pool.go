// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCConnPool maintains long-lived *grpc.ClientConn instances keyed by
// dovecot_sasl entry name. A single connection multiplexes many concurrent
// RPCs over HTTP/2, so callers should reuse pooled connections rather than
// dial per-request.
type GRPCConnPool struct {
	mu    sync.Mutex
	conns map[string]*pooledConn
}

// pooledConn pairs a connection with a fingerprint of the configuration that
// produced it. When a SIGHUP-triggered reload changes the transport settings,
// the fingerprint mismatch forces a re-dial on next access.
type pooledConn struct {
	conn        *grpc.ClientConn
	fingerprint uint64
}

// NewGRPCConnPool returns an empty connection pool.
func NewGRPCConnPool() *GRPCConnPool {
	return &GRPCConnPool{conns: make(map[string]*pooledConn)}
}

// Get returns a connection for the given entry name, creating one on demand.
// If the cached connection was built from a different fingerprint, it is
// closed and replaced.
func (p *GRPCConnPool) Get(name string, settings GRPCRequest) (*grpc.ClientConn, error) {
	if settings.Address == "" {
		return nil, errors.New("grpc.address is required")
	}

	fp := grpcFingerprint(settings)

	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.conns[name]; ok {
		if existing.fingerprint == fp {
			return existing.conn, nil
		}

		_ = existing.conn.Close()
		delete(p.conns, name)
	}

	conn, err := dialGRPC(settings)
	if err != nil {
		return nil, err
	}

	p.conns[name] = &pooledConn{conn: conn, fingerprint: fp}

	return conn, nil
}

// CloseAll closes every cached connection. Safe to call multiple times.
func (p *GRPCConnPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for name, pc := range p.conns {
		if cerr := pc.conn.Close(); cerr != nil {
			slog.Default().Warn("failed to close gRPC connection", slog.String("entry", name), slog.String("error", cerr.Error()))
		}
	}

	p.conns = make(map[string]*pooledConn)
}

// RetainOnly closes connections whose entry name is no longer present in
// keepNames. This is intended for SIGHUP-driven reloads where dovecot_sasl
// entries get removed or switched away from the gRPC transport.
func (p *GRPCConnPool) RetainOnly(keepNames map[string]struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for name, pc := range p.conns {
		if _, keep := keepNames[name]; keep {
			continue
		}

		if cerr := pc.conn.Close(); cerr != nil {
			slog.Default().Warn("failed to close gRPC connection", slog.String("entry", name), slog.String("error", cerr.Error()))
		}

		delete(p.conns, name)
	}
}

// dialGRPC creates a new client connection for the supplied settings. TLS is
// applied when settings.TLS.Enabled is true; otherwise the connection is
// plaintext (suitable only for trusted networks).
func dialGRPC(settings GRPCRequest) (*grpc.ClientConn, error) {
	options := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.WaitForReady(false)),
	}

	if settings.TLS.Enabled {
		tlsConfig, err := buildClientTLSConfig(settings.TLS)
		if err != nil {
			return nil, err
		}

		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(settings.Address, options...)
	if err != nil {
		return nil, fmt.Errorf("dial gRPC %q: %w", settings.Address, err)
	}

	return conn, nil
}

// buildClientTLSConfig converts the configured TLS section into a *tls.Config
// usable with grpc.credentials.NewTLS.
func buildClientTLSConfig(cfg GRPCTLS) (*tls.Config, error) {
	minVersion, err := resolveTLSMinVersion(cfg.MinVersion)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.SkipVerify,
		MinVersion:         minVersion,
	}

	if cfg.CACert != "" {
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read ca_cert: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_cert: no PEM certificates found")
		}

		tlsConfig.RootCAs = pool
	}

	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		if cfg.ClientCert == "" || cfg.ClientKey == "" {
			return nil, errors.New("client_cert and client_key must both be set for mTLS")
		}

		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client_cert/client_key: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// grpcFingerprint produces a stable hash of the connection-relevant fields so
// the pool can detect configuration changes after a reload.
func grpcFingerprint(s GRPCRequest) uint64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "addr=%s|to=%s|tls=%t|sni=%s|skip=%t|min=%s|ca=%s|cert=%s|key=%s",
		s.Address,
		s.Timeout,
		s.TLS.Enabled,
		s.TLS.ServerName,
		s.TLS.SkipVerify,
		s.TLS.MinVersion,
		s.TLS.CACert,
		s.TLS.ClientCert,
		s.TLS.ClientKey,
	)

	return h.Sum64()
}

// resolveTLSMinVersion converts the YAML "min_tls_version" value (1.2, 1.3,
// or empty) into a crypto/tls version constant. Anything below 1.2 is
// rejected — pfxhttp does not negotiate down to TLS 1.0/1.1 even if the
// peer would accept it. Empty defaults to TLS 1.2 so the floor is safe by
// default.
func resolveTLSMinVersion(value string) (uint16, error) {
	switch value {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported min_tls_version %q (allowed: 1.2, 1.3)", value)
	}
}

// effectiveGRPCTimeout returns the configured timeout or a sensible default
// when none was provided in the YAML config.
func effectiveGRPCTimeout(s GRPCRequest) time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}

	return 5 * time.Second
}
