package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "listen address")
	logLevel := flag.String("log-level", "info", "log level (debug/info/warn/error)")
	timeout := flag.Duration("timeout", 30*time.Second, "dial timeout")
	idleTimeout := flag.Duration("idle-timeout", 5*time.Minute, "idle timeout")
	flag.Parse()

	// Setup logger
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	srv := &Server{
		Timeout:     *timeout,
		IdleTimeout: *idleTimeout,
		Logger:      logger,
	}

	// Listen
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	logger.Info("listening", "addr", ln.Addr())

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					logger.Error("accept failed", "error", err)
					continue
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				srv.handleConnection(conn)
			}()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	ln.Close()

	// Wait for existing connections with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("all connections closed")
	case <-time.After(10 * time.Second):
		logger.Warn("shutdown timeout, forcing exit")
	}
}
