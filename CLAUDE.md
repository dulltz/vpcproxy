# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
make build    # Build binary (output: vpcproxy)
make test     # Run all tests (go test ./...)
make clean    # Remove build artifacts

# Run a single test
go test -run TestConnect_IPv4 ./...
```

## Architecture

vpcproxy is a minimal SOCKS5 proxy server written in Go with zero external dependencies.

- **main.go** - Entry point. Parses flags (`-listen`, `-log-level`, `-timeout`, `-idle-timeout`, `-max-connections`, `-block-metadata`), sets up TCP listener, accept loop (with semaphore-based connection limit and exponential backoff), and graceful shutdown.
- **socks5.go** - SOCKS5 protocol implementation. `Server` struct handles negotiation (NO AUTH only) and CONNECT command. Supports IPv4, IPv6, and domain name address types. Includes SSRF mitigation by blocking cloud metadata endpoints (`169.254.0.0/16`).
- **relay.go** - Bidirectional TCP relay with idle timeout using per-read/write deadlines.
- **socks5_test.go** - Integration tests using in-process test server and echo server.

## Conventions

- When adding new features or flags, update `README.md` (Features section and Flags table) to keep documentation in sync.
