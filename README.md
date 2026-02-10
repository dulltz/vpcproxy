# vpcproxy

A minimal SOCKS5 proxy server written in Go with zero external dependencies.

## Features

- SOCKS5 CONNECT command (RFC 1928)
- IPv4, IPv6, and domain name address types
- Idle timeout on relayed connections
- Graceful shutdown (SIGINT/SIGTERM)

## Installation

```
go install github.com/dulltz/vpcproxy@latest
```

Or download a pre-built binary from [Releases](https://github.com/dulltz/vpcproxy/releases).

## Usage

```
vpcproxy [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `127.0.0.1:1080` | Listen address |
| `-timeout` | `30s` | Dial timeout |
| `-idle-timeout` | `5m` | Idle timeout for relayed connections |
| `-log-level` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

### Example

```
vpcproxy -listen 0.0.0.0:1080 -log-level debug
```

Test with curl:

```
curl -x socks5h://127.0.0.1:1080 https://example.com
```

## Development

```
make build      # Build binary
make test       # Run tests with race detector
make vet        # Run go vet
make fmt-check  # Check formatting with goimports
make clean      # Remove build artifacts
```
