# I10 Banner Grabber

A comprehensive tool for grabbing service banners from network ports for reconnaissance.

## Overview

Banner grabbing is a fundamental reconnaissance technique used to identify services, versions, and potential vulnerabilities on target systems. This tool provides:

- Single and multi-port banner grabbing
- Protocol-specific probes
- SSL/TLS support
- Service fingerprinting
- Security analysis

## Features

### Service Detection
Automatically identifies services based on banner patterns:
- SSH, HTTP, FTP, SMTP, MySQL, PostgreSQL, Redis
- Version extraction from banners
- OS fingerprinting from server headers

### Protocol Probes
Sends appropriate probes for each protocol:
- HTTP: GET request
- SMTP: EHLO command
- Redis: PING command
- Raw: Wait for banner

### Security Analysis
Identifies potential security issues:
- Version disclosure
- Outdated protocols (SSLv2, SSLv3, SSH-1)
- Missing security headers
- Debug mode detection

## Usage

```bash
# Build the project
cargo build --release

# Grab single port banner
cargo run -- single example.com 22

# Grab banner with SSL
cargo run -- single example.com 443 --ssl

# Specify protocol hint
cargo run -- single example.com 25 --protocol smtp

# Scan multiple ports
cargo run -- scan example.com --ports "21,22,80,443"

# Scan port range
cargo run -- scan example.com --ports "1-1000" --concurrent 50

# Quick scan common ports
cargo run -- quick example.com

# Detailed HTTP banner analysis
cargo run -- http example.com --port 80

# HTTPS with analysis
cargo run -- http example.com --port 443 --ssl

# Output as JSON
cargo run -- --format json single example.com 80
```

## Commands

| Command | Description |
|---------|-------------|
| `single` | Grab banner from single port |
| `scan` | Scan multiple ports |
| `quick` | Quick scan of common ports |
| `http` | Detailed HTTP banner analysis |

## Security Applications

- **Service Enumeration**: Identify running services
- **Version Detection**: Find software versions for vulnerability research
- **Configuration Audit**: Check for information disclosure
- **Network Mapping**: Understand target infrastructure

## Dependencies

- `tokio` - Async runtime
- `tokio-native-tls` - SSL/TLS support
- `clap` - CLI parsing
- `regex` - Pattern matching
- `serde` - Serialization
- `tabled` - Table formatting

## Testing

```bash
cargo test
```

## License

MIT
