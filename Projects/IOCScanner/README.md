# IOC Scanner

A fast, parallel Indicator of Compromise (IOC) scanner written in Rust.

## Features

- Hash-based detection (MD5, SHA1, SHA256)
- Domain and IP address matching
- File path pattern matching
- Regex-based content scanning
- Real-time file system monitoring
- Multiple output formats (text, JSON, CSV, Markdown)
- STIX 2.1 export support
- Cross-platform (Linux, Windows, macOS)

## Installation

```bash
# Build from source
cargo build --release

# Install globally
cargo install --path .
```

## Quick Start

### Initialize IOC Database

```bash
# Create a sample database
iocscan init --output ioc_database.yaml
```

### Scan a Directory

```bash
# Basic scan
iocscan scan --path /var/www --database ioc_database.yaml

# With content scanning
iocscan scan --path /home --database iocs.yaml --content-scan

# Output as JSON
iocscan scan --path /tmp --database iocs.yaml --format json --output results.json
```

### Manage IOC Database

```bash
# Add a malicious hash
iocscan database add \
  --database iocs.yaml \
  --ioc-type hash \
  --value "e99a18c428cb38d5f260853678922e03" \
  --description "Known malware" \
  --severity critical

# Add a C2 domain
iocscan database add \
  --database iocs.yaml \
  --ioc-type domain \
  --value "evil-c2.example.com" \
  --description "Command and control server"

# List all IOCs
iocscan database list --database iocs.yaml

# Import from CSV
iocscan database import --database iocs.yaml --input threat_intel.csv

# Export to STIX
iocscan database export --database iocs.yaml --output iocs.stix.json --format stix
```

### Real-time Monitoring

```bash
# Watch a directory for changes
iocscan watch --path /var/www --database iocs.yaml
```

## IOC Database Format

The database supports YAML or JSON format:

```yaml
version: "1.0"
name: "My IOC Database"
description: "Custom indicators"

hashes:
  - hash: "e99a18c428cb38d5f260853678922e03"
    type: "md5"
    description: "Malware sample"
    severity: "critical"
    tags: ["malware", "apt"]

domains:
  - domain: "evil.com"
    description: "Known C2"
    severity: "high"

ip_addresses:
  - ip: "192.168.1.100"
    description: "Compromised host"
    severity: "medium"

file_paths:
  - path: "/tmp/.hidden"
    description: "Suspicious hidden file"
    severity: "medium"

patterns:
  - pattern: "eval\\s*\\(\\s*base64_decode"
    description: "PHP webshell"
    severity: "critical"
```

## Command Reference

### scan

```
iocscan scan [OPTIONS] --path <PATH> --database <DATABASE>

Options:
  -p, --path <PATH>          Path to scan
  -d, --database <DATABASE>  IOC database file
  -j, --workers <WORKERS>    Parallel workers [default: 4]
  -m, --max-size <SIZE>      Max file size in MB [default: 100]
  -L, --follow-links         Follow symbolic links
  -c, --content-scan         Scan file contents
      --depth <DEPTH>        Maximum directory depth
  -f, --format <FORMAT>      Output format [text, json, csv, markdown]
  -O, --output <FILE>        Output file
  -v, --verbose              Increase verbosity
```

### database

```
iocscan database add      # Add IOC to database
iocscan database list     # List IOCs
iocscan database import   # Import from file
iocscan database export   # Export to file
```

### watch

```
iocscan watch --path <PATH> --database <DATABASE>
```

## Performance

The scanner uses parallel processing for optimal performance:

| Files | Threads | Time |
|-------|---------|------|
| 10,000 | 1 | ~15s |
| 10,000 | 4 | ~5s |
| 10,000 | 8 | ~3s |
| 100,000 | 8 | ~25s |

## Integration

### SIEM Integration

Export results as JSON for SIEM ingestion:

```bash
iocscan scan -p /var/log -d iocs.yaml -f json -O /var/log/ioc_scan.json
```

### Cron Job

```bash
# Daily scan at 2 AM
0 2 * * * /usr/local/bin/iocscan scan -p /home -d /etc/iocs.yaml -f json -O /var/log/ioc_$(date +\%Y\%m\%d).json
```

### Docker

```dockerfile
FROM rust:1.75-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/iocscan /usr/local/bin/
ENTRYPOINT ["iocscan"]
```

## MITRE ATT&CK Coverage

| Technique | Detection |
|-----------|-----------|
| T1036 Masquerading | Hash mismatch detection |
| T1505.003 Web Shell | Pattern matching |
| T1071 Application Layer Protocol | Domain/IP IOCs |
| T1059 Command and Scripting | Script pattern detection |

## License

MIT License

## See Also

- [Rust Security Bible](../../README.md)
- [Blue Team Chapter](../../Chapter_04_Blue_Team/)
