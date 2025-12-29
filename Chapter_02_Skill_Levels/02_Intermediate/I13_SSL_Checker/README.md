# I13 SSL Checker

A comprehensive tool for checking SSL/TLS certificates and configuration.

## Overview

Essential for security audits, compliance checks, and vulnerability assessments. This tool provides:

- Certificate chain verification
- Expiration checking
- Protocol version detection
- Security grading
- Batch checking

## Features

### Certificate Analysis
Parse and display detailed certificate information.

### Expiration Monitoring
Check certificate expiration with customizable warning thresholds.

### Protocol Testing
Test which TLS/SSL versions are supported.

### Security Grading
Comprehensive security assessment with letter grades.

### Batch Checking
Check multiple hosts concurrently.

## Usage

```bash
# Build the project
cargo build --release

# Check a single host
cargo run -- check example.com

# Check with custom port
cargo run -- check example.com --port 8443

# Skip certificate verification (testing)
cargo run -- check example.com --insecure

# Check certificate expiration
cargo run -- expiry example.com --warn-days 30

# Check multiple hosts
cargo run -- batch --hosts "google.com,github.com,microsoft.com"

# Test supported protocols
cargo run -- protocols example.com

# Get security grade
cargo run -- grade example.com

# Get certificate in PEM format
cargo run -- pem example.com

# Output as JSON
cargo run -- --format json check example.com
```

## Commands

| Command | Description |
|---------|-------------|
| `check` | Check single host certificate |
| `expiry` | Check certificate expiration |
| `batch` | Check multiple hosts |
| `protocols` | Test supported protocols |
| `grade` | Security grade assessment |
| `pem` | Output certificate as PEM |

## Security Grades

| Grade | Score | Description |
|-------|-------|-------------|
| A+ | 90-100 | Excellent configuration |
| A | 80-89 | Good configuration |
| B | 70-79 | Acceptable |
| C | 60-69 | Needs improvement |
| D | 50-59 | Poor |
| F | <50 | Critical issues |

## Checked Items

- Certificate expiration
- Key strength (minimum 2048 bits)
- Signature algorithm (no SHA1/MD5)
- Self-signed certificates
- Protocol versions
- Chain validity

## Security Applications

- **Audit**: Check certificate configurations
- **Monitoring**: Track expiration dates
- **Compliance**: Verify security requirements
- **Assessment**: Identify vulnerabilities

## Dependencies

- `tokio` - Async runtime
- `native-tls` - TLS support
- `x509-parser` - Certificate parsing
- `chrono` - Date handling
- `clap` - CLI parsing

## Testing

```bash
cargo test
```

## License

MIT
