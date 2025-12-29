# B14 - URL Parser

A comprehensive URL parsing and analysis tool for web security applications.

## Overview

This tool parses, analyzes, and manipulates URLs with security-focused features. Essential for:

- **Phishing Analysis**: Identifying suspicious URL patterns
- **Web Application Security**: Validating and sanitizing URLs
- **Threat Intelligence**: Extracting domains and indicators
- **Log Analysis**: Parsing URLs from access logs
- **Security Testing**: Crafting and analyzing test URLs

## Features

- Complete URL parsing and component extraction
- Domain name analysis (TLD, subdomain detection)
- Security analysis for suspicious patterns
- URL encoding/decoding
- Query parameter parsing
- URL building from components
- URL normalization and comparison
- JSON output support
- Detection of credentials in URLs

## Installation

```bash
cd B14_URL_Parser
cargo build --release
```

## Usage

### Parse URL

```bash
# Parse a URL and show all components
./target/release/url_parser parse "https://user:pass@example.com:8080/path?query=value#fragment"

# Parse with JSON output
./target/release/url_parser parse "https://example.com/api/v1" --json

# Parse URL without scheme
./target/release/url_parser parse "example.com/path"
```

### Extract Components

```bash
# Extract specific components
./target/release/url_parser extract "https://example.com:8080/path" --component host
./target/release/url_parser extract "https://example.com:8080/path" --component port
./target/release/url_parser extract "https://example.com/path?q=test" --component query
./target/release/url_parser extract "https://example.com/page#section" --component fragment
```

### URL Encoding/Decoding

```bash
# Decode URL-encoded string
./target/release/url_parser decode "hello%20world%21"

# Encode string for URL
./target/release/url_parser encode "hello world!"
```

### Parse Query Parameters

```bash
# Parse query string from URL
./target/release/url_parser query "https://example.com?foo=bar&baz=qux"

# Parse raw query string
./target/release/url_parser query "?name=value&key=data"

# JSON output
./target/release/url_parser query "?a=1&b=2" --json
```

### Build URLs

```bash
# Build URL from components
./target/release/url_parser build --host example.com

# Full URL with all components
./target/release/url_parser build \
  --scheme https \
  --host api.example.com \
  --port 8443 \
  --path /api/v1/users \
  --query "limit=10&offset=0" \
  --fragment section1
```

### Security Analysis

```bash
# Analyze URL for security issues
./target/release/url_parser security "https://user:password@example.com"

# Analyze phishing-like URL
./target/release/url_parser security "http://login.bank.suspicious.tk/verify?token=abc123"

# JSON output for automation
./target/release/url_parser security "https://example.com" --json
```

### Compare URLs

```bash
# Compare two URLs
./target/release/url_parser compare "https://example.com" "https://Example.Com/"

# Check if URLs are equivalent
./target/release/url_parser compare "http://example.com:80/path" "http://example.com/path"
```

### Normalize URLs

```bash
# Normalize URL (lowercase, remove default ports, etc.)
./target/release/url_parser normalize "HTTP://EXAMPLE.COM:80/Path/?b=2&a=1"
```

## Security Checks Performed

| Category | Check | Severity |
|----------|-------|----------|
| Credentials | Password in URL | Critical |
| Credentials | Username in URL | Warning |
| Encryption | HTTP instead of HTTPS | Warning |
| Domain | Suspicious TLD (.tk, .ml, etc.) | Info |
| Domain | IP address instead of domain | Warning |
| Domain | Excessive subdomains | Warning |
| Domain | Mixed letters and numbers | Info |
| Domain | Very long domain name | Info |
| Query | Sensitive parameters (password, token, etc.) | Critical |
| Length | Very long URL (>2000 chars) | Info |
| Port | Non-standard port | Info |
| Encoding | Null bytes or newlines | Warning |

## Output Examples

### URL Parsing Output

```
URL Analysis
============================================================
  Original:       https://api.example.com:8080/v1/users?limit=10#results
  Length:         52 characters

Components:
  Scheme:         https
  Host:           api.example.com
  Port:           8080 (explicit)
  Path:           /v1/users
  Query:          limit=10
  Fragment:       #results

Domain Analysis:
  TLD:            com
  Registered:     example.com
  Subdomain:      api
  Subdomain Count: 1

Query Parameters:
  limit=10
```

### Security Analysis Output

```
Security Analysis
============================================================
  URL: https://user:password@evil.tk/login?api_key=secret
  Risk Level: high

Issues Found:
  [critical] Credentials: Password embedded in URL - visible in logs and history
  [critical] Query Parameters: Sensitive parameter in URL: api_key
  [warning] Credentials: Username embedded in URL
  [info] Domain: Uses potentially suspicious TLD: .tk

Recommendations:
  - Remove credentials from URL and use proper authentication
  - Never pass sensitive data in URL query parameters
```

## Rust Concepts Demonstrated

1. **URL Parsing**: Using the `url` crate
2. **Percent Encoding**: URL encoding/decoding
3. **HashMap Usage**: Query parameter storage
4. **Subcommands**: clap subcommand patterns
5. **Option Handling**: Optional URL components
6. **Error Types**: Custom error enum
7. **Serialization**: serde for JSON output
8. **String Manipulation**: Domain parsing

## Common Use Cases

### Phishing Detection
```bash
# Check for suspicious patterns
./url_parser security "http://paypal.login.verify-account.tk/secure"
```

### Log Analysis
```bash
# Extract domains from URLs
./url_parser extract "$URL" --component host
```

### Security Testing
```bash
# Build test URLs with various payloads
./url_parser build --host target.com --path "/api" --query "id=1%27%20OR%201=1--"
```

### URL Sanitization
```bash
# Normalize and compare URLs
./url_parser normalize "$USER_INPUT"
```

## Testing

```bash
cargo test
```

## License

MIT License
