# B06 - HTTP Client Tool

A security-focused HTTP client for making web requests and analyzing responses.

## Overview

This project provides comprehensive HTTP client functionality with security analysis:

- **GET Requests**: Fetch web resources with custom headers
- **POST Requests**: Submit data to endpoints
- **HEAD Requests**: Check resource headers
- **Security Analysis**: Evaluate security headers
- **Connectivity Checks**: Verify endpoint availability

## Security Features

1. **Security Header Analysis**: Checks for HSTS, CSP, X-Frame-Options, etc.
2. **Information Disclosure Detection**: Warns about server version leaks
3. **SSL/TLS Awareness**: Proper certificate verification by default
4. **Request/Response Logging**: Detailed output for forensics

## Building

```bash
cargo build --release
```

## Usage

### GET Request

```bash
# Simple GET
./http_client get https://example.com

# With custom headers
./http_client get https://api.example.com -H "Authorization: Bearer token"

# Save response to file
./http_client get https://example.com -s response.html

# Custom User-Agent
./http_client get https://example.com -A "Mozilla/5.0"

# Different output formats
./http_client get https://example.com -o json
./http_client get https://example.com -o headers
./http_client get https://example.com -o body

# Limit redirects
./http_client get https://example.com -r 5

# Custom timeout
./http_client get https://example.com -t 60

# Skip SSL verification (INSECURE!)
./http_client get https://self-signed.example.com --insecure
```

### POST Request

```bash
# POST with inline data
./http_client post https://api.example.com -d "key=value"

# POST JSON data
./http_client post https://api.example.com -d '{"key":"value"}' -j

# POST from file
./http_client post https://api.example.com -f data.json -j

# With custom headers
./http_client post https://api.example.com -d "data" -H "X-Custom: value"
```

### HEAD Request

```bash
# Get headers only
./http_client head https://example.com
```

### Security Analysis

```bash
# Analyze security headers
./http_client analyze https://example.com

# With custom User-Agent
./http_client analyze https://example.com -A "SecurityScanner/1.0"
```

### Connectivity Check

```bash
# Check if URL is accessible
./http_client check https://example.com

# Expect specific status code
./http_client check https://example.com/api -e 401

# Quick timeout
./http_client check https://example.com -t 5
```

## Key Rust Concepts Demonstrated

### HTTP Client Usage

```rust
use reqwest::blocking::Client;

// Build a client with configuration
let client = Client::builder()
    .timeout(Duration::from_secs(30))
    .redirect(Policy::limited(10))
    .user_agent("MyClient/1.0")
    .build()?;

// Make requests
let response = client.get("https://example.com")
    .header("Authorization", "Bearer token")
    .send()?;
```

### URL Parsing

```rust
use url::Url;

// Parse and validate URLs
let url = Url::parse("https://example.com/path?query=value")?;
println!("Scheme: {}", url.scheme());
println!("Host: {}", url.host_str().unwrap());
println!("Path: {}", url.path());
```

### Header Manipulation

```rust
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

let mut headers = HeaderMap::new();
headers.insert(
    HeaderName::from_static("x-custom-header"),
    HeaderValue::from_static("custom-value")
);
```

### Error Handling with Context

```rust
use anyhow::Context;

let response = client.get(url)
    .send()
    .context("Failed to send request")?;

let body = response.text()
    .context("Failed to read response body")?;
```

## Security Headers Checked

| Header | Purpose | Severity |
|--------|---------|----------|
| Strict-Transport-Security | Enforce HTTPS | 8 |
| Content-Security-Policy | Prevent XSS/injection | 9 |
| X-Frame-Options | Prevent clickjacking | 7 |
| X-Content-Type-Options | Prevent MIME sniffing | 6 |
| X-XSS-Protection | XSS filter (legacy) | 5 |
| Referrer-Policy | Control referrer leakage | 5 |
| Permissions-Policy | Control browser features | 6 |

## Information Disclosure Checks

- Server version in `Server` header
- Technology stack in `X-Powered-By`
- ASP.NET version in `X-AspNet-Version`
- Debug mode indicators

## Security Considerations

1. **Certificate Verification**: Enabled by default, disable only for testing
2. **Redirect Following**: Limited to prevent redirect loops
3. **Timeouts**: Always set to prevent hanging
4. **User-Agent**: Can reveal tool identity
5. **Credentials**: Never log sensitive headers

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

## Dependencies

- `clap` - Command-line argument parsing
- `anyhow` - Error handling with context
- `thiserror` - Custom error type derivation
- `colored` - Terminal color output
- `reqwest` - HTTP client library
- `url` - URL parsing
- `serde` / `serde_json` - Serialization
- `http` - HTTP types and utilities
