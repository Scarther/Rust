# I09 DNS Resolver

A comprehensive DNS lookup and enumeration tool for security reconnaissance.

## Overview

This tool provides DNS query capabilities commonly used in penetration testing and security assessments:

- Multiple record type lookups (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR)
- Subdomain enumeration with custom wordlists
- Reverse DNS lookups
- Mail server security analysis
- Custom DNS server queries

## Features

### Record Type Lookups
Query specific DNS record types for any domain.

### Subdomain Enumeration
Discover subdomains using built-in or custom wordlists with concurrent queries.

### Mail Security Check
Analyze mail server configuration including SPF and DMARC records.

### Reverse DNS
Perform PTR lookups to discover hostnames for IP addresses.

## Usage

```bash
# Build the project
cargo build --release

# Lookup A records
cargo run -- lookup example.com -t a

# Lookup all record types
cargo run -- lookup example.com -t all

# Full DNS lookup
cargo run -- full example.com

# Enumerate subdomains
cargo run -- enumerate example.com --concurrent 20

# Enumerate with custom wordlist
cargo run -- enumerate example.com --wordlist /path/to/wordlist.txt

# Reverse DNS lookup
cargo run -- reverse 8.8.8.8

# Check mail server security
cargo run -- mail-check example.com

# Query specific DNS server
cargo run -- query example.com --server 8.8.8.8 -t a

# Output as JSON
cargo run -- --format json lookup example.com -t all
```

## Commands

| Command | Description |
|---------|-------------|
| `lookup` | Query specific DNS record type |
| `full` | Perform all common DNS lookups |
| `enumerate` | Enumerate subdomains |
| `reverse` | Reverse DNS lookup for IP |
| `mail-check` | Analyze mail server security |
| `query` | Query using specific DNS server |

## Record Types

- **A** - IPv4 address records
- **AAAA** - IPv6 address records
- **MX** - Mail exchanger records
- **NS** - Name server records
- **TXT** - Text records (SPF, DKIM, etc.)
- **SOA** - Start of Authority records
- **PTR** - Pointer records (reverse DNS)
- **CNAME** - Canonical name records
- **SRV** - Service records

## Security Applications

- **Reconnaissance**: Map target infrastructure
- **Subdomain Discovery**: Find hidden assets
- **Email Security Audit**: Check SPF/DMARC configuration
- **Infrastructure Analysis**: Identify hosting providers and CDNs

## Dependencies

- `tokio` - Async runtime
- `trust-dns-resolver` - DNS resolution
- `clap` - CLI parsing
- `serde` - Serialization
- `tabled` - Table formatting
- `colored` - Terminal colors

## Testing

```bash
cargo test
```

## License

MIT
