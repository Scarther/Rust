# B13 - IP Validator

A comprehensive IP address validation and analysis tool for network security applications.

## Overview

This tool validates and analyzes IP addresses and CIDR notation, essential for:

- **Firewall Configuration**: Validating IP ranges and CIDR blocks
- **Log Analysis**: Parsing and classifying IPs from log files
- **Network Security**: Identifying private vs public IPs
- **Penetration Testing**: Understanding network ranges
- **Incident Response**: Quick IP classification

## Features

- IPv4 and IPv6 validation
- CIDR notation parsing and analysis
- Network containment checking
- IP range enumeration
- Private/public classification
- Special address detection (loopback, multicast, etc.)
- Reverse DNS format generation
- Binary and hexadecimal representations
- JSON output support
- Bulk IP processing

## Installation

```bash
cd B13_IP_Validator
cargo build --release
```

## Usage

### Validate IP Address

```bash
# Validate an IPv4 address
./target/release/ip_validator validate 192.168.1.1

# Validate an IPv6 address
./target/release/ip_validator validate "2001:db8::1"

# Output as JSON
./target/release/ip_validator validate 8.8.8.8 --json
```

### Analyze CIDR Notation

```bash
# Analyze a CIDR block
./target/release/ip_validator cidr 192.168.1.0/24

# Analyze IPv6 CIDR
./target/release/ip_validator cidr "2001:db8::/32"

# JSON output
./target/release/ip_validator cidr 10.0.0.0/8 --json
```

### Check Network Containment

```bash
# Check if IP is in a network
./target/release/ip_validator contains 192.168.1.0/24 192.168.1.100

# Check if IP is outside network
./target/release/ip_validator contains 10.0.0.0/8 192.168.1.1
```

### List IPs in Range

```bash
# List IPs in a /24 network
./target/release/ip_validator list 192.168.1.0/24

# Limit output
./target/release/ip_validator list 10.0.0.0/16 --limit 10
```

### Bulk Processing

```bash
# Process multiple IPs
./target/release/ip_validator bulk "192.168.1.1,10.0.0.1,8.8.8.8"

# JSON output
./target/release/ip_validator bulk "192.168.1.1,10.0.0.1" --json
```

### Compare IPs

```bash
# Compare two IP addresses
./target/release/ip_validator compare 192.168.1.1 8.8.8.8
```

### Show Private Ranges

```bash
# Show IPv4 private ranges
./target/release/ip_validator private

# Include IPv6 ranges
./target/release/ip_validator private -6
```

## Output Examples

### IP Validation Output

```
IP Address Analysis
==================================================
  Input:        192.168.1.1
  Canonical:    192.168.1.1
  Version:      IPv4
  Type:         Private (Class C - 192.168.0.0/16)

  Flags:
    Private:      Yes
    Loopback:     No
    Multicast:    No
    Link-Local:   No
    Documentation:No

  Binary:       11000000.10101000.00000001.00000001
  Hexadecimal:  0xc0a80101
  Reverse DNS:  1.1.168.192.in-addr.arpa
```

### CIDR Analysis Output

```
CIDR Network Analysis
==================================================
  Input:          192.168.1.0/24
  Version:        IPv4
  Prefix:         /24

  Addresses:
    Network:      192.168.1.0
    Broadcast:    192.168.1.255
    First Host:   192.168.1.1
    Last Host:    192.168.1.254

  Masks:
    Netmask:      255.255.255.0
    Wildcard:     0.0.0.255

  Size:
    Total IPs:    256
    Usable Hosts: 254
```

## IP Classifications

### IPv4 Address Types

| Type | Range | Description |
|------|-------|-------------|
| Private Class A | 10.0.0.0/8 | Large private networks |
| Private Class B | 172.16.0.0/12 | Medium private networks |
| Private Class C | 192.168.0.0/16 | Small private networks |
| Loopback | 127.0.0.0/8 | Local host |
| Link-Local | 169.254.0.0/16 | APIPA addresses |
| CGNAT | 100.64.0.0/10 | Carrier-grade NAT |
| Documentation | 192.0.2.0/24, etc. | Test/documentation |
| Multicast | 224.0.0.0/4 | Multicast addresses |

### IPv6 Address Types

| Type | Range | Description |
|------|-------|-------------|
| Loopback | ::1/128 | Local host |
| Link-Local | fe80::/10 | Local network |
| Unique Local | fc00::/7 | Private (like RFC1918) |
| Documentation | 2001:db8::/32 | Documentation |
| Global Unicast | 2000::/3 | Public addresses |

## Rust Concepts Demonstrated

1. **Network Types**: std::net::{IpAddr, Ipv4Addr, Ipv6Addr}
2. **External Crates**: ipnetwork for CIDR handling
3. **Enum Matching**: Complex pattern matching on IP types
4. **Bitwise Operations**: IP address calculations
5. **Trait Implementations**: Serialize/Deserialize for JSON
6. **Error Handling**: Custom error types
7. **Iterators**: Network range enumeration

## Security Use Cases

### Firewall Rule Validation
```bash
# Verify that a rule covers the intended range
./ip_validator cidr 10.0.0.0/8
./ip_validator contains 10.0.0.0/8 10.255.255.255
```

### Log Analysis
```bash
# Quickly classify IPs from logs
./ip_validator bulk "192.168.1.1,10.0.0.1,185.199.108.1" --json
```

### Network Reconnaissance
```bash
# Understand target network size
./ip_validator cidr 172.16.0.0/12
./ip_validator list 192.168.1.0/28
```

### Private IP Detection
```bash
# Check if traffic is internal
./ip_validator validate 10.0.0.50
```

## Testing

```bash
cargo test
```

## License

MIT License
