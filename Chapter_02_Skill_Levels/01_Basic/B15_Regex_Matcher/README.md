# B15 - Regex Matcher

A comprehensive regular expression matching tool designed for security analysis and pattern detection.

## Overview

This tool provides powerful regex capabilities for security professionals. Essential for:

- **Log Analysis**: Extracting patterns from security logs
- **Threat Detection**: Finding indicators of compromise
- **Data Validation**: Verifying input formats
- **Secret Detection**: Locating credentials and keys in files
- **Custom Rules**: Building detection patterns

## Features

- Pattern matching with capture groups
- Built-in security patterns (emails, IPs, credentials, etc.)
- Case-insensitive and multiline modes
- Pattern replacement with backreferences
- Text splitting by pattern
- Pattern validation and explanation
- Interactive testing mode
- JSON output for automation
- File and stdin input support

## Installation

```bash
cd B15_Regex_Matcher
cargo build --release
```

## Usage

### Basic Pattern Matching

```bash
# Match a pattern against text
./target/release/regex_matcher match "\d+" --text "abc123def456"

# Match from file
./target/release/regex_matcher match "error|warning" --file /var/log/syslog

# Case-insensitive matching
./target/release/regex_matcher match "password" --file config.txt --ignore-case

# Multiline mode
./target/release/regex_matcher match "^ERROR:" --file log.txt --multiline

# JSON output
./target/release/regex_matcher match "\d+" --text "abc123" --json
```

### Quick Pattern Test

```bash
# Test if pattern matches
./target/release/regex_matcher test "\d{3}-\d{4}" "555-1234"

# Case-insensitive test
./target/release/regex_matcher test "hello" "HELLO" --ignore-case
```

### Extract All Matches

```bash
# Extract all matches
./target/release/regex_matcher extract "[a-zA-Z]+" --text "hello 123 world 456"

# Extract unique matches only
./target/release/regex_matcher extract "\w+" --text "hello hello world" --unique

# From file
./target/release/regex_matcher extract "https?://[^\s]+" --file urls.txt
```

### Pattern Replacement

```bash
# Replace first occurrence
./target/release/regex_matcher replace "\d+" "X" "a1b2c3"

# Replace all occurrences
./target/release/regex_matcher replace "\d+" "X" "a1b2c3" --all

# Use capture groups ($1, $2, etc.)
./target/release/regex_matcher replace "(\w+)@(\w+)" "$2-$1" "user@domain" --all
```

### Split Text

```bash
# Split by pattern
./target/release/regex_matcher split "\s+" "hello   world  test"

# Limit splits
./target/release/regex_matcher split "," "a,b,c,d,e" --limit 3

# JSON output
./target/release/regex_matcher split "\s+" "a b c" --json
```

### Validate Pattern

```bash
# Check if pattern is valid
./target/release/regex_matcher validate "\d+[a-z]*"

# Invalid pattern shows error
./target/release/regex_matcher validate "[invalid"
```

### Security Patterns

```bash
# Use built-in security patterns
./target/release/regex_matcher security --pattern email --file users.txt
./target/release/regex_matcher security --pattern ipv4 --file access.log
./target/release/regex_matcher security --pattern credit-card --file transactions.txt
./target/release/regex_matcher security --pattern aws-key --file env.txt
./target/release/regex_matcher security --pattern jwt --file auth.log

# Available patterns:
# email, ipv4, ipv6, url, phone, credit-card, ssn, aws-key, private-key,
# jwt, password, api-key, mac-address, file-path, base64, md5, sha256, uuid, date
```

### List Built-in Patterns

```bash
# Show all available security patterns
./target/release/regex_matcher list-patterns
```

### Explain Pattern

```bash
# Get explanation of regex syntax
./target/release/regex_matcher explain "^[a-zA-Z]+\\d{2,4}$"
```

### Interactive Mode

```bash
# Start interactive regex tester
./target/release/regex_matcher interactive
```

## Built-in Security Patterns

| Pattern | Description | Example Match |
|---------|-------------|---------------|
| email | Email addresses | user@example.com |
| ipv4 | IPv4 addresses | 192.168.1.1 |
| ipv6 | IPv6 addresses | 2001:db8::1 |
| url | HTTP/HTTPS URLs | https://example.com |
| phone | Phone numbers | (555) 123-4567 |
| credit-card | Credit card numbers | 4111111111111111 |
| ssn | Social Security Numbers | 123-45-6789 |
| aws-key | AWS Access Key IDs | AKIAIOSFODNN7EXAMPLE |
| private-key | Private key headers | -----BEGIN PRIVATE KEY----- |
| jwt | JWT tokens | eyJhbG... |
| password | Hardcoded passwords | password = "secret" |
| api-key | API keys | api_key = "abc123..." |
| mac-address | MAC addresses | 00:1A:2B:3C:4D:5E |
| file-path | File paths | /etc/passwd |
| base64 | Base64 strings | SGVsbG8gV29ybGQ= |
| md5 | MD5 hashes | d41d8cd98f00b204e9800998ecf8427e |
| sha256 | SHA256 hashes | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| uuid | UUIDs | 550e8400-e29b-41d4-a716-446655440000 |
| date | Date formats | 2024-01-15 |

## Regex Syntax Quick Reference

| Pattern | Description |
|---------|-------------|
| `.` | Any character |
| `\d` | Any digit (0-9) |
| `\D` | Any non-digit |
| `\w` | Word character (a-z, A-Z, 0-9, _) |
| `\W` | Non-word character |
| `\s` | Whitespace |
| `\S` | Non-whitespace |
| `^` | Start of string/line |
| `$` | End of string/line |
| `*` | Zero or more |
| `+` | One or more |
| `?` | Zero or one |
| `{n}` | Exactly n times |
| `{n,m}` | Between n and m times |
| `[abc]` | Character class |
| `[^abc]` | Negated class |
| `(...)` | Capture group |
| `\|` | Alternation (OR) |
| `\b` | Word boundary |

## Output Examples

### Match Output

```
3 matches found
==================================================

1. 123 (1:3-6)
   Context: ...abc123def...
   Capture groups:
     $1: 123

2. 456 (1:9-12)
   Context: ...def456ghi...
```

### Security Pattern Output

```
Security Pattern: Ipv4
  Regex: \b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}...

2 matches found
==================================================

1. 192.168.1.1 (1:15-26)
2. 10.0.0.1 (1:35-43)
```

## Rust Concepts Demonstrated

1. **Regex Crate**: Pattern compilation and matching
2. **Lazy Static**: Compile-time pattern initialization
3. **Iterators**: Efficient match iteration
4. **Capture Groups**: Named and numbered captures
5. **Error Handling**: Custom error types
6. **Subcommands**: Complex CLI structure
7. **Serialization**: JSON output with serde

## Security Use Cases

### Credential Detection
```bash
# Find hardcoded passwords
./regex_matcher security --pattern password --file source.py

# Find AWS keys
./regex_matcher security --pattern aws-key --file .env
```

### Log Analysis
```bash
# Extract all IPs from access log
./regex_matcher extract "\d+\.\d+\.\d+\.\d+" --file access.log --unique

# Find error messages
./regex_matcher match "ERROR|FATAL|CRITICAL" --file app.log -i
```

### Data Validation
```bash
# Validate email format
./regex_matcher test "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" "$EMAIL"
```

### Secret Scanning
```bash
# Scan for various secrets
./regex_matcher security --pattern jwt --file auth.log
./regex_matcher security --pattern private-key --file keys/
./regex_matcher security --pattern api-key --file config.json
```

## Testing

```bash
cargo test
```

## License

MIT License
