# B11 - String Search

A security-focused string and pattern search tool, similar to grep but with built-in security patterns.

## Overview

This tool searches files for strings or regular expression patterns with special emphasis on security-relevant searches. It's designed for:

- **Secret Detection**: Finding hardcoded credentials, API keys, and tokens
- **Log Analysis**: Searching through log files for specific patterns
- **Code Auditing**: Locating potentially insecure code patterns
- **Forensic Investigation**: Finding evidence in text files

## Features

- String and regex pattern matching
- Built-in security patterns (AWS keys, passwords, IPs, etc.)
- Case-insensitive searching
- Line number display
- Context lines (before/after matches)
- Recursive directory searching
- File extension filtering
- Parallel file processing
- Memory-mapped file handling for large files
- Colored output with match highlighting

## Installation

```bash
cd B11_String_Search
cargo build --release
```

## Usage

### Basic Search

```bash
# Search for a string in a file
./target/release/string_search "password" config.txt

# Search in multiple files
./target/release/string_search "TODO" src/*.rs

# Recursive search in directory
./target/release/string_search -R "api_key" ./src

# Case-insensitive search
./target/release/string_search -i "error" logfile.txt
```

### Regex Search

```bash
# Enable regex mode
./target/release/string_search -r "password\s*=\s*['\"].*['\"]" config.py

# Find IP addresses
./target/release/string_search -r "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" access.log

# Find function definitions
./target/release/string_search -r "fn\s+\w+\(" src/main.rs
```

### Security Scanning

```bash
# Find AWS access keys
./target/release/string_search -s aws-key -R .

# Find hardcoded passwords
./target/release/string_search -s password -R ./src

# Find private keys
./target/release/string_search -s private-key -R /etc

# Find API keys
./target/release/string_search -s api-key -R .

# Find IP addresses
./target/release/string_search -s ip-address access.log

# Find email addresses
./target/release/string_search -s email user_data.csv

# Find JWT tokens
./target/release/string_search -s jwt auth.log

# Find credit card numbers
./target/release/string_search -s credit-card transactions.log
```

### Output Options

```bash
# Show line numbers
./target/release/string_search -n "error" logfile.txt

# Show only matching file names
./target/release/string_search -l "TODO" -R .

# Count matches per file
./target/release/string_search -c "import" -R ./src -e py

# Show context lines
./target/release/string_search -B 2 -A 2 "error" logfile.txt

# Invert match (show non-matching lines)
./target/release/string_search -v "DEBUG" logfile.txt
```

### Performance Options

```bash
# Enable parallel processing
./target/release/string_search -p "pattern" -R ./large_codebase

# Filter by extension
./target/release/string_search -e rs "unwrap" -R ./src

# Limit file size (MB)
./target/release/string_search --max-size-mb 10 "pattern" .
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| pattern | | Pattern to search for (required) |
| paths | | Files or directories to search |
| --regex | -r | Treat pattern as regex |
| --ignore-case | -i | Case-insensitive search |
| --line-numbers | -n | Show line numbers |
| --files-only | -l | Only show matching file names |
| --count | -c | Count matches per file |
| --invert | -v | Invert match |
| --before | -B | Lines to show before match |
| --after | -A | Lines to show after match |
| --recursive | -R | Recursive directory search |
| --extension | -e | File extension filter |
| --security-pattern | -s | Use built-in security pattern |
| --max-size-mb | | Max file size to search |
| --unique | -u | Show only unique matches |
| --parallel | -p | Enable parallel searching |

## Built-in Security Patterns

| Pattern | Description | Example Match |
|---------|-------------|---------------|
| aws-key | AWS Access Key IDs | AKIAIOSFODNN7EXAMPLE |
| api-key | API Keys and Tokens | api_key = "abc123..." |
| private-key | Private Key Headers | -----BEGIN PRIVATE KEY----- |
| password | Hardcoded Passwords | password = "secret123" |
| ip-address | IPv4 Addresses | 192.168.1.1 |
| email | Email Addresses | user@example.com |
| url | HTTP/HTTPS URLs | https://example.com |
| jwt | JWT Tokens | eyJhbG... |
| base64 | Base64 Encoded Strings | SGVsbG8gV29ybGQ= |
| credit-card | Credit Card Numbers | 4111111111111111 |

## Rust Concepts Demonstrated

1. **Regular Expressions**: Using the regex crate for pattern matching
2. **Enums with Methods**: SecurityPattern enum with associated functions
3. **Memory Mapping**: Efficient file I/O with memmap2
4. **Parallel Processing**: Using rayon for concurrent file searching
5. **Iterator Chains**: Complex filtering and transformation
6. **Error Handling**: Result types and error propagation
7. **Atomic Operations**: Thread-safe counters
8. **Trait Objects**: Using ValueEnum for CLI parsing

## Example Output

```
$ ./string_search -s password -R ./src -n

[Security Scan] Searching for: Hardcoded Passwords
------------------------------------------------------------
src/config.rs:42:    let password = "admin123";
src/auth.rs:15:    PASSWORD = "secretpass"
src/database.rs:8:    db_password = getenv("DB_PASS")
------------------------------------------------------------
Total matches: 3
```

## Testing

```bash
cargo test
```

## Security Considerations

- This tool is for authorized security testing only
- Never search files you don't have permission to access
- Handle discovered secrets responsibly
- Report vulnerabilities through proper channels

## License

MIT License
