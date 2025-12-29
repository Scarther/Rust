# B10 - Directory Walker

A security-focused directory traversal tool for discovering files by pattern matching.

## Overview

This tool recursively walks directories to find files matching specific patterns, with special emphasis on security-relevant file discovery. It's useful for:

- **Security Auditing**: Finding configuration files, keys, and credentials
- **Forensic Analysis**: Locating log files and backup files
- **Penetration Testing**: Discovering sensitive files in target systems
- **Incident Response**: Quickly identifying potentially compromised files

## Features

- Recursive directory traversal with depth limiting
- Glob pattern matching (*.log, config*, etc.)
- File extension filtering
- File size filtering (min/max)
- Hidden file handling
- Security-sensitive file detection
- Colored output for easy identification
- Verbose mode with file details

## Installation

```bash
cd B10_Directory_Walker
cargo build --release
```

## Usage

### Basic Usage

```bash
# Walk current directory
./target/release/directory_walker

# Walk specific directory
./target/release/directory_walker -d /var/log

# Find all .log files
./target/release/directory_walker -p "*.log"

# Find files by extension
./target/release/directory_walker -e conf
```

### Security Scanning

```bash
# Enable security scan mode (finds sensitive files)
./target/release/directory_walker -s

# Find sensitive files in /etc
./target/release/directory_walker -d /etc -s -v

# Find backup files that might contain secrets
./target/release/directory_walker -p "*.bak" -v
```

### Advanced Options

```bash
# Limit recursion depth
./target/release/directory_walker -D 2

# Show hidden files
./target/release/directory_walker -H

# Filter by size (find large log files)
./target/release/directory_walker -e log --min-size 1000000

# Verbose output with timestamps and sizes
./target/release/directory_walker -v

# Show only directories
./target/release/directory_walker --dirs-only

# Show only files
./target/release/directory_walker --files-only
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| --directory | -d | Starting directory (default: current) |
| --pattern | -p | Glob pattern to match files |
| --extension | -e | File extension filter |
| --max-depth | -D | Maximum recursion depth |
| --min-size | | Minimum file size in bytes |
| --max-size | | Maximum file size in bytes |
| --hidden | -H | Include hidden files |
| --verbose | -v | Show detailed file information |
| --dirs-only | | Show only directories |
| --files-only | | Show only files |
| --security-scan | -s | Find security-sensitive files |

## Security-Sensitive File Detection

The tool automatically detects potentially sensitive files:

### Sensitive Extensions
- **Certificates/Keys**: .pem, .key, .crt, .cer, .p12, .pfx
- **Configuration**: .conf, .config, .cfg, .ini, .yaml, .yml, .toml
- **Logs**: .log, .logs
- **Secrets**: .env, .secret
- **Database**: .sql, .db, .sqlite
- **Backups**: .bak, .backup, .old, .orig, .swp

### Sensitive File Names
- SSH keys: id_rsa, id_dsa, id_ecdsa, id_ed25519
- Git config: .gitconfig
- Environment: .env, .netrc, .npmrc
- History: .bash_history, .zsh_history
- System: shadow, passwd, sudoers

## Rust Concepts Demonstrated

1. **Struct Definitions**: FileInfo struct with multiple fields
2. **Trait Derivation**: Debug, Clone traits
3. **Method Implementation**: impl blocks for structs
4. **Error Handling**: Result and Option types
5. **Iterator Patterns**: filter, filter_map, map, collect
6. **Closures**: Anonymous functions passed to iterators
7. **Pattern Matching**: match expressions and if-let
8. **Lifetime Management**: Borrowing and references
9. **External Crates**: walkdir, clap, colored

## Example Output

```
Directory Walker - Security File Scanner
Scanning: /etc
Security scan mode enabled
------------------------------------------------------------
/etc/ssh/ssh_host_rsa_key
/etc/shadow
/etc/passwd
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
/etc/mysql/my.cnf

============================================================
Scan Summary
============================================================
  Files found:     156
  Directories:     42
  Total size:      2.3 MiB
  Security files:  23
```

## Testing

```bash
cargo test
```

## License

MIT License
