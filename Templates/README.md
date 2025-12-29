# Rust Security Tool Templates

## Overview

Ready-to-use templates for building Rust security tools. Copy, customize, and deploy.

---

## Available Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| [CLI Tool](./cli_tool/) | Basic command-line tool structure | General-purpose tools |
| [Network Scanner](./network_scanner/) | Port/host scanning framework | Reconnaissance |
| [Web Tool](./web_tool/) | HTTP client with async support | Web testing |
| [Log Analyzer](./log_analyzer/) | Log parsing and analysis | Blue team |
| [Binary Analyzer](./binary_analyzer/) | ELF/PE parsing | Malware analysis |
| [Crypto Tool](./crypto_tool/) | Encryption/hashing operations | Data protection |

---

## Quick Start

### 1. Copy Template

```bash
cp -r Templates/cli_tool my_tool
cd my_tool
```

### 2. Update Cargo.toml

```toml
[package]
name = "my_tool"
version = "0.1.0"
```

### 3. Customize and Build

```bash
cargo build --release
```

---

## Template Features

All templates include:

- Proper error handling with `anyhow`
- CLI argument parsing with `clap`
- Structured logging
- Cross-platform support
- Release profile optimization
- Basic unit tests

---

[← Back to Main](../README.md)
