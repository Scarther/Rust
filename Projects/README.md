# Rust Security Projects

## Overview

Complete, production-ready Rust security tool implementations for learning and reference.

---

## Project Index

| Project | Description | Skill Level | Lines of Code |
|---------|-------------|-------------|---------------|
| [PortScanner](./PortScanner/) | Multi-threaded TCP/UDP port scanner | Intermediate | ~500 |
| [WebCrawler](./WebCrawler/) | Async web crawler with link extraction | Intermediate | ~600 |
| [HashCracker](./HashCracker/) | Dictionary-based password hash cracker | Advanced | ~400 |
| [LogAnalyzer](./LogAnalyzer/) | Security log parser and analyzer | Intermediate | ~500 |
| [IOCScanner](./IOCScanner/) | Indicator of Compromise scanner | Advanced | ~700 |
| [BinaryParser](./BinaryParser/) | ELF/PE binary analysis tool | Advanced | ~800 |

---

## Project Structure

Each project follows a standard structure:

```
ProjectName/
├── Cargo.toml           # Project configuration
├── README.md            # Project documentation
├── src/
│   ├── main.rs          # Entry point
│   ├── lib.rs           # Library code
│   └── modules/         # Feature modules
├── tests/               # Integration tests
└── examples/            # Usage examples
```

---

## Building Projects

```bash
# Navigate to a project
cd Projects/PortScanner

# Build in release mode
cargo build --release

# Run tests
cargo test

# Run with arguments
cargo run --release -- --help
```

---

## Cross-Compilation

All projects support cross-compilation:

```bash
# For Linux (static binary)
cargo build --release --target x86_64-unknown-linux-musl

# For Windows
cargo build --release --target x86_64-pc-windows-gnu
```

---

## Learning Path

### Beginner Path
1. PortScanner - Learn async networking basics
2. LogAnalyzer - Learn file I/O and parsing

### Intermediate Path
3. WebCrawler - Learn HTTP clients and async patterns
4. HashCracker - Learn cryptography and parallelism

### Advanced Path
5. IOCScanner - Learn pattern matching and threat detection
6. BinaryParser - Learn binary format parsing

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on adding new projects.

---

[← Back to Main](../README.md)
