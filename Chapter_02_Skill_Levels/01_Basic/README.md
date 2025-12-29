# Basic Level Projects (B01-B15)

## Overview

These projects introduce fundamental Rust concepts through security-relevant exercises. Complete these in order to build a solid foundation.

## Prerequisites

- Rust installed (`rustup`)
- Basic command line familiarity
- Text editor or IDE

## Projects

| ID | Name | Concepts | Difficulty |
|----|------|----------|------------|
| B01 | Hello Security World | Project structure, println!, formatting | Easy |
| B02 | Command-Line Arguments | clap, argument parsing, validation | Easy |
| B03 | File Operations | fs, io, Read/Write traits | Easy |
| B04 | Environment Variables | env module, configuration | Easy |
| B05 | Process Information | process module, Command | Easy |
| B06 | Simple HTTP Client | reqwest basics, async intro | Easy |
| B07 | JSON Parsing | serde_json, serialization | Easy |
| B08 | Base64 Encoding/Decoding | base64 crate, data transformation | Easy |
| B09 | Hash Calculator | sha2, md5, file hashing | Easy |
| B10 | Directory Walker | walkdir, recursion, Path | Medium |
| B11 | Simple Logger | log crate, env_logger | Medium |
| B12 | Config File Parser | toml/yaml parsing | Medium |
| B13 | String Manipulation | String vs &str, parsing | Medium |
| B14 | Regex Basics | regex crate, pattern matching | Medium |
| B15 | Error Handling Patterns | Result, custom errors, ? operator | Medium |

## Learning Path

```
B01-B05: Core Rust fundamentals
    ↓
B06-B10: External crates & I/O
    ↓
B11-B15: Intermediate patterns
    ↓
[Proceed to Intermediate Level]
```

## How to Use Each Project

Each project folder contains:
- `README.md` - Detailed explanation and breakdown
- `Cargo.toml` - Dependencies
- `src/main.rs` - Implementation
- `exercises/` - Practice challenges

## Building and Running

```bash
cd B01_Hello_Security
cargo run

# Or with release optimizations
cargo run --release
```

## Verification

After completing a project, run the tests:
```bash
cargo test
```
