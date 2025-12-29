# Cross-Compilation Guide

## Overview

Build your Rust security tools for multiple platforms from a single machine.

---

## Target Triples

Format: `<arch>-<vendor>-<os>-<abi>`

| Target | Description |
|--------|-------------|
| `x86_64-unknown-linux-gnu` | Linux 64-bit (glibc) |
| `x86_64-unknown-linux-musl` | Linux 64-bit (static) |
| `x86_64-pc-windows-gnu` | Windows 64-bit (MinGW) |
| `x86_64-pc-windows-msvc` | Windows 64-bit (MSVC) |
| `x86_64-apple-darwin` | macOS 64-bit |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |
| `aarch64-apple-darwin` | macOS ARM64 (M1/M2) |
| `armv7-unknown-linux-gnueabihf` | Raspberry Pi |

---

## Setup

### Install Targets

```bash
# List available targets
rustup target list

# Add common targets
rustup target add x86_64-unknown-linux-musl
rustup target add x86_64-pc-windows-gnu
rustup target add aarch64-unknown-linux-gnu

# List installed targets
rustup target list --installed
```

### Install Linkers

**Linux (for Windows cross-compile):**
```bash
# Ubuntu/Debian
sudo apt install mingw-w64

# Fedora
sudo dnf install mingw64-gcc
```

**Linux (for musl static builds):**
```bash
# Ubuntu/Debian
sudo apt install musl-tools

# Fedora
sudo dnf install musl-gcc
```

**Linux (for ARM):**
```bash
sudo apt install gcc-aarch64-linux-gnu
```

---

## Basic Cross-Compilation

### Build for Specific Target

```bash
# Linux static binary (no dependencies)
cargo build --release --target x86_64-unknown-linux-musl

# Windows from Linux
cargo build --release --target x86_64-pc-windows-gnu

# ARM64 Linux
cargo build --release --target aarch64-unknown-linux-gnu
```

### Output Location

```
target/
├── x86_64-unknown-linux-musl/
│   └── release/
│       └── mytool          # Linux static
├── x86_64-pc-windows-gnu/
│   └── release/
│       └── mytool.exe      # Windows
└── aarch64-unknown-linux-gnu/
    └── release/
        └── mytool          # ARM64 Linux
```

---

## Configuration

### .cargo/config.toml

```toml
# Linux musl (static)
[target.x86_64-unknown-linux-musl]
linker = "musl-gcc"

# Windows (MinGW)
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"

# ARM64 Linux
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"

# Default to release optimizations
[profile.release]
opt-level = 3
lto = true
strip = true
panic = "abort"
codegen-units = 1
```

---

## Static Linux Binaries (musl)

Best for deployment - no runtime dependencies.

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools

# Build
cargo build --release --target x86_64-unknown-linux-musl

# Verify it's static
ldd target/x86_64-unknown-linux-musl/release/mytool
# Output: "not a dynamic executable" (good!)

# Check size
ls -lh target/x86_64-unknown-linux-musl/release/mytool
```

---

## Windows Cross-Compile (from Linux)

```bash
# Install target and linker
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64

# Build
cargo build --release --target x86_64-pc-windows-gnu

# Output
ls target/x86_64-pc-windows-gnu/release/*.exe
```

### Windows with OpenSSL

If your tool uses OpenSSL (reqwest, native-tls):

```toml
# Cargo.toml - Use rustls instead
[dependencies]
reqwest = { version = "0.11", default-features = false, features = ["rustls-tls"] }
```

---

## ARM/Raspberry Pi

```bash
# ARM64
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu

cargo build --release --target aarch64-unknown-linux-gnu

# ARMv7 (older Raspberry Pi)
rustup target add armv7-unknown-linux-gnueabihf
sudo apt install gcc-arm-linux-gnueabihf

cargo build --release --target armv7-unknown-linux-gnueabihf
```

---

## Build Script (build_all.sh)

```bash
#!/bin/bash

TARGETS=(
    "x86_64-unknown-linux-musl"
    "x86_64-pc-windows-gnu"
    "aarch64-unknown-linux-gnu"
)

PROJECT_NAME="security-tool"
VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

echo "Building $PROJECT_NAME v$VERSION"

mkdir -p dist

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."

    cargo build --release --target "$target"

    if [ $? -eq 0 ]; then
        case $target in
            *windows*)
                EXT=".exe"
                ;;
            *)
                EXT=""
                ;;
        esac

        cp "target/$target/release/${PROJECT_NAME}${EXT}" \
           "dist/${PROJECT_NAME}-${VERSION}-${target}${EXT}"

        echo "  ✓ Built: dist/${PROJECT_NAME}-${VERSION}-${target}${EXT}"
    else
        echo "  ✗ Failed: $target"
    fi
done

echo ""
echo "Build complete. Artifacts in dist/"
ls -lh dist/
```

---

## Optimizing Binary Size

```toml
# Cargo.toml
[profile.release]
opt-level = "z"      # Optimize for size
lto = true           # Link-time optimization
codegen-units = 1    # Single codegen unit
panic = "abort"      # Remove panic unwinding
strip = true         # Strip symbols
```

```bash
# Additional stripping (Linux)
strip target/release/mytool

# UPX compression (optional, may trigger AV)
upx --best target/release/mytool
```

### Size Comparison

| Configuration | Size |
|--------------|------|
| Debug build | ~50MB |
| Release build | ~5MB |
| Release + LTO | ~3MB |
| Release + LTO + strip | ~2MB |
| + UPX | ~800KB |

---

## GitHub Actions CI/CD

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-musl
            artifact: mytool
          - os: ubuntu-latest
            target: x86_64-pc-windows-gnu
            artifact: mytool.exe
          - os: macos-latest
            target: x86_64-apple-darwin
            artifact: mytool

    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-action@stable
        with:
          targets: ${{ matrix.target }}

      - name: Install dependencies (Linux)
        if: matrix.os == 'ubuntu-latest'
        run: |
          sudo apt-get update
          sudo apt-get install -y musl-tools mingw-w64

      - name: Build
        run: cargo build --release --target ${{ matrix.target }}

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: ${{ matrix.target }}
          path: target/${{ matrix.target }}/release/${{ matrix.artifact }}
```

---

## Troubleshooting

### "linker not found"

```bash
# Check linker is installed
which x86_64-w64-mingw32-gcc
which musl-gcc
which aarch64-linux-gnu-gcc

# Install if missing
sudo apt install mingw-w64 musl-tools gcc-aarch64-linux-gnu
```

### OpenSSL/TLS Issues

```toml
# Use rustls instead of native-tls
[dependencies]
reqwest = { version = "0.11", default-features = false, features = ["rustls-tls"] }
```

### "cannot find crti.o"

```bash
# Install C library for target
sudo apt install libc6-dev-arm64-cross  # For ARM64
```

### Large Binary Size

- Use `--release` flag
- Enable LTO in Cargo.toml
- Use `strip` command
- Avoid pulling in unnecessary dependencies

---

## Platform-Specific Code

```rust
#[cfg(target_os = "windows")]
fn get_temp_dir() -> PathBuf {
    std::env::var("TEMP").unwrap().into()
}

#[cfg(target_os = "linux")]
fn get_temp_dir() -> PathBuf {
    "/tmp".into()
}

#[cfg(target_os = "macos")]
fn get_temp_dir() -> PathBuf {
    "/tmp".into()
}
```

---

[← Back to Quick Reference](./README.md)
