# B08 - Base64 Tool

A security-focused Base64 encoding and decoding utility.

## Overview

This project provides comprehensive Base64 operations with security analysis:

- **Encode**: Convert data to Base64 (multiple variants)
- **Decode**: Decode Base64 data (auto-detect encoding)
- **Detect**: Find Base64 strings in text
- **Analyze**: Examine decoded content for security patterns
- **Convert**: Transform between Base64, hex, and URL encoding
- **Compare**: Check if two Base64 strings decode to the same data

## Security Features

1. **Multi-layer Decoding**: Unpack nested/obfuscated Base64
2. **Sensitive Data Detection**: Find passwords, keys, tokens
3. **Binary Analysis**: Detect file types (PE, ELF, images)
4. **Multiple Encoding Support**: Standard, URL-safe, with/without padding
5. **Pattern Detection**: Find Base64 in logs and text

## Building

```bash
cargo build --release
```

## Usage

### Encode to Base64

```bash
# Encode string
./base64_tool encode "Hello, World!"

# Encode file
./base64_tool encode -f input.bin

# URL-safe encoding
./base64_tool encode "data" -e url-safe

# Without padding
./base64_tool encode "data" -e no-pad

# Wrap output at 76 characters
./base64_tool encode -f large.bin -w 76

# Save to file
./base64_tool encode "data" -o output.txt
```

### Decode Base64

```bash
# Decode string
./base64_tool decode "SGVsbG8gV29ybGQh"

# Decode from file
./base64_tool decode -f encoded.txt

# URL-safe decoding
./base64_tool decode "aGVsbG8" -e url-safe-no-pad

# Output as hex
./base64_tool decode "SGVsbG8=" -O hex

# Save as binary
./base64_tool decode -f image.b64 -O binary -o image.png

# Recursive decoding (multi-layer obfuscation)
./base64_tool decode "U0dWc2JHOD0=" -r

# Limit recursion depth
./base64_tool decode "nested_b64" -r --max-depth 5
```

### Detect Base64 Strings

```bash
# Find Base64 in text
./base64_tool detect -f logfile.txt

# Minimum length threshold
./base64_tool detect -f logfile.txt -m 20

# Also decode found strings
./base64_tool detect -f logfile.txt -d
```

### Analyze Base64

```bash
# Analyze encoded data
./base64_tool analyze "SGVsbG8gV29ybGQh"

# Check for sensitive content
./base64_tool analyze "cGFzc3dvcmQ9c2VjcmV0" -s
```

### Convert Encoding

```bash
# Base64 to hex
./base64_tool convert "SGVsbG8=" -f base64 -t hex

# Hex to Base64
./base64_tool convert "48656c6c6f" -f hex -t base64

# Base64 to URL encoding
./base64_tool convert "SGVsbG8gV29ybGQh" -f base64 -t url

# URL to Base64
./base64_tool convert "Hello%20World" -f url -t base64
```

### Compare Base64 Strings

```bash
# Check if two strings decode to same content
./base64_tool compare "SGVsbG8=" "SGVsbG8"
```

### Generate Random Base64

```bash
# Generate 32 random bytes as Base64
./base64_tool generate

# Generate 64 bytes
./base64_tool generate -b 64

# URL-safe output
./base64_tool generate -b 32 -e url-safe
```

## Key Rust Concepts Demonstrated

### Base64 Encoding

```rust
use base64::{engine::general_purpose, Engine as _};

// Encode
let encoded = general_purpose::STANDARD.encode(b"Hello");

// Decode
let decoded = general_purpose::STANDARD.decode("SGVsbG8=")?;

// URL-safe variant
let url_safe = general_purpose::URL_SAFE.encode(b"data");
```

### Pattern Matching

```rust
// Check if string could be Base64
fn is_potential_base64(s: &str) -> bool {
    s.len() >= 4 &&
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() ||
        c == '+' || c == '/' || c == '=' ||
        c == '-' || c == '_'
    })
}
```

### Recursive Processing

```rust
fn decode_recursive(data: &str, max_depth: usize) -> Vec<DecodedLayer> {
    let mut results = Vec::new();
    let mut current = data.to_string();

    for depth in 0..max_depth {
        if let Some(decoded) = try_decode(&current) {
            results.push(DecodedLayer { depth, data: decoded.clone() });
            // Continue if result looks like more Base64
            if is_potential_base64(&decoded) {
                current = decoded;
                continue;
            }
        }
        break;
    }
    results
}
```

### Binary Pattern Detection

```rust
fn detect_file_type(bytes: &[u8]) -> Option<&str> {
    match bytes {
        [0x89, 0x50, 0x4E, 0x47, ..] => Some("PNG"),
        [0xFF, 0xD8, 0xFF, ..] => Some("JPEG"),
        [0x25, 0x50, 0x44, 0x46, ..] => Some("PDF"),
        [0x50, 0x4B, 0x03, 0x04, ..] => Some("ZIP"),
        [0x7F, 0x45, 0x4C, 0x46, ..] => Some("ELF"),
        [0x4D, 0x5A, ..] => Some("PE/EXE"),
        _ => None,
    }
}
```

## Encoding Types

| Type | Alphabet | Padding | Use Case |
|------|----------|---------|----------|
| standard | A-Za-z0-9+/ | = | General purpose |
| url-safe | A-Za-z0-9-_ | = | URLs and filenames |
| no-pad | A-Za-z0-9+/ | None | Space-constrained |
| url-safe-no-pad | A-Za-z0-9-_ | None | JWT, cookies |

## Security Use Cases

### Malware Analysis
```bash
# Decode obfuscated payload
./base64_tool decode -f malware_sample.b64 -r -s

# Detect encoded strings in binary
strings binary.exe | ./base64_tool detect -d
```

### Log Analysis
```bash
# Find and decode Base64 in logs
./base64_tool detect -f access.log -m 20 -d
```

### Credential Discovery
```bash
# Analyze potential credentials
./base64_tool analyze "dXNlcm5hbWU6cGFzc3dvcmQ=" -s
```

## Sensitive Patterns Detected

- Passwords and credentials
- API keys and tokens
- Private keys (RSA, SSH)
- Certificates
- AWS credentials
- Authorization headers
- Bearer tokens

## Binary Signatures Detected

| Signature | Type |
|-----------|------|
| 89 50 4E 47 | PNG Image |
| FF D8 FF | JPEG Image |
| 25 50 44 46 | PDF Document |
| 50 4B 03 04 | ZIP Archive |
| 7F 45 4C 46 | ELF Executable |
| 4D 5A | Windows PE |
| 1F 8B | GZIP Compressed |

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
- `base64` - Base64 encoding/decoding
- `hex` - Hexadecimal encoding/decoding
- `urlencoding` - URL encoding/decoding
