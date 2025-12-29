# I11 Encoding Converter

A comprehensive tool for converting between various encodings commonly encountered in security analysis.

## Overview

This tool provides encoding and decoding capabilities for formats frequently used in:
- Web application security testing
- CTF challenges
- Malware analysis
- Data exfiltration detection
- Payload obfuscation analysis

## Features

### Supported Encodings

| Encoding | Description |
|----------|-------------|
| `base64` | Standard Base64 |
| `base64url` | URL-safe Base64 |
| `hex` | Hexadecimal |
| `url` | URL encoding (standard) |
| `urlfull` | URL encoding (all chars) |
| `html` | HTML entity encoding |
| `htmldec` | HTML decimal (&#65;) |
| `htmlhex` | HTML hex (&#x41;) |
| `unicode` | Unicode codepoints |
| `unicode-escape` | Unicode escape (\\u0041) |
| `binary` | Binary representation |
| `octal` | Octal representation |
| `rot13` | ROT13 cipher |
| `caesar` | Caesar cipher |
| `reverse` | Reverse string |
| `ascii` | ASCII values |

### Special Features

- **Auto-detection**: Automatically detect and decode unknown encodings
- **Chain encoding**: Apply multiple encodings in sequence
- **XOR operations**: XOR encode/decode with custom keys
- **Analysis**: Detailed input analysis with entropy calculation

## Usage

```bash
# Build the project
cargo build --release

# Encode to Base64
cargo run -- encode -e base64 "Hello, World!"

# Decode from Base64
cargo run -- decode -e base64 "SGVsbG8sIFdvcmxkIQ=="

# Encode to Hex
cargo run -- encode -e hex "Test"

# URL encode
cargo run -- encode -e url "Hello World!"

# Full URL encode (all characters)
cargo run -- encode -e url-full "Hello World!"

# HTML encode
cargo run -- encode -e html "<script>alert('xss')</script>"

# Auto-detect and decode
cargo run -- auto "SGVsbG8="

# Chain multiple encodings
cargo run -- chain -e "base64,hex" "Secret"

# Decode chain (reverse order applied)
cargo run -- chain -e "hex,base64" "encoded_data" --decode

# Analyze input
cargo run -- analyze "SGVsbG8gV29ybGQh"

# Show all encodings
cargo run -- all "Test"

# XOR encode
cargo run -- xor "Hello" --key "secret"

# XOR decode from hex
cargo run -- xor "1a0b..." --key "secret" --hex-input
```

## Commands

| Command | Description |
|---------|-------------|
| `encode` | Encode input with specified encoding |
| `decode` | Decode input with specified encoding |
| `auto` | Auto-detect and attempt decoding |
| `chain` | Apply multiple encodings in sequence |
| `analyze` | Analyze input characteristics |
| `all` | Show input in all encodings |
| `xor` | XOR encode/decode with key |

## Security Applications

- **Payload Analysis**: Decode obfuscated malicious payloads
- **CTF Solving**: Quick encoding/decoding for challenges
- **Web Testing**: Generate encoded test payloads
- **Malware Analysis**: Decode strings from malware samples

## Dependencies

- `clap` - CLI parsing
- `base64` - Base64 encoding
- `hex` - Hex encoding
- `urlencoding` - URL encoding
- `html-escape` - HTML entity handling
- `serde` - Serialization

## Testing

```bash
cargo test
```

## License

MIT
