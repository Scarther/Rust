# B04 - Environment Variable Tool

A security-focused environment variable inspection and manipulation utility.

## Overview

This project provides comprehensive environment variable management with security analysis:

- **List Variables**: View all environment variables with categorization
- **Get/Set Variables**: Safely read and modify environment variables
- **Security Audit**: Detect potential security issues in environment
- **Export/Import**: Save and compare environment snapshots
- **PATH Analysis**: Security check of PATH directories

## Security Features

1. **Sensitive Data Detection**: Automatically identifies variables that may contain secrets
2. **Value Sanitization**: Detects shell injection patterns in values
3. **PATH Security**: Checks for world-writable directories and relative paths
4. **LD_PRELOAD Detection**: Warns about library injection variables
5. **Proxy Detection**: Identifies traffic redirection settings

## Building

```bash
cargo build --release
```

## Usage

### List Environment Variables

```bash
# List all variables
./environment list

# Filter by pattern
./environment list -f "PATH|HOME"

# Show only sensitive variables
./environment list -s

# Sort alphabetically
./environment list -o

# Show actual values (including sensitive)
./environment list --show-values
```

### Get a Variable

```bash
# Get specific variable
./environment get HOME

# With default value
./environment get MY_VAR -d "default_value"
```

### Set a Variable

```bash
# Set a variable
./environment set MY_VAR "my_value"

# With safety check
./environment set MY_VAR "value" -c
```

### Security Audit

```bash
# Full audit
./environment audit

# Verbose audit
./environment -v audit
```

### PATH Analysis

```bash
# Basic PATH analysis
./environment path

# With security checks
./environment path -s
```

### Export Environment

```bash
# Export to JSON
./environment export -o env.json

# Export as shell script
./environment export -o env.sh -f shell

# Export as .env file
./environment export -o .env -f env

# Include sensitive variables (DANGER!)
./environment export -o env.json --include-sensitive
```

### Compare Environments

```bash
# Compare current environment with snapshot
./environment diff -s previous_env.json
```

## Key Rust Concepts Demonstrated

### Environment Handling

```rust
// Get a variable with error handling
let value = env::var("HOME")?;

// Set a variable
env::set_var("MY_VAR", "value");

// Remove a variable
env::remove_var("MY_VAR");

// Iterate all variables
for (key, value) in env::vars() {
    println!("{}={}", key, value);
}
```

### Pattern Matching

```rust
// Using const arrays for patterns
const SENSITIVE_PATTERNS: &[&str] = &["PASSWORD", "SECRET", "TOKEN"];

// Pattern matching with iterators
fn is_sensitive(name: &str) -> bool {
    SENSITIVE_PATTERNS.iter().any(|p| name.contains(p))
}
```

### Serialization

```rust
#[derive(Serialize, Deserialize)]
struct EnvVariable {
    name: String,
    value: String,
}

// Serialize to JSON
let json = serde_json::to_string_pretty(&data)?;

// Deserialize from JSON
let data: EnvVariable = serde_json::from_str(&json)?;
```

## Security Considerations

1. **Environment variables are inherited** by child processes
2. **Secrets in environment** can be leaked through:
   - Process listings (`ps aux`)
   - Core dumps
   - Log files
   - Error messages
3. **LD_PRELOAD and LD_LIBRARY_PATH** can be used for code injection
4. **PATH manipulation** can lead to command hijacking
5. **Proxy settings** can redirect network traffic

## Variable Categories

| Category | Description | Examples |
|----------|-------------|----------|
| sensitive | May contain secrets | API_KEY, PASSWORD, TOKEN |
| security | Affects program behavior | PATH, LD_PRELOAD |
| path | File system paths | HOME, TMPDIR |
| language | Programming runtime | RUST_BACKTRACE, PYTHONPATH |
| system | System configuration | LANG, TERM, SHELL |
| user | User-defined | Custom variables |

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
- `regex` - Regular expression support
- `serde` / `serde_json` - Serialization
