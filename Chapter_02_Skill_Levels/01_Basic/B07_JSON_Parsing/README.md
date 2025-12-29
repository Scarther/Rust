# B07 - JSON Parsing Tool

A security-focused JSON parsing and manipulation utility.

## Overview

This project provides comprehensive JSON handling with security analysis:

- **Parse/Validate**: Parse and validate JSON from files or stdin
- **Query**: Extract data using JSONPath expressions
- **Analyze**: Inspect JSON structure and detect sensitive data
- **Create**: Build JSON from key-value pairs
- **Modify**: Update or delete values in JSON
- **Sanitize**: Remove or mask sensitive fields

## Security Features

1. **Sensitive Data Detection**: Automatically identifies passwords, API keys, tokens
2. **Data Sanitization**: Remove or mask sensitive fields before sharing
3. **Structure Analysis**: Understand JSON complexity and content
4. **Safe Parsing**: Proper error handling for malformed JSON

## Building

```bash
cargo build --release
```

## Usage

### Parse JSON

```bash
# Parse from file
./json_parsing parse -f data.json

# Parse from string
./json_parsing parse -s '{"key": "value"}'

# Pretty print
./json_parsing parse -f data.json -p

# Compact output
./json_parsing parse -f data.json -c

# Parse from stdin
cat data.json | ./json_parsing parse
```

### Query JSON

```bash
# Query using JSONPath
./json_parsing query -f data.json -p '$.users[*].name'

# Output as JSON array
./json_parsing query -f data.json -p '$.items[0]' -j

# Complex queries
./json_parsing query -f data.json -p '$.users[?(@.age > 18)].name'
```

### Analyze JSON

```bash
# Basic analysis
./json_parsing analyze -f data.json

# Check for sensitive data
./json_parsing analyze -f data.json -s
```

### Create JSON

```bash
# Simple key-value pairs
./json_parsing create -p name=John -p age=30

# Nested paths
./json_parsing create -n user.name=John -n user.email=john@example.com

# Save to file
./json_parsing create -p name=John -o output.json -p
```

### Modify JSON

```bash
# Set values
./json_parsing modify -f data.json -s user.name=Jane

# Delete keys
./json_parsing modify -f data.json -d user.password

# Multiple operations
./json_parsing modify -f data.json -s status=active -d temp_field -o output.json
```

### Diff JSON

```bash
# Compare two files
./json_parsing diff -f file1.json -f file2.json

# Show only differences
./json_parsing diff -f file1.json -f file2.json -o
```

### Sanitize JSON

```bash
# Remove sensitive fields
./json_parsing sanitize -f data.json

# Mask instead of removing
./json_parsing sanitize -f data.json -m

# Additional fields to remove
./json_parsing sanitize -f data.json -r email -r phone

# Save to file
./json_parsing sanitize -f data.json -o clean.json
```

### Merge JSON

```bash
# Merge multiple files
./json_parsing merge -f base.json -f overlay.json

# Deep merge
./json_parsing merge -f base.json -f overlay.json -d

# Save to file
./json_parsing merge -f base.json -f overlay.json -o merged.json
```

## Key Rust Concepts Demonstrated

### Serde Serialization

```rust
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// Define structures
#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    age: u32,
}

// Parse JSON string
let user: User = serde_json::from_str(json_str)?;

// Create JSON dynamically
let value = json!({
    "name": "John",
    "items": [1, 2, 3]
});

// Serialize to string
let json_str = serde_json::to_string_pretty(&value)?;
```

### Working with serde_json::Value

```rust
use serde_json::Value;

// Access nested values
let name = value["user"]["name"].as_str();

// Modify values
if let Some(obj) = value.as_object_mut() {
    obj.insert("new_key".to_string(), json!("new_value"));
}

// Pattern matching on value types
match &value {
    Value::Object(map) => { /* handle object */ }
    Value::Array(arr) => { /* handle array */ }
    Value::String(s) => { /* handle string */ }
    Value::Number(n) => { /* handle number */ }
    Value::Bool(b) => { /* handle boolean */ }
    Value::Null => { /* handle null */ }
}
```

### Recursive Processing

```rust
fn process_value(value: &Value, depth: usize) {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                process_value(val, depth + 1);
            }
        }
        Value::Array(arr) => {
            for val in arr {
                process_value(val, depth + 1);
            }
        }
        _ => { /* handle leaf values */ }
    }
}
```

## Sensitive Data Patterns

The tool detects these patterns in key names:

| Pattern | Description |
|---------|-------------|
| password | User passwords |
| secret | Secret values |
| token | Authentication tokens |
| api_key | API keys |
| credential | Credentials |
| private_key | Private keys |
| access_key | Access keys |
| session | Session data |
| jwt | JSON Web Tokens |
| ssn | Social Security Numbers |
| credit_card | Credit card info |
| cvv | Card verification values |

## JSONPath Examples

| Expression | Description |
|------------|-------------|
| `$.store.book[*].author` | Authors of all books |
| `$..author` | All authors (recursive) |
| `$.store.*` | All things in store |
| `$.store..price` | All prices |
| `$..book[0,1]` | First two books |
| `$..book[:2]` | First two books |
| `$..book[?(@.price<10)]` | Books cheaper than 10 |
| `$..book[?(@.author)]` | Books with author |

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
- `serde` / `serde_json` - JSON serialization
- `jsonpath-rust` - JSONPath query support
