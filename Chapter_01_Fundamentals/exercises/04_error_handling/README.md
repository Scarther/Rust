# Exercise 04: Error Handling

## Overview

Rust uses `Result<T, E>` and `Option<T>` for error handling instead of exceptions. This makes error handling explicit and catches potential errors at compile time.

## Key Concepts

### Option<T>

Represents a value that may or may not exist:
- `Some(value)` - Value exists
- `None` - No value

```rust
fn find_user(id: u32) -> Option<User> {
    users.get(&id).cloned()
}

match find_user(1) {
    Some(user) => println!("Found: {}", user.name),
    None => println!("User not found"),
}
```

### Result<T, E>

Represents success or failure:
- `Ok(value)` - Operation succeeded
- `Err(error)` - Operation failed

```rust
fn parse_config(data: &str) -> Result<Config, ConfigError> {
    // ...
}

match parse_config(input) {
    Ok(config) => use_config(config),
    Err(e) => eprintln!("Error: {}", e),
}
```

### The ? Operator

Propagates errors automatically:

```rust
fn load_config() -> Result<Config, Error> {
    let content = read_file("config.toml")?; // Returns early on error
    let config = parse_config(&content)?;
    Ok(config)
}
```

## Security Applications

### Authentication Errors

```rust
enum AuthError {
    InvalidCredentials,
    AccountLocked { attempts: u32 },
    SessionExpired,
    PermissionDenied { required_role: String },
}
```

### Validation Chains

```rust
fn validate_input(input: &str) -> Result<ValidatedInput, ValidationError> {
    let trimmed = input.trim();
    check_length(trimmed)?;
    check_format(trimmed)?;
    check_content(trimmed)?;
    Ok(ValidatedInput::new(trimmed))
}
```

## Exercises

1. **Option Basics** - Working with optional values
2. **Result Basics** - Handling success and failure
3. **The ? Operator** - Error propagation
4. **Custom Error Types** - Detailed error information
5. **Error Conversion** - From trait for error types
6. **Option Combinators** - map, and_then, filter, etc.
7. **Result Combinators** - Chaining Result operations
8. **Authentication Errors** - Complete auth error handling
9. **File Security Scanner** - Multi-error scanning
10. **Crypto Operation Pipeline** - Complex error chains

## Running

```bash
cd exercises/04_error_handling
cargo run
```

## Common Patterns

### Early Return with ?
```rust
fn process(data: &str) -> Result<Output, Error> {
    let validated = validate(data)?;
    let processed = transform(validated)?;
    Ok(finalize(processed))
}
```

### Error Context
```rust
file.read_to_string(&mut content)
    .map_err(|e| format!("Failed to read {}: {}", path, e))?;
```

### Collecting Results
```rust
let results: Result<Vec<_>, _> = items
    .iter()
    .map(|item| process(item))
    .collect();
```

## Best Practices

1. Use custom error types for domain-specific errors
2. Implement `Display` and `Error` for custom types
3. Use `From` for seamless error conversion
4. Prefer `?` over `unwrap()` in production code
5. Provide context when propagating errors
