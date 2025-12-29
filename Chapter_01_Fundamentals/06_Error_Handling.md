# Lesson 06: Error Handling

## Overview

Learn how Rust handles errors safely and expressively. Rust doesn't have exceptions - instead, it uses `Result` and `Option` types that force you to handle errors explicitly.

**Time:** 45 minutes
**Difficulty:** Beginner

---

## What You'll Learn

- The difference between recoverable and unrecoverable errors
- Using `Result<T, E>` for operations that can fail
- Using `Option<T>` for values that might not exist
- The `?` operator for error propagation
- Creating custom error types
- Best practices for error handling

---

## Two Types of Errors

| Type | Rust Tool | When to Use |
|------|-----------|-------------|
| **Recoverable** | `Result<T, E>` | File not found, network timeout |
| **Unrecoverable** | `panic!` | Bug in code, corrupted state |

---

## Unrecoverable Errors: panic!

When something goes catastrophically wrong:

```rust
fn main() {
    // Explicit panic
    // panic!("Something went terribly wrong!");

    // Implicit panic (array out of bounds)
    let arr = [1, 2, 3];
    // let bad = arr[99];  // This panics!
}
```

**When to panic:**
- Bug in your code (should never happen)
- Unrecoverable state
- During prototyping/examples

**When NOT to panic:**
- User provides bad input
- File doesn't exist
- Network connection fails

---

## Recoverable Errors: Result<T, E>

Most operations that can fail return `Result`:

```rust
enum Result<T, E> {
    Ok(T),   // Success, contains value
    Err(E),  // Failure, contains error
}
```

### Reading a File

```rust
use std::fs::File;

fn main() {
    let result = File::open("hello.txt");

    match result {
        Ok(file) => {
            println!("File opened successfully!");
            // Use the file...
        }
        Err(error) => {
            println!("Failed to open file: {}", error);
        }
    }
}
```

### The match Pattern

```rust
use std::fs::File;
use std::io::ErrorKind;

fn main() {
    let result = File::open("config.txt");

    let file = match result {
        Ok(file) => file,
        Err(error) => match error.kind() {
            ErrorKind::NotFound => {
                println!("File not found, creating it...");
                File::create("config.txt").expect("Failed to create file")
            }
            ErrorKind::PermissionDenied => {
                panic!("Permission denied!");
            }
            other_error => {
                panic!("Problem opening file: {:?}", other_error);
            }
        },
    };

    println!("Got file: {:?}", file);
}
```

---

## Shortcuts for Result

### unwrap() - Get Value or Panic

```rust
use std::fs::File;

fn main() {
    // Panics if file doesn't exist
    let file = File::open("hello.txt").unwrap();
}
```

### expect() - Panic with Custom Message

```rust
use std::fs::File;

fn main() {
    // Panics with your message
    let file = File::open("config.txt")
        .expect("config.txt should be included in the project");
}
```

### unwrap_or() - Default Value

```rust
fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or("8080".to_string())
        .parse()
        .unwrap_or(8080);

    println!("Using port: {}", port);
}
```

### unwrap_or_else() - Default with Closure

```rust
fn main() {
    let value = some_operation()
        .unwrap_or_else(|err| {
            eprintln!("Error: {}", err);
            "default".to_string()
        });
}
```

---

## The ? Operator: Error Propagation

The `?` operator is magic for clean error handling:

```rust
use std::fs::File;
use std::io::{self, Read};

// Without ? (verbose)
fn read_file_verbose(path: &str) -> Result<String, io::Error> {
    let file_result = File::open(path);

    let mut file = match file_result {
        Ok(file) => file,
        Err(e) => return Err(e),
    };

    let mut contents = String::new();

    match file.read_to_string(&mut contents) {
        Ok(_) => Ok(contents),
        Err(e) => Err(e),
    }
}

// With ? (clean!)
fn read_file(path: &str) -> Result<String, io::Error> {
    let mut file = File::open(path)?;  // Returns early if error
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;  // Returns early if error
    Ok(contents)
}

fn main() {
    match read_file("hello.txt") {
        Ok(contents) => println!("File contents: {}", contents),
        Err(e) => println!("Error reading file: {}", e),
    }
}
```

### Chaining with ?

```rust
use std::fs::File;
use std::io::{self, Read};

fn read_file_chained(path: &str) -> Result<String, io::Error> {
    let mut contents = String::new();
    File::open(path)?.read_to_string(&mut contents)?;
    Ok(contents)
}
```

### Using ? in main()

```rust
use std::fs::File;
use std::io::{self, Read};

fn main() -> Result<(), io::Error> {
    let mut file = File::open("hello.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    println!("{}", contents);
    Ok(())
}
```

---

## Option<T>: Values That Might Not Exist

When a value might be absent (not an error, just no value):

```rust
enum Option<T> {
    Some(T),  // Has a value
    None,     // No value
}
```

### Common Uses

```rust
fn main() {
    // Finding an element
    let numbers = vec![1, 2, 3, 4, 5];
    let first = numbers.first();  // Returns Option<&i32>

    match first {
        Some(num) => println!("First number: {}", num),
        None => println!("List is empty"),
    }

    // Getting from a HashMap
    use std::collections::HashMap;
    let mut scores = HashMap::new();
    scores.insert("Alice", 100);

    match scores.get("Bob") {
        Some(score) => println!("Bob's score: {}", score),
        None => println!("Bob not found"),
    }

    // Parsing might fail
    let maybe_num: Option<i32> = "42".parse().ok();
}
```

### Option Methods

```rust
fn main() {
    let some_value = Some(5);
    let no_value: Option<i32> = None;

    // is_some() and is_none()
    if some_value.is_some() {
        println!("Has a value!");
    }

    // unwrap() - panics if None
    let val = some_value.unwrap();

    // unwrap_or() - default if None
    let val = no_value.unwrap_or(0);
    println!("Value: {}", val);  // 0

    // map() - transform if Some
    let doubled = some_value.map(|x| x * 2);
    println!("Doubled: {:?}", doubled);  // Some(10)

    // and_then() - chain operations
    let result = some_value
        .map(|x| x * 2)
        .and_then(|x| if x > 5 { Some(x) } else { None });
}
```

### Using ? with Option

```rust
fn get_first_char(s: &str) -> Option<char> {
    s.chars().next()
}

fn get_first_char_uppercase(s: &str) -> Option<char> {
    let c = get_first_char(s)?;  // Returns None if no char
    Some(c.to_ascii_uppercase())
}

fn main() {
    println!("{:?}", get_first_char_uppercase("hello"));  // Some('H')
    println!("{:?}", get_first_char_uppercase(""));       // None
}
```

---

## Creating Functions That Return Result

```rust
use std::num::ParseIntError;

fn parse_port(s: &str) -> Result<u16, ParseIntError> {
    let port: u16 = s.parse()?;
    Ok(port)
}

fn validate_port(s: &str) -> Result<u16, String> {
    let port: u16 = s.parse()
        .map_err(|_| format!("'{}' is not a valid number", s))?;

    if port == 0 {
        return Err("Port cannot be 0".to_string());
    }

    if port < 1024 {
        return Err(format!("Port {} requires root privileges", port));
    }

    Ok(port)
}

fn main() {
    match validate_port("8080") {
        Ok(port) => println!("Using port: {}", port),
        Err(e) => println!("Error: {}", e),
    }

    match validate_port("80") {
        Ok(port) => println!("Using port: {}", port),
        Err(e) => println!("Error: {}", e),
    }
}
```

---

## Custom Error Types

### Simple String Errors

```rust
fn connect(addr: &str) -> Result<(), String> {
    if !addr.contains(':') {
        return Err("Address must include port".to_string());
    }

    // Try to connect...
    Ok(())
}
```

### Enum Errors

```rust
#[derive(Debug)]
enum NetworkError {
    ConnectionFailed(String),
    Timeout,
    InvalidAddress,
    PermissionDenied,
}

fn connect(addr: &str, timeout_ms: u64) -> Result<(), NetworkError> {
    if addr.is_empty() {
        return Err(NetworkError::InvalidAddress);
    }

    if timeout_ms == 0 {
        return Err(NetworkError::Timeout);
    }

    // Simulate connection failure
    Err(NetworkError::ConnectionFailed(
        format!("Could not connect to {}", addr)
    ))
}

fn main() {
    match connect("192.168.1.1:80", 1000) {
        Ok(_) => println!("Connected!"),
        Err(NetworkError::ConnectionFailed(msg)) => {
            println!("Connection failed: {}", msg);
        }
        Err(NetworkError::Timeout) => {
            println!("Connection timed out");
        }
        Err(NetworkError::InvalidAddress) => {
            println!("Invalid address provided");
        }
        Err(NetworkError::PermissionDenied) => {
            println!("Permission denied");
        }
    }
}
```

### Using thiserror Crate (Recommended)

```toml
[dependencies]
thiserror = "1.0"
```

```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum ScanError {
    #[error("Connection to {0}:{1} failed")]
    ConnectionFailed(String, u16),

    #[error("Port {0} is not valid (must be 1-65535)")]
    InvalidPort(u16),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

fn scan_port(host: &str, port: u16) -> Result<bool, ScanError> {
    if port == 0 {
        return Err(ScanError::InvalidPort(port));
    }

    // Use ? with std::io::Error - automatically converts
    let addr = format!("{}:{}", host, port);
    // std::net::TcpStream::connect(&addr)?;

    Ok(true)
}
```

---

## Best Practices

### 1. Don't Panic in Libraries

```rust
// Bad - panics on error
fn parse_config(path: &str) -> Config {
    let contents = std::fs::read_to_string(path).unwrap();  // Panic!
    // ...
}

// Good - returns Result
fn parse_config(path: &str) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    // ...
}
```

### 2. Use expect() Over unwrap()

```rust
// Bad - unhelpful panic message
let file = File::open("config.txt").unwrap();

// Good - explains why this should work
let file = File::open("config.txt")
    .expect("config.txt must exist - it's created during installation");
```

### 3. Convert Errors at Boundaries

```rust
// Convert low-level errors to domain errors
fn load_user(id: u32) -> Result<User, AppError> {
    let data = std::fs::read_to_string(format!("users/{}.json", id))
        .map_err(|_| AppError::UserNotFound(id))?;

    serde_json::from_str(&data)
        .map_err(|_| AppError::CorruptUserData(id))
}
```

### 4. Use anyhow for Applications

```toml
[dependencies]
anyhow = "1.0"
```

```rust
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let config = std::fs::read_to_string("config.txt")
        .context("Failed to read config file")?;

    let port: u16 = config.trim().parse()
        .context("Config must contain a valid port number")?;

    println!("Running on port {}", port);
    Ok(())
}
```

---

## Security Example: Safe Input Handling

```rust
use std::io::{self, BufRead};

#[derive(Debug)]
enum InputError {
    Empty,
    TooLong,
    InvalidCharacters,
    IoError(io::Error),
}

fn get_safe_input(max_len: usize) -> Result<String, InputError> {
    let stdin = io::stdin();
    let mut line = String::new();

    stdin.lock().read_line(&mut line)
        .map_err(InputError::IoError)?;

    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(InputError::Empty);
    }

    if trimmed.len() > max_len {
        return Err(InputError::TooLong);
    }

    // Only allow alphanumeric and some punctuation
    if !trimmed.chars().all(|c| c.is_alphanumeric() || "._-".contains(c)) {
        return Err(InputError::InvalidCharacters);
    }

    Ok(trimmed)
}

fn main() {
    println!("Enter username (max 32 chars, alphanumeric only):");

    match get_safe_input(32) {
        Ok(username) => println!("Welcome, {}!", username),
        Err(InputError::Empty) => println!("Username cannot be empty"),
        Err(InputError::TooLong) => println!("Username too long"),
        Err(InputError::InvalidCharacters) => println!("Invalid characters"),
        Err(InputError::IoError(e)) => println!("IO error: {}", e),
    }
}
```

---

## Try It Yourself

### Exercise 1: Parse with Validation

Write a function that parses an IP address string and validates each octet:

```rust
fn parse_ip(s: &str) -> Result<[u8; 4], String> {
    // "192.168.1.1" -> Ok([192, 168, 1, 1])
    // "256.1.1.1" -> Err("Invalid octet: 256")
    todo!()
}
```

### Exercise 2: Chain Operations

Use the `?` operator to write a function that:
1. Reads a file
2. Parses it as a number
3. Returns the number doubled

### Exercise 3: Custom Error Type

Create an error enum for a password validator with variants:
- TooShort
- NoUppercase
- NoDigit
- CommonPassword

---

## Key Takeaways

1. **Use `Result<T, E>`** for recoverable errors
2. **Use `panic!`** only for bugs/unrecoverable states
3. **Use `Option<T>`** when values might not exist
4. **Use `?`** to propagate errors cleanly
5. **Use `expect()`** over `unwrap()` for better messages
6. **Create custom error types** for domain-specific errors
7. **Never panic in library code** - let the caller decide

---

[← Previous: Structs & Enums](./05_Structs_Enums.md) | [Next: Collections →](./07_Collections.md)
