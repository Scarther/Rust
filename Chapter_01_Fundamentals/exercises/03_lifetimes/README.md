# Exercise 03: Lifetimes

## Overview

Lifetimes are Rust's way of ensuring references are valid for as long as they're used. They prevent dangling references and use-after-free bugs at compile time.

## Key Concepts

### What are Lifetimes?

Lifetimes are annotations that tell the Rust compiler how long references should be valid. Most of the time, lifetimes are inferred, but sometimes you need to annotate them explicitly.

### Lifetime Syntax

```rust
&'a T      // Reference with lifetime 'a
&'a mut T  // Mutable reference with lifetime 'a
```

### Why Lifetimes Matter for Security

- **No dangling pointers**: References can't outlive their data
- **No use-after-free**: Compiler prevents accessing freed memory
- **Zero-copy parsing**: Parse data without copying, safely
- **Clear data flow**: Track exactly how long data is accessible

## Common Patterns

### Function Lifetime Annotations

```rust
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}
```

### Struct Lifetime Annotations

```rust
struct Parser<'a> {
    input: &'a str,
    position: usize,
}
```

### Method Lifetime Annotations

```rust
impl<'a> Parser<'a> {
    fn remaining(&self) -> &'a str {
        &self.input[self.position..]
    }
}
```

### Static Lifetime

```rust
let s: &'static str = "I live forever";

fn error_message(code: u32) -> &'static str {
    match code {
        404 => "Not Found",
        _ => "Unknown",
    }
}
```

## Exercises

1. **Basic Lifetime Annotations** - Simple function lifetimes
2. **Multiple Lifetimes** - Independent lifetime parameters
3. **Struct Lifetimes** - References in structs
4. **Method Lifetimes** - Self and parameter lifetimes
5. **Static Lifetime** - 'static references
6. **Lifetime Bounds** - Generic type constraints
7. **Security Token Validation** - Token parsing with lifetimes
8. **Log Parser** - Zero-copy log analysis
9. **Configuration Reader** - Efficient config parsing
10. **Zero-Copy HTTP Parser** - Complete request parsing

## Running

```bash
cd exercises/03_lifetimes
cargo run
```

## Lifetime Elision Rules

The compiler can often infer lifetimes using these rules:

1. Each elided lifetime in input position becomes a distinct lifetime parameter
2. If there's exactly one input lifetime, it's assigned to all output lifetimes
3. If there's a `&self` or `&mut self`, its lifetime is assigned to all output lifetimes

## Security Best Practices

1. Use lifetimes for zero-copy parsing of security data
2. Prefer borrowing over cloning for large security payloads
3. Use 'static for security error messages and constants
4. Combine with ownership for clear data custody chains
