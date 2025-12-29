# Exercise 01: Ownership

## Overview

Ownership is Rust's most unique feature and has deep implications for the rest of the language. It enables Rust to make memory safety guarantees without needing a garbage collector.

## Key Concepts

### What is Ownership?

Ownership is a set of rules that govern how a Rust program manages memory:

1. **Each value in Rust has an owner**
2. **There can only be one owner at a time**
3. **When the owner goes out of scope, the value will be dropped**

### Why Ownership Matters for Security

- **No dangling pointers**: Memory is automatically freed when the owner goes out of scope
- **No double-free bugs**: Only one owner means memory can only be freed once
- **Clear data flow**: You can track exactly where sensitive data goes
- **Automatic cleanup**: Sensitive data is cleared when it goes out of scope

## Exercises

### Exercise 1: Basic Ownership Transfer
Learn how values move when assigned to new variables.

### Exercise 2: Clone vs Move
Understand when to copy data and when moving is sufficient.

### Exercise 3: Ownership in Functions
See how function calls transfer ownership.

### Exercise 4: Return Ownership
Learn to return ownership from functions.

### Exercise 5: Ownership with Tuples
Use tuples to return multiple values with their ownership.

### Exercise 6: Security Context Ownership
Implement single-use security contexts.

### Exercise 7: Sensitive Data Handling
Create data structures that securely clear memory.

### Exercise 8: Resource Management
Manage cryptographic keys with ownership.

### Exercise 9: Ownership Chains
Build data pipelines with clear ownership flow.

### Exercise 10: Challenge - Secure Memory Transfer
Implement a secure, single-read data transfer system.

## Running the Exercises

```bash
cd exercises/01_ownership
cargo run
```

## Common Patterns

### Clone for Independent Copies
```rust
let original = String::from("data");
let copy = original.clone();
// Both are now valid
```

### Move Semantics
```rust
let original = String::from("data");
let moved = original;
// original is no longer valid
```

### Ownership in Functions
```rust
fn process(data: String) -> String {
    // data is owned by this function
    data.to_uppercase()
    // ownership of result is returned
}
```

## Security Best Practices

1. Use ownership to ensure sensitive data has a single, clear owner
2. Implement `Drop` trait for secure memory clearing
3. Use move semantics for "use once" security tokens
4. Consider `Box<T>` for heap-allocated sensitive data with clear ownership
