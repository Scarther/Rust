# Exercise 02: Borrowing and References

## Overview

Borrowing allows you to access data without taking ownership. This is essential for efficient code that doesn't unnecessarily copy data.

## Key Concepts

### Immutable References (&T)

- Allow reading data without taking ownership
- Multiple immutable references can exist simultaneously
- Cannot modify the data through an immutable reference

```rust
let data = String::from("secret");
let ref1 = &data; // First immutable borrow
let ref2 = &data; // Second immutable borrow - OK!
println!("{} {}", ref1, ref2);
```

### Mutable References (&mut T)

- Allow reading AND modifying data without taking ownership
- Only ONE mutable reference can exist at a time
- Cannot have mutable and immutable references simultaneously

```rust
let mut data = String::from("secret");
let ref_mut = &mut data;
ref_mut.push_str("_modified");
// Cannot create another reference while ref_mut exists
```

### The Borrowing Rules

1. At any given time, you can have EITHER:
   - One mutable reference, OR
   - Any number of immutable references

2. References must always be valid (no dangling references)

## Security Applications

### Efficient Data Inspection

```rust
fn check_for_vulnerabilities(data: &[u8]) -> bool {
    // Inspect without copying potentially large data
    data.windows(4).any(|w| w == b"\x00\x00\x00\x00")
}
```

### Safe Password Validation

```rust
fn validate_password(password: &str, policy: &Policy) -> Result<(), Vec<&str>> {
    // Borrow both password and policy for validation
    // Neither is consumed
}
```

## Exercises

1. **Immutable References** - Multiple readers, no writers
2. **Mutable References** - Single writer, in-place modification
3. **Reference Rules** - Understanding borrow checker constraints
4. **References in Functions** - Efficient function signatures
5. **Multiple Immutable Borrows** - Parallel read access
6. **Borrowing in Loops** - Iteration patterns
7. **Security Audit Trail** - Event logging with references
8. **Password Validator** - Multi-rule validation
9. **Network Packet Inspector** - Efficient payload analysis
10. **Access Control System** - Role-based access checking

## Running

```bash
cd exercises/02_borrowing
cargo run
```

## Common Patterns

### Borrow for Read, Own for Store
```rust
fn process(data: &str) -> ProcessedData {
    // Borrow for processing
    ProcessedData::from(data)
}
```

### Return References to Internal Data
```rust
impl Container {
    fn get(&self, key: &str) -> Option<&Value> {
        self.map.get(key)
    }
}
```
