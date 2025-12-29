# Lesson 02: Variables and Data Types

## Overview

Learn how Rust handles variables, understand the type system, and work with basic data types.

**Time:** 45 minutes
**Difficulty:** Beginner

---

## What You'll Learn

- Declaring variables with `let`
- Mutability in Rust
- Basic data types (integers, floats, booleans, characters)
- Compound types (tuples, arrays)
- Type inference vs explicit types
- Constants and shadowing

---

## Variables in Rust

### Immutable by Default

In Rust, variables are **immutable by default**. This prevents accidental changes and makes code safer.

```rust
fn main() {
    let x = 5;
    println!("x is: {}", x);

    // This would cause an error!
    // x = 6;  // ERROR: cannot assign twice to immutable variable
}
```

### Making Variables Mutable

Use the `mut` keyword to make a variable mutable:

```rust
fn main() {
    let mut x = 5;
    println!("x is: {}", x);

    x = 6;  // This works now!
    println!("x is now: {}", x);
}
```

Output:
```
x is: 5
x is now: 6
```

### Why Immutable by Default?

| Benefit | Explanation |
|---------|-------------|
| Safety | Prevents accidental modifications |
| Clarity | You know a value won't change |
| Concurrency | Easier to reason about in multi-threaded code |
| Optimization | Compiler can make better optimizations |

---

## Data Types

Rust is **statically typed** - every variable must have a known type at compile time.

### Integer Types

| Type | Size | Range | Signed? |
|------|------|-------|---------|
| `i8` | 8-bit | -128 to 127 | Yes |
| `i16` | 16-bit | -32,768 to 32,767 | Yes |
| `i32` | 32-bit | -2.1B to 2.1B | Yes |
| `i64` | 64-bit | Very large | Yes |
| `i128` | 128-bit | Huge | Yes |
| `isize` | Platform | Pointer size | Yes |
| `u8` | 8-bit | 0 to 255 | No |
| `u16` | 16-bit | 0 to 65,535 | No |
| `u32` | 32-bit | 0 to 4.2B | No |
| `u64` | 64-bit | 0 to very large | No |
| `u128` | 128-bit | 0 to huge | No |
| `usize` | Platform | Pointer size | No |

```rust
fn main() {
    // Integer types
    let port: u16 = 8080;           // Port number (0-65535)
    let count: i32 = -42;           // Signed integer
    let byte: u8 = 255;             // Single byte
    let big_number: u64 = 1_000_000; // Underscores for readability

    // Default is i32
    let default = 42;  // Type is i32

    println!("Port: {}", port);
    println!("Count: {}", count);
    println!("Byte: {}", byte);
    println!("Big: {}", big_number);
}
```

### Number Literals

```rust
fn main() {
    let decimal = 98_222;      // Decimal (underscores for readability)
    let hex = 0xff;            // Hexadecimal
    let octal = 0o77;          // Octal
    let binary = 0b1111_0000;  // Binary
    let byte = b'A';           // Byte (u8 only)

    println!("Decimal: {}", decimal);
    println!("Hex: {} (0xff)", hex);
    println!("Octal: {} (0o77)", octal);
    println!("Binary: {} (0b11110000)", binary);
    println!("Byte: {} (b'A')", byte);
}
```

Output:
```
Decimal: 98222
Hex: 255 (0xff)
Octal: 63 (0o77)
Binary: 240 (0b11110000)
Byte: 65 (b'A')
```

### Floating-Point Types

| Type | Size | Precision |
|------|------|-----------|
| `f32` | 32-bit | ~6-7 digits |
| `f64` | 64-bit | ~15-16 digits |

```rust
fn main() {
    let pi: f64 = 3.14159265359;
    let small: f32 = 2.5;

    // Default is f64
    let default = 3.14;  // Type is f64

    // Math operations
    let sum = 5.0 + 10.5;
    let difference = 95.5 - 4.3;
    let product = 4.0 * 30.0;
    let quotient = 56.7 / 32.2;

    println!("Pi: {}", pi);
    println!("Sum: {}", sum);
}
```

### Booleans

```rust
fn main() {
    let active: bool = true;
    let logged_in = false;  // Type inferred as bool

    // Common in conditions
    if active {
        println!("System is active");
    }

    // Boolean from comparison
    let is_adult = 25 >= 18;  // true
    println!("Is adult: {}", is_adult);
}
```

### Characters

Rust's `char` type is 4 bytes and represents a Unicode Scalar Value:

```rust
fn main() {
    let letter: char = 'A';
    let emoji = '🦀';  // Ferris the crab!
    let chinese = '中';
    let heart = '❤';

    println!("Letter: {}", letter);
    println!("Emoji: {}", emoji);
    println!("Chinese: {}", chinese);

    // Character to number
    let ascii_value = letter as u8;
    println!("ASCII value of 'A': {}", ascii_value);  // 65
}
```

---

## Compound Types

### Tuples

Group multiple values of different types:

```rust
fn main() {
    // Create a tuple
    let person: (String, i32, bool) = (
        String::from("Alice"),
        30,
        true
    );

    // Access by index (destructuring)
    let (name, age, active) = person.clone();
    println!("Name: {}, Age: {}, Active: {}", name, age, active);

    // Access by position
    let tup = (500, 6.4, 'x');
    println!("First: {}", tup.0);
    println!("Second: {}", tup.1);
    println!("Third: {}", tup.2);

    // Useful for returning multiple values
    let (ip, port) = ("192.168.1.1", 8080);
    println!("Connecting to {}:{}", ip, port);
}
```

### Arrays

Fixed-size collection of same type:

```rust
fn main() {
    // Array with explicit type
    let ports: [u16; 5] = [22, 80, 443, 8080, 8443];

    // Array with type inference
    let numbers = [1, 2, 3, 4, 5];

    // Array filled with same value
    let zeros = [0; 10];  // Ten zeros

    // Access elements
    println!("First port: {}", ports[0]);
    println!("Last port: {}", ports[4]);

    // Array length
    println!("Number of ports: {}", ports.len());

    // Iterate over array
    for port in ports {
        println!("Scanning port {}", port);
    }
}
```

**Important:** Array access is bounds-checked at runtime. Accessing an invalid index causes a panic:

```rust
fn main() {
    let arr = [1, 2, 3];
    // let bad = arr[10];  // PANIC: index out of bounds!
}
```

---

## Type Inference

Rust can often infer types from context:

```rust
fn main() {
    // Rust infers types
    let x = 5;           // i32 (default integer)
    let y = 3.14;        // f64 (default float)
    let z = true;        // bool
    let s = "hello";     // &str

    // Sometimes you need to specify
    let guess: u32 = "42".parse().expect("Not a number!");

    // Type from method return
    let ports = vec![80, 443, 8080];  // Vec<i32>
}
```

---

## Constants

Constants are always immutable and must have a type:

```rust
// Constants use SCREAMING_SNAKE_CASE
const MAX_CONNECTIONS: u32 = 1000;
const DEFAULT_PORT: u16 = 8080;
const PI: f64 = 3.14159265359;

fn main() {
    println!("Max connections: {}", MAX_CONNECTIONS);
    println!("Default port: {}", DEFAULT_PORT);

    // Constants can be used anywhere
    let timeout = MAX_CONNECTIONS * 2;
}
```

**Constants vs Variables:**

| Feature | `const` | `let` |
|---------|---------|-------|
| Mutability | Never | With `mut` |
| Type annotation | Required | Optional |
| Scope | Any | Block only |
| Compile-time | Yes | No |
| Naming convention | SCREAMING_CASE | snake_case |

---

## Shadowing

You can declare a new variable with the same name:

```rust
fn main() {
    let x = 5;
    println!("x: {}", x);  // 5

    let x = x + 1;  // Shadow the previous x
    println!("x: {}", x);  // 6

    {
        let x = x * 2;  // Shadow in inner scope
        println!("x in scope: {}", x);  // 12
    }

    println!("x after scope: {}", x);  // 6

    // Can even change types with shadowing
    let data = "   hello   ";
    let data = data.trim();  // Now it's trimmed
    let data = data.len();   // Now it's a usize!
    println!("Length: {}", data);
}
```

**Shadowing vs Mutation:**

```rust
fn main() {
    // Shadowing - creates new variable
    let x = 5;
    let x = "five";  // OK - different type

    // Mutation - changes existing variable
    let mut y = 5;
    // y = "five";  // ERROR - can't change type
    y = 6;          // OK - same type
}
```

---

## Security-Relevant Examples

### IP Address Parsing

```rust
fn main() {
    // Store IP octets
    let ip: [u8; 4] = [192, 168, 1, 1];
    println!("IP: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);

    // Port range
    let start_port: u16 = 1;
    let end_port: u16 = 1024;
    println!("Scanning ports {} to {}", start_port, end_port);
}
```

### Byte Operations

```rust
fn main() {
    // Working with bytes
    let packet: [u8; 4] = [0x45, 0x00, 0x00, 0x3c];

    // Extract IP version (upper 4 bits of first byte)
    let version = (packet[0] >> 4) & 0x0F;
    println!("IP Version: {}", version);  // 4

    // Header length (lower 4 bits * 4)
    let header_len = (packet[0] & 0x0F) * 4;
    println!("Header length: {} bytes", header_len);  // 20
}
```

### Hash Representation

```rust
fn main() {
    // MD5 hash as bytes
    let hash: [u8; 16] = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    ];

    // Convert to hex string
    let hex: String = hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("MD5: {}", hex);
}
```

---

## Try It Yourself

### Exercise 1: Variable Practice

Create variables to store:
- Your age (integer)
- Your height in meters (float)
- Whether you know Rust (boolean)
- First letter of your name (character)

Print them all.

### Exercise 2: Port Array

Create an array of common ports: 21, 22, 23, 25, 80, 443, 3306, 3389

Loop through and print each one.

### Exercise 3: Type Conversion

```rust
fn main() {
    let port_str = "8080";
    // Convert port_str to u16 and store in port
    // Hint: use .parse() and handle the Result

    let byte: u8 = 65;
    // Convert byte to char and print it
    // Hint: use 'as char'
}
```

---

## Common Errors

### Type Mismatch

```rust
let x: i32 = 5;
let y: i64 = x;  // ERROR: mismatched types
```

**Fix:** Explicit conversion:
```rust
let y: i64 = x as i64;
```

### Integer Overflow

```rust
let x: u8 = 255;
let y = x + 1;  // PANIC in debug mode!
```

**Fix:** Use wrapping, saturating, or checked arithmetic:
```rust
let y = x.wrapping_add(1);  // Wraps to 0
let y = x.saturating_add(1);  // Stays at 255
let y = x.checked_add(1);  // Returns None
```

---

## Key Takeaways

1. **Variables are immutable by default** - Use `mut` for mutable
2. **Rust is statically typed** - Types known at compile time
3. **Type inference is smart** - But sometimes you need annotations
4. **Use appropriate integer sizes** - `u16` for ports, `u8` for bytes
5. **Shadowing creates new variables** - Can change types
6. **Arrays are fixed-size** - Use `Vec` for dynamic sizes (next chapter)

---

[← Previous: Getting Started](./01_Getting_Started.md) | [Next: Functions →](./03_Functions.md)
