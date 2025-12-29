# Lesson 04: Ownership and Borrowing

## Overview

This is the most important lesson in Rust. Ownership is Rust's unique approach to memory safety without garbage collection. Master this, and the rest of Rust becomes much easier.

**Time:** 60 minutes
**Difficulty:** Beginner (but fundamental!)

---

## What You'll Learn

- What ownership is and why it matters
- The three ownership rules
- How data is moved and copied
- References and borrowing
- The borrow checker
- Slices

---

## Why Ownership Matters

In other languages:
- **C/C++:** You manage memory manually (prone to bugs)
- **Java/Python:** Garbage collector manages memory (runtime overhead)
- **Rust:** Ownership system manages memory (compile-time, zero cost)

Ownership prevents:
- Use-after-free bugs
- Double-free bugs
- Memory leaks
- Data races
- Buffer overflows

---

## The Three Rules of Ownership

```
1. Each value in Rust has a single OWNER
2. There can only be ONE owner at a time
3. When the owner goes out of SCOPE, the value is DROPPED
```

Let's see each rule in action.

---

## Rule 1: Each Value Has an Owner

```rust
fn main() {
    let s = String::from("hello");  // s owns the String
    //  ↑ owner        ↑ value

    let x = 5;  // x owns the value 5
    //  ↑ owner  ↑ value
}
```

---

## Rule 2: Only One Owner at a Time

### The Move

When you assign a variable to another, ownership **moves**:

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = s1;  // s1's value MOVES to s2

    // println!("{}", s1);  // ERROR! s1 no longer valid
    println!("{}", s2);     // OK - s2 owns the value now
}
```

**Why does this happen?**

`String` is stored on the heap. If both `s1` and `s2` pointed to the same data, we'd have double-free problems when both go out of scope.

```
Stack                    Heap
+-------+              +----------------+
| s1    | ---(moved)   | "hello"        |
+-------+              +----------------+
                            ↑
+-------+              |    |
| s2    | -------------+----+
+-------+
```

### Copy Types

Simple types that live entirely on the stack implement `Copy`:

```rust
fn main() {
    let x = 5;
    let y = x;  // x is COPIED, not moved

    println!("x: {}, y: {}", x, y);  // Both valid!
}
```

**Copy types include:**
- All integers (`i32`, `u8`, etc.)
- Booleans (`bool`)
- Floating-point (`f32`, `f64`)
- Characters (`char`)
- Tuples containing only Copy types

---

## Rule 3: Values are Dropped When Owner Goes Out of Scope

```rust
fn main() {
    {
        let s = String::from("hello");
        // s is valid here
        println!("{}", s);
    }  // s goes out of scope, memory is freed

    // println!("{}", s);  // ERROR! s no longer exists
}
```

---

## Ownership and Functions

### Moving Into Functions

```rust
fn main() {
    let s = String::from("hello");

    takes_ownership(s);  // s moves into the function

    // println!("{}", s);  // ERROR! s was moved
}

fn takes_ownership(some_string: String) {
    println!("{}", some_string);
}  // some_string is dropped here
```

### Returning Ownership

```rust
fn main() {
    let s1 = gives_ownership();  // Gets ownership from function
    println!("{}", s1);

    let s2 = String::from("hello");
    let s3 = takes_and_gives_back(s2);  // s2 moved in, result moved to s3
    println!("{}", s3);
}

fn gives_ownership() -> String {
    let s = String::from("yours");
    s  // Ownership moves to caller
}

fn takes_and_gives_back(a_string: String) -> String {
    a_string  // Ownership moves back
}
```

**This is tedious!** We don't want to pass ownership back and forth constantly. That's where **borrowing** comes in.

---

## Borrowing with References

A **reference** lets you use a value without taking ownership:

```rust
fn main() {
    let s = String::from("hello");

    let len = calculate_length(&s);  // Pass a reference

    println!("'{}' has length {}", s, len);  // s still valid!
}

fn calculate_length(s: &String) -> usize {  // Takes a reference
    s.len()
}  // s goes out of scope, but doesn't drop the String
```

The `&` creates a reference:

```
Stack                    Heap
+-------+
| s     | -----------→ "hello"
+-------+                 ↑
                          |
+-------+                 |
| &s    | ----------------+  (points to s, not heap directly)
+-------+
```

### Mutable References

By default, references are **immutable**. Use `&mut` for mutable references:

```rust
fn main() {
    let mut s = String::from("hello");

    change(&mut s);  // Pass mutable reference

    println!("{}", s);  // "hello, world"
}

fn change(s: &mut String) {
    s.push_str(", world");
}
```

### The Borrowing Rules

```
1. You can have EITHER:
   - Any number of immutable references (&T)
   - OR exactly one mutable reference (&mut T)

2. References must always be VALID
```

### Multiple Immutable References: OK

```rust
fn main() {
    let s = String::from("hello");

    let r1 = &s;  // OK
    let r2 = &s;  // OK - multiple immutable refs
    let r3 = &s;  // OK

    println!("{}, {}, {}", r1, r2, r3);
}
```

### Mutable + Immutable: NOT OK

```rust
fn main() {
    let mut s = String::from("hello");

    let r1 = &s;      // OK - immutable ref
    let r2 = &s;      // OK - another immutable ref
    // let r3 = &mut s;  // ERROR! Can't have mutable while immutable exists

    println!("{}, {}", r1, r2);
}
```

### Two Mutable References: NOT OK

```rust
fn main() {
    let mut s = String::from("hello");

    let r1 = &mut s;
    // let r2 = &mut s;  // ERROR! Only one mutable ref at a time

    println!("{}", r1);
}
```

### Why These Rules?

They prevent **data races** at compile time:

- Two pointers accessing the same data
- At least one is writing
- No synchronization

This is impossible in safe Rust!

---

## Reference Scope (Non-Lexical Lifetimes)

References are valid until their last use:

```rust
fn main() {
    let mut s = String::from("hello");

    let r1 = &s;
    let r2 = &s;
    println!("{} and {}", r1, r2);
    // r1 and r2 are no longer used after this point

    let r3 = &mut s;  // OK! No conflict
    println!("{}", r3);
}
```

---

## Dangling References

Rust prevents dangling references at compile time:

```rust
fn main() {
    let reference_to_nothing = dangle();
}

fn dangle() -> &String {  // ERROR!
    let s = String::from("hello");
    &s  // Returns reference to s
}  // s is dropped here - reference would be invalid!
```

**Fix:** Return the owned value:

```rust
fn no_dangle() -> String {
    let s = String::from("hello");
    s  // Ownership moves to caller
}
```

---

## Slices: Borrowing Parts of Data

A **slice** is a reference to a contiguous sequence:

### String Slices

```rust
fn main() {
    let s = String::from("hello world");

    let hello = &s[0..5];   // "hello"
    let world = &s[6..11];  // "world"

    // Shorthand
    let hello = &s[..5];    // From start
    let world = &s[6..];    // To end
    let whole = &s[..];     // Whole string

    println!("{} {}", hello, world);
}
```

### Array Slices

```rust
fn main() {
    let arr = [1, 2, 3, 4, 5];

    let slice = &arr[1..3];  // [2, 3]

    println!("{:?}", slice);

    // Works with any array/vector
    let first_three = &arr[..3];  // [1, 2, 3]
}
```

### String Slices and Functions

```rust
fn main() {
    let sentence = String::from("hello world");

    let word = first_word(&sentence);
    println!("First word: {}", word);
}

fn first_word(s: &str) -> &str {  // Takes &str, returns &str
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[..i];
        }
    }

    &s[..]  // Whole string if no space
}
```

**Note:** `&str` (string slice) is more flexible than `&String`:

```rust
fn print_str(s: &str) {
    println!("{}", s);
}

fn main() {
    let string = String::from("hello");
    let literal = "world";

    print_str(&string);   // Works with &String
    print_str(literal);   // Works with &str
    print_str(&string[..]); // Works with slice
}
```

---

## Security-Relevant Example: Safe Buffer Handling

```rust
fn main() {
    // Read some data
    let mut buffer = vec![0u8; 1024];

    // Process returns a slice of valid data
    let valid_data = process_packet(&mut buffer);

    // Can only access valid portion
    println!("Received {} bytes", valid_data.len());

    // buffer is still owned by main, safely cleaned up
}

fn process_packet(buffer: &mut [u8]) -> &[u8] {
    // Simulate receiving data
    let received = 100;  // Pretend we got 100 bytes
    buffer[..received].copy_from_slice(&[0xAA; 100]);

    &buffer[..received]  // Return slice of valid data only
}
```

This prevents:
- Buffer overflows (slice is bounds-checked)
- Use-after-free (borrow checker ensures validity)
- Memory leaks (buffer dropped when main ends)

---

## Try It Yourself

### Exercise 1: Fix the Ownership Error

```rust
fn main() {
    let s = String::from("hello");
    let s2 = s;
    println!("{}", s);  // Fix this!
}
```

### Exercise 2: Implement a Function with Borrowing

Write a function `count_vowels` that takes a `&str` and returns the count of vowels.

### Exercise 3: Slice Practice

```rust
fn main() {
    let data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

    // Get a slice of elements 3-7 (indices 2-6)
    // Calculate and print their sum
}
```

---

## Common Patterns

### Taking Ownership When Needed

```rust
// Takes ownership - use when you need to store the value
fn store_in_database(data: String) {
    // ...
}

// Borrows - use when you only need to read
fn validate(data: &str) -> bool {
    // ...
}

// Mutable borrow - use when you need to modify
fn sanitize(data: &mut String) {
    // ...
}
```

### The Clone Escape Hatch

When you need a copy of heap data:

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = s1.clone();  // Deep copy

    println!("{} {}", s1, s2);  // Both valid
}
```

**Warning:** `clone()` can be expensive for large data!

---

## Key Takeaways

1. **Each value has exactly one owner**
2. **When the owner goes out of scope, value is dropped**
3. **Move by default** for heap data, **copy** for stack data
4. **References borrow** without taking ownership
5. **One mutable ref OR many immutable refs** (never both)
6. **The borrow checker prevents bugs** at compile time
7. **Use slices** to reference portions of data

---

## Quick Reference

```rust
// Ownership
let s1 = String::from("hello");
let s2 = s1;          // Move
let s3 = s2.clone();  // Clone (deep copy)

// Borrowing
let r1 = &s3;         // Immutable reference
let r2 = &s3;         // Another immutable ref (OK)

let mut s4 = String::from("hello");
let r3 = &mut s4;     // Mutable reference

// Slices
let slice = &s3[0..5];  // String slice
let arr_slice = &[1,2,3][..2];  // Array slice
```

---

[← Previous: Functions](./03_Functions.md) | [Next: Structs & Enums →](./05_Structs_Enums.md)
