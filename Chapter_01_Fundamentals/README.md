# Chapter 01: Rust Fundamentals for Security

## Welcome to Rust!

This chapter will take you from zero to confident Rust programmer. We'll cover everything you need to know to start building security tools, with hands-on examples and exercises throughout.

---

## Why Rust for Security?

| Feature | Benefit for Security Tools |
|---------|---------------------------|
| Memory Safety | No buffer overflows, use-after-free, or null pointer bugs |
| Zero-Cost Abstractions | High-level code with C-like performance |
| No Garbage Collector | Predictable performance, no runtime overhead |
| Single Binary | Easy deployment, no dependencies |
| Cross-Platform | Build once, run on Linux, Windows, macOS |
| Strong Type System | Catch bugs at compile time, not runtime |

---

## Chapter Contents

| Lesson | Topic | Time | Difficulty |
|--------|-------|------|------------|
| [01_Getting_Started](./01_Getting_Started.md) | Installation & First Program | 30 min | Beginner |
| [02_Variables_Types](./02_Variables_Types.md) | Variables, Data Types, Constants | 45 min | Beginner |
| [03_Control_Flow](./03_Control_Flow.md) | If/Else, Match, Loops | 45 min | Beginner |
| [04_Ownership](./04_Ownership.md) | Ownership & Borrowing | 60 min | Beginner |
| [05_Structs_Enums](./05_Structs_Enums.md) | Custom Data Types & Methods | 45 min | Beginner |
| [06_Error_Handling](./06_Error_Handling.md) | Result, Option, Error Types | 45 min | Beginner |
| [07_Collections](./07_Collections.md) | Vec, String, HashMap | 45 min | Beginner |
| [08_Traits](./08_Traits.md) | Traits & Generics | 60 min | Intermediate |

---

## Learning Objectives

By the end of this chapter, you will be able to:

- Install Rust and set up a development environment
- Understand ownership, borrowing, and lifetimes
- Write functions with proper error handling
- Create custom types with structs and enums
- Use collections like Vec and HashMap
- Organize code with modules and crates
- Write and run tests for your code

---

## Prerequisites

- Basic programming experience in any language
- Command line familiarity
- A computer with Linux, Windows, or macOS

---

## How to Use This Chapter

### For Absolute Beginners

1. Start with Lesson 01 and work through sequentially
2. Type out all code examples yourself (don't copy-paste!)
3. Complete all exercises before moving on
4. Use `cargo check` frequently to catch errors early

### For Experienced Programmers

1. Skim Lessons 01-03 for Rust-specific syntax
2. Focus on Lessons 04 (Ownership) and 06 (Error Handling)
3. Complete the chapter project at the end

### Practice Makes Perfect

Each lesson includes:
- **Concepts** - Theory and explanations
- **Examples** - Working code to study
- **Try It** - Small exercises to reinforce learning
- **Challenges** - Harder problems to solve

---

## Quick Setup

```bash
# Install Rust (Linux/macOS)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Rust (Windows)
# Download from https://rustup.rs

# Verify installation
rustc --version
cargo --version

# Create your first project
cargo new hello_rust
cd hello_rust
cargo run
```

---

## Chapter Project: Hash Calculator

By the end of this chapter, you'll build a command-line hash calculator:

```
$ hashcalc md5 "Hello, World!"
MD5: 65a8e27d8879283831b664bd8b7f0ad4

$ hashcalc sha256 -f myfile.txt
SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

$ hashcalc --help
Hash Calculator v1.0

Usage: hashcalc <ALGORITHM> [OPTIONS] <INPUT>

Algorithms:
  md5       MD5 hash (128-bit)
  sha1      SHA-1 hash (160-bit)
  sha256    SHA-256 hash (256-bit)

Options:
  -f, --file    Input is a file path
  -h, --help    Show this help
```

This project will teach you:
- CLI argument parsing
- File I/O
- External crate usage
- Error handling
- Building release binaries

---

## Resources

### Official Documentation
- [The Rust Book](https://doc.rust-lang.org/book/) - Free online book
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/) - Learn by doing
- [Standard Library Docs](https://doc.rust-lang.org/std/) - API reference

### Helpful Tools
- [Rust Playground](https://play.rust-lang.org/) - Test code in browser
- [Clippy](https://github.com/rust-lang/rust-clippy) - Lint your code
- [rustfmt](https://github.com/rust-lang/rustfmt) - Format your code

### Community
- [Rust Users Forum](https://users.rust-lang.org/)
- [r/rust](https://www.reddit.com/r/rust/)
- [Rust Discord](https://discord.gg/rust-lang)

---

## Checkpoint Quiz

Before starting, test your current knowledge:

1. What is Rust's main feature for memory safety?
2. What command creates a new Rust project?
3. What file extension do Rust source files use?

<details>
<summary>Answers</summary>

1. Ownership system (no garbage collector, compile-time checks)
2. `cargo new project_name`
3. `.rs`

</details>

---

[← Back to Main](../README.md) | [Start Learning: Lesson 01 →](./01_Getting_Started.md)
