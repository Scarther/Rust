# Lesson 01: Getting Started with Rust

## Overview

In this lesson, you'll install Rust, understand its toolchain, and write your first program.

**Time:** 30 minutes
**Difficulty:** Beginner

---

## What You'll Learn

- How to install the Rust toolchain
- Understanding cargo, rustc, and rustup
- Creating and running your first project
- Basic project structure

---

## Installing Rust

### Linux & macOS

Open a terminal and run:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts and select option 1 (default installation).

After installation, restart your terminal or run:

```bash
source $HOME/.cargo/env
```

### Windows

1. Download the installer from [rustup.rs](https://rustup.rs)
2. Run the `.exe` file
3. Follow the installation prompts
4. You may need to install Visual Studio Build Tools

### Verify Installation

```bash
$ rustc --version
rustc 1.75.0 (82e1608df 2023-12-21)

$ cargo --version
cargo 1.75.0 (1d8b05cdd 2023-11-20)

$ rustup --version
rustup 1.26.0 (2023-11-14)
```

---

## Understanding the Rust Toolchain

Rust comes with three main tools:

| Tool | Purpose | Example |
|------|---------|---------|
| `rustc` | The Rust compiler | `rustc main.rs` |
| `cargo` | Package manager & build tool | `cargo build` |
| `rustup` | Toolchain manager | `rustup update` |

### rustup - Toolchain Manager

```bash
# Update Rust to latest version
rustup update

# Show installed toolchains
rustup show

# Add a compilation target
rustup target add x86_64-unknown-linux-musl

# Install a component
rustup component add clippy
```

### cargo - Your Daily Driver

Cargo is what you'll use most. It handles:
- Creating projects
- Building code
- Running programs
- Managing dependencies
- Running tests
- Publishing packages

---

## Your First Project

### Creating a Project

```bash
# Create a new project
cargo new hello_security

# Navigate into it
cd hello_security

# See what was created
ls -la
```

### Project Structure

```
hello_security/
├── Cargo.toml    # Project configuration (like package.json)
├── .git/         # Git repository (created automatically)
├── .gitignore    # Git ignore file
└── src/
    └── main.rs   # Your source code
```

### Cargo.toml Explained

```toml
[package]
name = "hello_security"      # Project name
version = "0.1.0"            # Version number
edition = "2021"             # Rust edition (language version)

[dependencies]               # External libraries go here
# We'll add dependencies later
```

### main.rs Explained

```rust
fn main() {
    println!("Hello, world!");
}
```

Let's break this down:

| Part | Meaning |
|------|---------|
| `fn` | Keyword to define a function |
| `main` | Function name (entry point of program) |
| `()` | No parameters |
| `{ }` | Function body |
| `println!` | Macro to print text (note the `!`) |
| `"Hello, world!"` | String literal |
| `;` | Statement terminator |

---

## Running Your Program

### Method 1: Build and Run Separately

```bash
# Compile the program
cargo build

# Run the compiled binary
./target/debug/hello_security
```

### Method 2: Build and Run Together (Recommended)

```bash
cargo run
```

Output:
```
   Compiling hello_security v0.1.0 (/path/to/hello_security)
    Finished dev [unoptimized + debuginfo] target(s) in 0.50s
     Running `target/debug/hello_security`
Hello, world!
```

### Method 3: Check Without Building

```bash
# Just check for errors (faster)
cargo check
```

---

## Build Modes

### Debug Mode (Default)

```bash
cargo build
# Binary at: target/debug/hello_security
```

- Fast compilation
- Includes debug symbols
- No optimizations
- Larger binary size

### Release Mode

```bash
cargo build --release
# Binary at: target/release/hello_security
```

- Slower compilation
- Optimized code
- Smaller, faster binary
- Use for final builds

---

## Let's Modify the Code

Open `src/main.rs` in your editor and change it:

```rust
fn main() {
    // This is a comment
    println!("Hello, Security Researcher!");
    println!("Welcome to Rust!");

    // Print multiple lines
    println!("Today we learn:");
    println!("  1. How Rust works");
    println!("  2. Why it's great for security");
    println!("  3. How to build tools");
}
```

Run it:

```bash
cargo run
```

Output:
```
Hello, Security Researcher!
Welcome to Rust!
Today we learn:
  1. How Rust works
  2. Why it's great for security
  3. How to build tools
```

---

## Useful Cargo Commands

| Command | Purpose |
|---------|---------|
| `cargo new name` | Create new project |
| `cargo init` | Initialize in current directory |
| `cargo build` | Compile the project |
| `cargo run` | Build and run |
| `cargo check` | Check for errors (no build) |
| `cargo test` | Run tests |
| `cargo doc --open` | Generate and view docs |
| `cargo clean` | Remove build artifacts |
| `cargo update` | Update dependencies |
| `cargo fmt` | Format code |
| `cargo clippy` | Lint code |

---

## Try It Yourself

### Exercise 1: Personalize Your Program

Modify `main.rs` to print:
- Your name
- Why you want to learn Rust
- What security tools you want to build

### Exercise 2: Explore Cargo

Run these commands and observe the output:
```bash
cargo build --release
ls -lh target/debug/hello_security
ls -lh target/release/hello_security
```

What's the size difference between debug and release builds?

### Exercise 3: Create a Second Project

```bash
cd ..
cargo new my_scanner
cd my_scanner
cargo run
```

---

## Common Errors and Fixes

### Error: Command not found

```
cargo: command not found
```

**Fix:** Restart your terminal or run:
```bash
source $HOME/.cargo/env
```

### Error: Missing semicolon

```rust
fn main() {
    println!("Hello")  // Missing semicolon!
}
```

```
error: expected `;`, found `}`
```

**Fix:** Add the semicolon:
```rust
println!("Hello");
```

### Error: Mismatched quotes

```rust
println!("Hello, world!');  // Mixed quotes
```

**Fix:** Use matching quotes:
```rust
println!("Hello, world!");
```

---

## Key Takeaways

1. **Rust is installed via rustup** - Keep it updated with `rustup update`
2. **Cargo is your best friend** - Use it for everything
3. **Projects have structure** - `Cargo.toml` + `src/` directory
4. **Two build modes** - Debug (fast compile) and Release (optimized)
5. **Use `cargo check`** - Faster than full build for error checking

---

## What's Next?

In the next lesson, we'll learn about variables, data types, and how Rust handles data.

---

## Quick Reference

```bash
# Installation
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Create project
cargo new project_name

# Build and run
cargo run

# Build for release
cargo build --release

# Check for errors
cargo check
```

---

[← Back to Chapter](./README.md) | [Next: Variables & Types →](./02_Variables_Types.md)
