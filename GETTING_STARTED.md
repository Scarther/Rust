# Getting Started with Rust Security Bible

## Welcome, Future Rust Security Developer!

This guide will help you get up and running quickly, no matter your background. Whether you're a complete beginner or an experienced developer, you'll find your path here.

---

## Quick Start (5 Minutes)

### 1. Install Rust

**Linux/macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Windows:**
Download and run the installer from [rustup.rs](https://rustup.rs)

### 2. Verify Installation

```bash
rustc --version
cargo --version
```

### 3. Create Your First Project

```bash
cargo new hello_security
cd hello_security
cargo run
```

You should see: `Hello, world!`

**Congratulations!** You've just run your first Rust program!

---

## Choose Your Learning Path

### Path A: Complete Beginner (No Programming Experience)

**Estimated Time:** 4-6 weeks

1. **Week 1-2:** [Chapter 01: Fundamentals](./Chapter_01_Fundamentals/)
   - Start with Lesson 01 and work through each lesson
   - Complete all exercises before moving on
   - Don't skip the ownership lesson - it's crucial!

2. **Week 3:** [Skill Level: Basic](./Chapter_02_Skill_Levels/01_Basic/)
   - Practice basic Rust syntax
   - Complete the challenges

3. **Week 4:** Your First Security Tool
   - Build the [Hash Calculator Project](./Chapter_01_Fundamentals/README.md#chapter-project-hash-calculator)
   - Follow the step-by-step guide

4. **Week 5-6:** [Intermediate Skills](./Chapter_02_Skill_Levels/02_Intermediate/)
   - Learn about networking
   - Build your first port scanner

**Resources for Beginners:**
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/) - Learn by doing
- [Rustlings](https://github.com/rust-lang/rustlings) - Small exercises

---

### Path B: Experienced Programmer (New to Rust)

**Estimated Time:** 2-3 weeks

1. **Days 1-3:** Quick Fundamentals Review
   - Skim [Chapter 01](./Chapter_01_Fundamentals/) - focus on:
     - [Ownership](./Chapter_01_Fundamentals/04_Ownership.md) (most important!)
     - [Error Handling](./Chapter_01_Fundamentals/06_Error_Handling.md)
     - [Traits](./Chapter_01_Fundamentals/09_Traits.md)

2. **Days 4-7:** [Take the Assessment](./Assessments/Chapter_01_Fundamentals_Quiz.md)
   - Score 70%+ → Move to security content
   - Score below 70% → Review weak areas

3. **Week 2:** Jump into Security
   - [Red Team Rust](./Chapter_03_Red_Team/)
   - [Blue Team Rust](./Chapter_04_Blue_Team/)

4. **Week 3:** Build Real Tools
   - [IOC Scanner Project](./Projects/IOCScanner/)
   - [Network Scanner Template](./Templates/network_scanner/)

**Key Differences from Other Languages:**
| Concept | Other Languages | Rust |
|---------|-----------------|------|
| Memory | GC or manual | Ownership |
| Null | `null`/`None` | `Option<T>` |
| Errors | Exceptions | `Result<T, E>` |
| Mutation | Default mutable | Default immutable |

---

### Path C: Security Professional (Learn Rust for Tools)

**Estimated Time:** 1-2 weeks

1. **Day 1:** Environment Setup
   - Install Rust
   - Set up the [Lab Environment](./Lab_Environment/)
   - Run `docker-compose up -d`

2. **Days 2-3:** Tool Templates
   - Clone a [Template](./Templates/)
   - Understand the structure
   - Build your first scanner

3. **Days 4-5:** Security-Specific Content
   - [Quick Reference: Security Cheatsheet](./Quick_Reference/Rust_Security_Cheatsheet.md)
   - [Networking Patterns](./Quick_Reference/Async_Tokio_Cheatsheet.md)

4. **Week 2:** Build Custom Tools
   - Customize templates for your needs
   - Complete [CTF Challenges](./CTF_Challenges/)
   - Work through [Case Studies](./Case_Studies/)

**Why Rust for Security Tools:**
- Single binary deployment (no dependencies)
- Memory-safe (no buffer overflows)
- Fast as C/C++
- Cross-platform compilation
- Great for offensive and defensive tools

---

## Setting Up Your Environment

### Recommended Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| **VS Code** | Editor | [Download](https://code.visualstudio.com/) |
| **rust-analyzer** | IDE support | VS Code extension |
| **CodeLLDB** | Debugging | VS Code extension |
| **Docker** | Lab environment | [Install Docker](https://docs.docker.com/get-docker/) |

### VS Code Setup

1. Install VS Code
2. Install extensions:
   - rust-analyzer
   - CodeLLDB
   - Even Better TOML
   - Error Lens

3. Create `settings.json`:
```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.inlayHints.enable": true,
    "editor.formatOnSave": true
}
```

### Terminal Setup (Optional)

For a better terminal experience:
```bash
# Add to ~/.bashrc or ~/.zshrc
alias cb="cargo build"
alias cr="cargo run"
alias ct="cargo test"
alias cc="cargo check"
alias cf="cargo fmt"
alias ccl="cargo clippy"
```

---

## The Lab Environment

Our Docker lab provides safe targets for testing:

```bash
cd Lab_Environment
docker-compose up -d
```

### Available Targets

| Service | IP | Ports | Use Case |
|---------|----|----- -|----------|
| rust-dev | 172.30.0.10 | SSH:2222 | Development |
| target-linux | 172.30.0.20 | SSH:2223 | Practice target |
| vuln-web | 172.30.0.30 | HTTP:8082 | Web testing |
| services | 172.30.0.40 | Multiple | Port scanning |
| database | 172.30.0.50 | 5432 | PostgreSQL |
| redis | 172.30.0.51 | 6379 | Redis |

### First Lab Exercise

```bash
# Connect to dev container
ssh root@localhost -p 2222
# Password: rustlab

# Inside container
cd /workspace
cargo new my_first_scanner
cd my_first_scanner
cargo run
```

---

## Your First Security Tool

Let's build a simple port checker:

### Step 1: Create Project

```bash
cargo new port_check
cd port_check
```

### Step 2: Write the Code

Edit `src/main.rs`:

```rust
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let target = "127.0.0.1";
    let ports = [22, 80, 443, 8080];

    println!("Scanning {}...\n", target);

    for port in ports {
        let address = format!("{}:{}", target, port);

        match TcpStream::connect_timeout(
            &address.parse().unwrap(),
            Duration::from_millis(500)
        ) {
            Ok(_) => println!("  Port {}: OPEN", port),
            Err(_) => println!("  Port {}: closed", port),
        }
    }

    println!("\nScan complete!");
}
```

### Step 3: Run It

```bash
cargo run
```

### Step 4: Enhance It

Try these improvements:
1. Accept target from command line
2. Add more ports
3. Make it concurrent

See [Templates/network_scanner](./Templates/network_scanner/) for a complete example.

---

## Learning Milestones

Track your progress through these milestones:

### Beginner Milestones
- [ ] Install Rust and run first program
- [ ] Understand variables and types
- [ ] Write functions with parameters
- [ ] Grasp ownership and borrowing basics
- [ ] Use structs and enums
- [ ] Handle errors with Result and Option
- [ ] Complete Chapter 01 Quiz with 70%+

### Intermediate Milestones
- [ ] Build a working port scanner
- [ ] Make HTTP requests with reqwest
- [ ] Parse JSON and config files
- [ ] Write async code with Tokio
- [ ] Create a CLI tool with clap
- [ ] Complete an Intermediate CTF challenge

### Advanced Milestones
- [ ] Build a multi-threaded scanner
- [ ] Parse binary formats (PE/ELF)
- [ ] Implement custom protocols
- [ ] Cross-compile for multiple platforms
- [ ] Create production-ready tooling
- [ ] Complete an Advanced CTF challenge

### Expert Milestones
- [ ] Build detection/analysis engines
- [ ] Contribute to security projects
- [ ] Create novel security tools
- [ ] Optimize for performance
- [ ] Complete all Expert CTF challenges

---

## Common Beginner Mistakes

### Mistake 1: Fighting the Borrow Checker

```rust
// Wrong - trying to use value after move
let s = String::from("hello");
let s2 = s;
println!("{}", s);  // Error!

// Right - clone or borrow
let s = String::from("hello");
let s2 = s.clone();
println!("{}", s);  // Works!

// Or use references
let s = String::from("hello");
let s2 = &s;
println!("{}", s);  // Works!
```

### Mistake 2: Using unwrap() Everywhere

```rust
// Risky - panics on error
let file = File::open("config.txt").unwrap();

// Better - handle errors
let file = match File::open("config.txt") {
    Ok(f) => f,
    Err(e) => {
        eprintln!("Error: {}", e);
        return;
    }
};

// Best for applications - use ?
let file = File::open("config.txt")?;
```

### Mistake 3: Ignoring Compiler Messages

The Rust compiler gives excellent error messages. Read them carefully!

```
error[E0382]: borrow of moved value: `s`
 --> src/main.rs:4:20
  |
2 |     let s = String::from("hello");
  |         - move occurs because `s` has type `String`
3 |     let s2 = s;
  |              - value moved here
4 |     println!("{}", s);
  |                    ^ value borrowed here after move
  |
help: consider cloning the value
  |
3 |     let s2 = s.clone();
  |               ++++++++
```

---

## Getting Help

### When You're Stuck

1. **Read the compiler message** - It usually tells you what's wrong
2. **Check the docs** - `cargo doc --open`
3. **Search the error** - Copy/paste the error code (e.g., E0382)
4. **Ask for help:**
   - [Rust Users Forum](https://users.rust-lang.org/)
   - [r/rust](https://reddit.com/r/rust)
   - [Rust Discord](https://discord.gg/rust-lang)

### Useful Commands

```bash
# Check for errors without building
cargo check

# Get helpful suggestions
cargo clippy

# Format your code
cargo fmt

# Open documentation
cargo doc --open

# Run tests
cargo test

# See expanded macros
cargo expand
```

---

## Next Steps

Based on your path:

**Beginners:** Start [Chapter 01, Lesson 01](./Chapter_01_Fundamentals/01_Getting_Started.md)

**Experienced Devs:** Take the [Chapter 01 Quiz](./Assessments/Chapter_01_Fundamentals_Quiz.md)

**Security Pros:** Set up the [Lab Environment](./Lab_Environment/) and grab a [Template](./Templates/)

---

## Quick Reference Card

```bash
# Create project
cargo new project_name

# Build
cargo build           # Debug
cargo build --release # Optimized

# Run
cargo run

# Check for errors
cargo check

# Run tests
cargo test

# Format code
cargo fmt

# Lint code
cargo clippy

# Update dependencies
cargo update
```

---

Welcome to the Rust security community! Let's build something amazing together.

[→ Start Learning](./Chapter_01_Fundamentals/README.md)
