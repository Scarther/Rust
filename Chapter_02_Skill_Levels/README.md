# Chapter 02: Skill Levels

## Overview

Progressive learning path from beginner to expert. Each level builds on the previous, with hands-on exercises, challenges, and real projects.

---

## Skill Level Structure

```
Level 01: Basic         → Learn Rust fundamentals
    ↓
Level 02: Intermediate  → Build networking tools
    ↓
Level 03: Advanced      → Create security applications
    ↓
Level 04: Expert        → Develop production tools
```

---

## Level Overview

| Level | Focus | Prerequisites | Projects |
|-------|-------|---------------|----------|
| [01_Basic](./01_Basic/) | Rust syntax, CLI tools | None | Hash calculator, File reader |
| [02_Intermediate](./02_Intermediate/) | Networking, async | Basic | Port scanner, Web crawler |
| [03_Advanced](./03_Advanced/) | Security tools, parsing | Intermediate | Log analyzer, Binary parser |
| [04_Expert](./04_Expert/) | Production systems | Advanced | Detection engine, Full toolkit |

---

## How to Use This Chapter

### Step 1: Assess Your Level

Take the [Chapter 01 Quiz](../Assessments/Chapter_01_Fundamentals_Quiz.md):
- **Score 90%+** → Start at Intermediate
- **Score 70-89%** → Start at Basic, move quickly
- **Score below 70%** → Study Chapter 01 first

### Step 2: Work Through Each Level

Each level contains:
- **Concepts** - New techniques to learn
- **Examples** - Working code to study
- **Exercises** - Practice problems
- **Challenges** - Harder problems
- **Project** - Capstone to build

### Step 3: Don't Skip!

Each level assumes knowledge from previous levels. If you're struggling, go back and review.

---

## Learning Path by Goal

### "I want to build security tools"

```
Basic (1 week)
  → Learn Rust syntax
  → Build CLI tools

Intermediate (2 weeks)
  → Learn networking
  → Build scanners

Advanced (2 weeks)
  → Learn parsing
  → Build analyzers

Expert (ongoing)
  → Build production tools
  → Contribute to projects
```

### "I want to understand Rust for code review"

```
Basic (3 days)
  → Focus on syntax
  → Understand ownership

Intermediate (1 week)
  → Learn error patterns
  → Study async code
```

### "I want to automate security tasks"

```
Basic (1 week)
  → CLI tool building
  → File operations

Intermediate (1 week)
  → HTTP requests
  → Data parsing
```

---

## Progress Tracking

### Basic Level Checklist
- [ ] Variables and types
- [ ] Functions and control flow
- [ ] Ownership basics
- [ ] Structs and enums
- [ ] Error handling with Result
- [ ] File I/O
- [ ] CLI argument parsing
- [ ] Basic project complete

### Intermediate Level Checklist
- [ ] TCP/UDP networking
- [ ] HTTP clients
- [ ] Async/await with Tokio
- [ ] JSON parsing
- [ ] Multi-threading basics
- [ ] External crates
- [ ] Port scanner project complete

### Advanced Level Checklist
- [ ] Binary file parsing
- [ ] Regular expressions
- [ ] Custom error types
- [ ] Trait implementations
- [ ] Concurrency patterns
- [ ] Cross-compilation
- [ ] Log analyzer project complete

### Expert Level Checklist
- [ ] Production architecture
- [ ] Performance optimization
- [ ] Plugin systems
- [ ] Memory safety patterns
- [ ] Full toolkit project complete

---

## Tips for Success

### 1. Type Everything

Don't copy-paste code. Type it out yourself. You'll learn better and catch mistakes.

### 2. Make Mistakes

Rust's compiler is strict but helpful. Read error messages carefully - they teach you.

### 3. Build Projects

Don't just read - build things! Modify examples. Break things. Fix them.

### 4. Use the Tools

```bash
cargo check   # Fast error checking
cargo clippy  # Get suggestions
cargo fmt     # Format code
cargo doc     # Read documentation
```

### 5. Ask for Help

- Read the compiler message (it's usually right!)
- Search the error code (e.g., "rust E0382")
- Ask on forums with your code and error

---

## Quick Navigation

| I want to... | Go to... |
|--------------|----------|
| Learn Rust basics | [01_Basic](./01_Basic/) |
| Build a port scanner | [02_Intermediate](./02_Intermediate/) |
| Parse binary files | [03_Advanced](./03_Advanced/) |
| Build production tools | [04_Expert](./04_Expert/) |

---

[← Back to Main](../README.md) | [Start: Basic Level →](./01_Basic/)
