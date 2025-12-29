# B01: Hello Security World

## Overview

| Property | Value |
|----------|-------|
| **ID** | B01 |
| **Name** | Hello Security World |
| **Difficulty** | Basic |
| **Time** | 15 minutes |
| **Prerequisites** | Rust installed |

## What You'll Learn

1. Rust project structure
2. The `main()` function
3. `println!` macro and formatting
4. Basic variables
5. String literals vs String type

---

## The Code

```rust
// src/main.rs

fn main() {
    // ═══════════════════════════════════════════════════════════════
    // ASCII Art Banner
    // ═══════════════════════════════════════════════════════════════
    // Using raw string literal (r#"..."#) to avoid escaping
    let banner = r#"
    ╔═══════════════════════════════════════════╗
    ║     RUST SECURITY TRAINING - B01          ║
    ║     Hello Security World                  ║
    ╚═══════════════════════════════════════════╝
    "#;

    println!("{}", banner);

    // ═══════════════════════════════════════════════════════════════
    // Variables and Types
    // ═══════════════════════════════════════════════════════════════

    // &str - String slice (borrowed, fixed length)
    let tool_name = "RustRecon";

    // String - Owned, growable string
    let mut version = String::from("1.0");
    version.push_str(".0");  // Can modify because it's mut + owned

    // Multiple types
    let author = "Security Student";
    let year: u16 = 2025;
    let is_production = false;

    // ═══════════════════════════════════════════════════════════════
    // Formatted Output
    // ═══════════════════════════════════════════════════════════════

    // Basic formatting
    println!("[*] Tool: {} v{}", tool_name, version);
    println!("[*] Author: {}", author);
    println!("[*] Year: {}", year);
    println!("[*] Production: {}", is_production);
    println!();

    // ═══════════════════════════════════════════════════════════════
    // Security-Style Output Conventions
    // ═══════════════════════════════════════════════════════════════

    // Common log level prefixes in security tools
    println!("[+] Success - Action completed successfully");
    println!("[-] Failure - Action failed");
    println!("[*] Info - General information");
    println!("[!] Warning - Attention required");
    println!("[?] Question - Uncertain status");
    println!("[>] Input - Awaiting input");
    println!();

    // ═══════════════════════════════════════════════════════════════
    // Report-Style Output
    // ═══════════════════════════════════════════════════════════════

    let target = "192.168.1.1";
    let ports_found = 3;
    let scan_time = 2.45;

    // Box drawing characters for reports
    println!("═══════════════════════════════════════════");
    println!(" SCAN RESULTS");
    println!("═══════════════════════════════════════════");
    println!(" Target:      {}", target);
    println!(" Open Ports:  {}", ports_found);
    println!(" Scan Time:   {:.2}s", scan_time);  // {:.2} = 2 decimal places
    println!("═══════════════════════════════════════════");
    println!();

    // ═══════════════════════════════════════════════════════════════
    // Advanced Formatting
    // ═══════════════════════════════════════════════════════════════

    // Width and alignment
    println!("{:<15} {:>10}", "PORT", "STATUS");  // < left, > right
    println!("{:-<15} {:->10}", "", "");          // Fill with dashes
    println!("{:<15} {:>10}", "22", "OPEN");
    println!("{:<15} {:>10}", "80", "OPEN");
    println!("{:<15} {:>10}", "443", "OPEN");
    println!();

    // Padding with zeros
    let port: u16 = 22;
    println!("Port with padding: {:05}", port);  // Output: 00022

    // Hexadecimal output (common in security)
    let byte: u8 = 255;
    println!("Decimal: {}, Hex: {:#x}, Binary: {:08b}", byte, byte, byte);

    // ═══════════════════════════════════════════════════════════════
    // Exit Message
    // ═══════════════════════════════════════════════════════════════

    println!();
    println!("[*] B01 Complete! Proceed to B02: CLI Arguments");
}
```

---

## Line-by-Line Breakdown

### The Banner (Lines 7-13)

```rust
let banner = r#"
    ╔═══════════════════════════════════════════╗
    ...
"#;
```

**What it does**: Creates a multi-line string with ASCII art.

**Key concepts**:
- `r#"..."#` is a **raw string literal** - no escape processing
- Box-drawing characters (╔, ═, ╗) create professional-looking output
- Common in security tools for branding and clarity

**Why it matters for security**:
- Tool banners can be signatures in memory
- Consistent output helps with log parsing
- Professional appearance builds trust

---

### Variables (Lines 22-30)

```rust
let tool_name = "RustRecon";        // &str - borrowed
let mut version = String::from("1.0");  // String - owned
version.push_str(".0");              // Modifying owned string
```

**Key concepts**:
- `let` declares an immutable variable
- `let mut` allows mutation
- `&str` vs `String`:
  - `&str`: Fixed-size, borrowed reference to string data
  - `String`: Heap-allocated, owned, growable

```
Stack                Heap
┌─────────────┐
│ tool_name   │──────► "RustRecon" (read-only memory)
└─────────────┘

┌─────────────┐      ┌───────────────┐
│ version     │─────►│ "1.0.0"       │ (can grow)
│ ptr, len,   │      └───────────────┘
│ capacity    │
└─────────────┘
```

---

### Formatting Specifiers

| Specifier | Meaning | Example | Output |
|-----------|---------|---------|--------|
| `{}` | Display format | `println!("{}", 42)` | `42` |
| `{:?}` | Debug format | `println!("{:?}", vec![1,2])` | `[1, 2]` |
| `{:#?}` | Pretty debug | `println!("{:#?}", obj)` | Multi-line |
| `{:.2}` | 2 decimal places | `println!("{:.2}", 3.14159)` | `3.14` |
| `{:05}` | Pad with zeros | `println!("{:05}", 42)` | `00042` |
| `{:<10}` | Left align, 10 chars | `println!("{:<10}", "hi")` | `"hi        "` |
| `{:>10}` | Right align, 10 chars | `println!("{:>10}", "hi")` | `"        hi"` |
| `{:x}` | Lowercase hex | `println!("{:x}", 255)` | `ff` |
| `{:#x}` | Hex with prefix | `println!("{:#x}", 255)` | `0xff` |
| `{:b}` | Binary | `println!("{:b}", 5)` | `101` |
| `{:08b}` | Binary, 8 digits | `println!("{:08b}", 5)` | `00000101` |

---

## Red Team Perspective

### Why This Matters

1. **Output Consistency**: Predictable output enables automation
2. **Log Levels**: Help operators quickly identify status
3. **Formatting**: Makes data extraction easier for scripts
4. **Signatures**: Banners become IOCs in memory

### Operational Considerations

```rust
// OPSEC: Consider making output configurable
// In real tools, you might want:
// - Quiet mode (-q) for scripting
// - JSON output for automation
// - No banner for stealth

let quiet_mode = false;
if !quiet_mode {
    println!("{}", banner);
}
```

---

## Blue Team Perspective

### Detection Opportunities

1. **String Signatures**: Banner text can be detected in:
   - Process memory
   - Network traffic (if transmitted)
   - Disk (binary strings)

2. **Output Patterns**: Log aggregation can detect:
   - Consistent formatting patterns
   - Known tool signatures
   - Unusual console output speed

### YARA Rule Example

```yara
rule Rust_Security_Tool_B01
{
    meta:
        description = "Detects B01 training tool"
        author = "Blue Team"

    strings:
        $banner1 = "RUST SECURITY TRAINING"
        $banner2 = "Hello Security World"
        $prefix1 = "[+] Success"
        $prefix2 = "[*] Info"

    condition:
        2 of them
}
```

---

## Exercises

### Exercise 1: Custom Banner
Create your own ASCII art banner using a generator like:
- https://patorjk.com/software/taag/

### Exercise 2: Color Output
Add the `colored` crate and make output colorful:

```rust
use colored::*;

println!("{}", "[+] Success".green());
println!("{}", "[-] Failure".red());
println!("{}", "[!] Warning".yellow());
```

### Exercise 3: Timestamp
Add a timestamp to the output:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

println!("[{}] Starting scan...", timestamp());
```

### Exercise 4: Environment-Based Output
Modify output based on environment variable:

```rust
use std::env;

let verbose = env::var("VERBOSE").is_ok();
if verbose {
    println!("[DEBUG] Extra information here");
}
```

---

## Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `cannot borrow as mutable` | Trying to modify immutable variable | Add `mut` to declaration |
| `expected &str, found String` | Type mismatch | Use `&my_string` or `.as_str()` |
| `use of undeclared crate` | Missing dependency | Add to `Cargo.toml` |

---

## Summary

**Concepts Mastered**:
- [x] Rust project structure
- [x] `fn main()` entry point
- [x] `println!` macro
- [x] Variable declarations (`let`, `let mut`)
- [x] String types (`&str` vs `String`)
- [x] Format specifiers
- [x] Security output conventions

**Next Project**: [B02: Command-Line Arguments](../B02_CLI_Args/README.md)

---

[← Back to Basic Level](../README.md) | [Next: B02 CLI Args →](../B02_CLI_Args/README.md)
