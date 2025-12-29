# Contributing to Rust Security Bible

Thank you for your interest in contributing! This guide will help you get started.

---

## Code of Conduct

- Be respectful and constructive
- Focus on education and ethical use
- No malicious code or actual exploits
- All contributions must be for defensive/educational purposes

---

## How to Contribute

### Types of Contributions

| Type | Description |
|------|-------------|
| Bug Fixes | Fix errors in code examples |
| Documentation | Improve explanations, add examples |
| New Content | Add chapters, exercises, case studies |
| Tool Examples | Add working Rust security tool examples |
| Translations | Translate content to other languages |

### Getting Started

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/rust-security-bible
   cd rust-security-bible
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**

4. **Test Your Changes**
   ```bash
   # For Rust code examples
   cargo check
   cargo test
   cargo clippy

   # For markdown
   # Use a markdown linter
   ```

5. **Submit a Pull Request**

---

## Content Guidelines

### Code Examples

```rust
// DO: Include complete, working examples
use std::net::TcpStream;

fn connect_to_server(addr: &str) -> std::io::Result<TcpStream> {
    TcpStream::connect(addr)
}

// DON'T: Incomplete snippets without context
// fn foo() { ... }
```

### Documentation Standards

- Use clear, concise language
- Include practical examples
- Explain the "why" not just the "what"
- Add MITRE ATT&CK references where applicable
- Include security considerations

### File Naming

| Type | Convention | Example |
|------|------------|---------|
| Chapters | `Chapter_XX_Topic_Name/` | `Chapter_01_Fundamentals/` |
| Lessons | `NN_Lesson_Name.md` | `01_Ownership_Basics.md` |
| Projects | `ProjectName/` | `PortScanner/` |
| Case Studies | `CSNN_Title.md` | `CS01_Compromised_Server.md` |

---

## Rust Style Guide

### Formatting

```bash
# Always format with rustfmt
cargo fmt

# Check with clippy
cargo clippy -- -D warnings
```

### Conventions

```rust
// Use descriptive names
fn scan_port_range(target: &str, start: u16, end: u16) -> Vec<u16>

// Handle errors properly
fn read_file(path: &Path) -> Result<String, io::Error>

// Document public items
/// Scans the specified port range on the target host.
///
/// # Arguments
/// * `target` - The target IP address or hostname
/// * `start` - The starting port number
/// * `end` - The ending port number
///
/// # Returns
/// A vector of open ports
pub fn scan_ports(target: &str, start: u16, end: u16) -> Vec<u16>
```

### Security Considerations

```rust
// DO: Validate input
fn parse_port(input: &str) -> Result<u16, ParseError> {
    let port: u16 = input.parse()?;
    if port == 0 {
        return Err(ParseError::InvalidPort);
    }
    Ok(port)
}

// DO: Handle sensitive data properly
use zeroize::Zeroize;

let mut password = String::from("secret");
// ... use password ...
password.zeroize(); // Clear from memory

// DON'T: Log sensitive information
// println!("Password: {}", password); // NEVER DO THIS
```

---

## Testing Requirements

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_parser() {
        assert_eq!(parse_port("80").unwrap(), 80);
        assert!(parse_port("0").is_err());
        assert!(parse_port("-1").is_err());
    }
}
```

### Integration Tests

```rust
// tests/integration_test.rs
#[test]
fn test_scanner_workflow() {
    // Setup test environment
    let server = start_test_server();

    // Run scanner
    let results = scan_ports("127.0.0.1", 8000, 8010);

    // Verify results
    assert!(results.contains(&8000));

    // Cleanup
    server.shutdown();
}
```

---

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code compiles without warnings (`cargo build`)
- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] Clippy is happy (`cargo clippy`)
- [ ] Documentation is updated
- [ ] Examples are complete and working
- [ ] No sensitive data or credentials
- [ ] Security considerations documented

---

## Review Process

1. **Automated Checks** - CI runs formatting, linting, and tests
2. **Code Review** - Maintainers review for quality and security
3. **Feedback** - Address any requested changes
4. **Merge** - Approved PRs are merged to main

---

## Getting Help

- Open an issue for questions
- Join discussions in the repository
- Check existing issues before creating new ones

---

## Recognition

All contributors are recognized in:
- The repository's contributor list
- Chapter/section credits where applicable
- The project README

Thank you for helping make Rust Security Bible better!
