# Lesson 03: Control Flow

## Overview

Control flow determines which code runs based on conditions. Rust provides powerful and safe control flow constructs that catch errors at compile time.

---

## Learning Objectives

By the end of this lesson, you will:
- Use `if`, `else if`, and `else` for branching
- Master `match` expressions for pattern matching
- Understand loops: `loop`, `while`, `for`
- Use `if let` and `while let` for concise patterns
- Apply control flow to security scenarios

---

## If/Else Expressions

### Basic If

```rust
fn main() {
    let port = 22;

    if port == 22 {
        println!("SSH detected");
    }
}
```

### If/Else

```rust
fn main() {
    let port = 80;

    if port == 22 {
        println!("SSH service");
    } else if port == 80 || port == 443 {
        println!("Web service");
    } else if port == 3306 {
        println!("MySQL service");
    } else {
        println!("Unknown service on port {}", port);
    }
}
```

### If as an Expression

In Rust, `if` is an expression that returns a value:

```rust
fn main() {
    let port = 443;

    // if returns a value
    let protocol = if port == 443 { "HTTPS" } else { "HTTP" };

    println!("Protocol: {}", protocol);

    // More complex example
    let risk_level = if port < 1024 {
        "privileged"
    } else if port < 10000 {
        "standard"
    } else {
        "high"
    };

    println!("Port {} risk level: {}", port, risk_level);
}
```

**Important:** Both branches must return the same type!

```rust
// This WON'T compile:
// let value = if condition { 5 } else { "text" };  // Error!
```

---

## Match Expressions

`match` is Rust's most powerful control flow construct. It's exhaustive - you must handle all cases.

### Basic Match

```rust
fn main() {
    let port: u16 = 22;

    match port {
        22 => println!("SSH"),
        80 => println!("HTTP"),
        443 => println!("HTTPS"),
        _ => println!("Unknown port"),  // _ catches everything else
    }
}
```

### Match with Multiple Patterns

```rust
fn main() {
    let port: u16 = 8080;

    match port {
        22 | 2222 => println!("SSH"),           // OR patterns
        80 | 8080 | 8000 => println!("HTTP"),   // Multiple options
        443 | 8443 => println!("HTTPS"),
        1..=1023 => println!("Privileged port"), // Range
        _ => println!("High port"),
    }
}
```

### Match with Guards

```rust
fn main() {
    let port: u16 = 3389;
    let os = "windows";

    match port {
        22 => println!("SSH"),
        3389 if os == "windows" => println!("RDP - Windows system!"),
        3389 => println!("RDP - unexpected OS"),
        _ => println!("Other"),
    }
}
```

### Match Returns Values

```rust
fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        _ => "Unknown",
    }
}

fn main() {
    let ports = [22, 80, 443, 8080, 3306];

    for port in ports {
        println!("Port {}: {}", port, get_service_name(port));
    }
}
```

### Destructuring in Match

```rust
enum ScanResult {
    Open(u16),
    Closed(u16),
    Filtered(u16),
    Error(String),
}

fn main() {
    let result = ScanResult::Open(22);

    match result {
        ScanResult::Open(port) => println!("Port {} is OPEN", port),
        ScanResult::Closed(port) => println!("Port {} is closed", port),
        ScanResult::Filtered(port) => println!("Port {} is filtered", port),
        ScanResult::Error(msg) => println!("Error: {}", msg),
    }
}
```

---

## Loops

### Infinite Loop with `loop`

```rust
fn main() {
    let mut count = 0;

    loop {
        count += 1;
        println!("Attempt {}", count);

        if count >= 3 {
            println!("Maximum retries reached");
            break;
        }
    }
}
```

### Loop Returns Values

```rust
fn main() {
    let mut counter = 0;

    let result = loop {
        counter += 1;

        if counter == 10 {
            break counter * 2;  // Return value from loop
        }
    };

    println!("Result: {}", result);  // Prints: Result: 20
}
```

### While Loop

```rust
fn main() {
    let mut attempts = 0;
    let max_attempts = 3;

    while attempts < max_attempts {
        attempts += 1;
        println!("Connection attempt {} of {}", attempts, max_attempts);

        // Simulate connection attempt
        let connected = attempts == 3;  // Success on third try

        if connected {
            println!("Connected!");
            break;
        }
    }
}
```

### For Loop

```rust
fn main() {
    // Iterate over a range
    println!("Scanning ports 20-25:");
    for port in 20..=25 {
        println!("  Checking port {}", port);
    }

    // Iterate over a collection
    let common_ports = [21, 22, 23, 25, 80, 443];
    println!("\nScanning common ports:");
    for port in common_ports {
        println!("  Port {}: {}", port, get_service(port));
    }

    // With index using enumerate
    println!("\nWith index:");
    for (index, port) in common_ports.iter().enumerate() {
        println!("  [{}] Port {}", index, port);
    }
}

fn get_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        80 => "HTTP",
        443 => "HTTPS",
        _ => "Unknown",
    }
}
```

### Loop Labels

```rust
fn main() {
    let targets = ["192.168.1.1", "192.168.1.2"];
    let ports = [22, 80, 443];

    'outer: for target in targets {
        println!("Scanning {}", target);

        for port in ports {
            println!("  Checking port {}", port);

            // If we find SSH, move to next target
            if port == 22 {
                println!("  Found SSH, moving to next target");
                continue 'outer;  // Continue outer loop
            }
        }
    }
}
```

---

## If Let and While Let

### If Let - Concise Pattern Matching

```rust
fn main() {
    let some_port: Option<u16> = Some(22);

    // Verbose way with match
    match some_port {
        Some(port) => println!("Port: {}", port),
        None => (),
    }

    // Concise way with if let
    if let Some(port) = some_port {
        println!("Port: {}", port);
    }

    // With else
    if let Some(port) = some_port {
        println!("Scanning port {}", port);
    } else {
        println!("No port specified");
    }
}
```

### While Let

```rust
fn main() {
    let mut ports = vec![22, 80, 443, 8080];

    // Process ports until none left
    while let Some(port) = ports.pop() {
        println!("Processing port: {}", port);
    }

    println!("All ports processed");
}
```

---

## Security-Focused Examples

### Port Range Validator

```rust
fn validate_port_range(start: u16, end: u16) -> Result<(), String> {
    if start == 0 {
        return Err("Port 0 is reserved".to_string());
    }

    if end > 65535 {
        return Err("Port exceeds maximum (65535)".to_string());
    }

    if start > end {
        return Err("Start port cannot be greater than end port".to_string());
    }

    let count = end - start + 1;
    if count > 10000 {
        return Err(format!("Range too large: {} ports", count));
    }

    Ok(())
}

fn main() {
    let ranges = [
        (1, 1024),
        (80, 80),
        (1000, 500),   // Invalid: start > end
        (0, 100),      // Invalid: starts at 0
    ];

    for (start, end) in ranges {
        match validate_port_range(start, end) {
            Ok(()) => println!("Range {}-{}: Valid", start, end),
            Err(msg) => println!("Range {}-{}: Invalid - {}", start, end, msg),
        }
    }
}
```

### Access Control Check

```rust
#[derive(Debug)]
enum UserRole {
    Admin,
    Operator,
    Viewer,
    Guest,
}

#[derive(Debug)]
enum Action {
    Read,
    Write,
    Execute,
    Delete,
}

fn check_permission(role: &UserRole, action: &Action) -> bool {
    match (role, action) {
        // Admin can do everything
        (UserRole::Admin, _) => true,

        // Operator can read, write, execute
        (UserRole::Operator, Action::Read) => true,
        (UserRole::Operator, Action::Write) => true,
        (UserRole::Operator, Action::Execute) => true,
        (UserRole::Operator, Action::Delete) => false,

        // Viewer can only read
        (UserRole::Viewer, Action::Read) => true,
        (UserRole::Viewer, _) => false,

        // Guest has no permissions
        (UserRole::Guest, _) => false,
    }
}

fn main() {
    let test_cases = [
        (UserRole::Admin, Action::Delete),
        (UserRole::Operator, Action::Execute),
        (UserRole::Operator, Action::Delete),
        (UserRole::Viewer, Action::Read),
        (UserRole::Viewer, Action::Write),
        (UserRole::Guest, Action::Read),
    ];

    for (role, action) in test_cases {
        let allowed = check_permission(&role, &action);
        println!("{:?} + {:?} = {}", role, action,
            if allowed { "ALLOWED" } else { "DENIED" });
    }
}
```

### Threat Level Assessment

```rust
fn assess_threat(port: u16, service_banner: Option<&str>) -> &'static str {
    match port {
        // Critical - always high risk
        23 => "CRITICAL - Telnet (unencrypted)",

        // Check banner for version info
        22 => {
            if let Some(banner) = service_banner {
                if banner.contains("OpenSSH_7") || banner.contains("OpenSSH_6") {
                    "HIGH - Outdated SSH version"
                } else {
                    "LOW - SSH appears current"
                }
            } else {
                "MEDIUM - SSH (version unknown)"
            }
        },

        // Web services - check for HTTP vs HTTPS
        80 => "MEDIUM - HTTP (unencrypted web)",
        443 => "LOW - HTTPS (encrypted web)",

        // Database ports
        3306 | 5432 | 1433 => "HIGH - Database exposed to network",

        // Remote access
        3389 => "HIGH - RDP exposed",
        5900..=5910 => "HIGH - VNC exposed",

        // Common development ports
        8080 | 8000 | 8888 => "MEDIUM - Development server",

        _ if port < 1024 => "MEDIUM - Privileged port",
        _ => "LOW - High port",
    }
}

fn main() {
    let findings = [
        (23, None),
        (22, Some("SSH-2.0-OpenSSH_7.4")),
        (22, Some("SSH-2.0-OpenSSH_9.0")),
        (80, None),
        (3306, None),
        (8080, None),
    ];

    println!("{:<6} {:<30} {}", "PORT", "BANNER", "ASSESSMENT");
    println!("{}", "-".repeat(60));

    for (port, banner) in findings {
        let banner_str = banner.unwrap_or("(none)");
        let assessment = assess_threat(port, banner);
        println!("{:<6} {:<30} {}", port, banner_str, assessment);
    }
}
```

---

## Exercises

### Exercise 1: HTTP Status Classifier
Write a function that takes an HTTP status code and returns the category:
- 100-199: Informational
- 200-299: Success
- 300-399: Redirect
- 400-499: Client Error
- 500-599: Server Error
- Other: Unknown

### Exercise 2: Retry Logic
Write a connection function that:
- Attempts to connect up to 5 times
- Waits between attempts (simulate with a counter)
- Returns success or failure

### Exercise 3: Log Level Filter
Create a function that filters log messages by severity level using match.

---

## Key Takeaways

1. **`if` is an expression** - Returns a value, both branches must have same type
2. **`match` is exhaustive** - Must handle all possible cases
3. **Use `_` for catch-all** - Matches anything not explicitly handled
4. **`if let` for single patterns** - Cleaner than match when you only care about one case
5. **Loop labels** - Use `'label:` to break/continue outer loops
6. **Ranges in patterns** - Use `..=` for inclusive ranges

---

## Next Steps

Continue to [Lesson 04: Ownership](./04_Ownership.md) to learn Rust's most unique feature.

---

[← Previous: Variables and Types](./02_Variables_Types.md) | [Next: Ownership →](./04_Ownership.md)
