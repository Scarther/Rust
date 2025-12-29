# Lesson 05: Structs and Enums

## Overview

Structs and enums are Rust's primary ways to create custom data types. They let you model your security tools' data in a type-safe way.

---

## Learning Objectives

By the end of this lesson, you will:
- Create and use structs to group related data
- Implement methods on structs
- Define enums for variant types
- Use pattern matching with enums
- Apply these concepts to security tools

---

## Structs

### Defining Structs

Structs group related data together:

```rust
// A simple struct
struct Target {
    ip: String,
    port: u16,
    hostname: Option<String>,
}

fn main() {
    // Creating an instance
    let target = Target {
        ip: String::from("192.168.1.1"),
        port: 22,
        hostname: Some(String::from("server01")),
    };

    println!("Scanning {}:{}", target.ip, target.port);

    if let Some(name) = &target.hostname {
        println!("Hostname: {}", name);
    }
}
```

### Struct Update Syntax

Create a new struct from an existing one:

```rust
struct ScanConfig {
    timeout_ms: u64,
    retries: u32,
    verbose: bool,
    threads: usize,
}

fn main() {
    let default_config = ScanConfig {
        timeout_ms: 1000,
        retries: 3,
        verbose: false,
        threads: 10,
    };

    // Create new config, overriding only some fields
    let custom_config = ScanConfig {
        timeout_ms: 5000,
        verbose: true,
        ..default_config  // Copy remaining fields
    };

    println!("Timeout: {}ms", custom_config.timeout_ms);
    println!("Retries: {}", custom_config.retries);  // 3 from default
}
```

### Tuple Structs

Named tuples when field names aren't needed:

```rust
struct IpAddress(u8, u8, u8, u8);
struct Port(u16);
struct MacAddress(String);

fn main() {
    let ip = IpAddress(192, 168, 1, 1);
    let port = Port(22);
    let mac = MacAddress(String::from("00:1A:2B:3C:4D:5E"));

    println!("IP: {}.{}.{}.{}", ip.0, ip.1, ip.2, ip.3);
    println!("Port: {}", port.0);
    println!("MAC: {}", mac.0);
}
```

### Unit Structs

Structs with no fields (useful for traits):

```rust
struct Marker;

// Often used with traits
struct TcpScanner;
struct UdpScanner;
```

---

## Methods and Associated Functions

### Implementing Methods

Methods are functions defined on a struct:

```rust
struct Scanner {
    target: String,
    ports: Vec<u16>,
    timeout_ms: u64,
}

impl Scanner {
    // Associated function (like a constructor)
    // Called with Scanner::new()
    fn new(target: &str) -> Scanner {
        Scanner {
            target: target.to_string(),
            ports: Vec::new(),
            timeout_ms: 1000,
        }
    }

    // Method that borrows self immutably
    fn target(&self) -> &str {
        &self.target
    }

    // Method that borrows self mutably
    fn add_port(&mut self, port: u16) {
        self.ports.push(port);
    }

    // Method that adds a range of ports
    fn add_port_range(&mut self, start: u16, end: u16) {
        for port in start..=end {
            self.ports.push(port);
        }
    }

    // Method that takes ownership of self
    fn scan(self) -> ScanResults {
        println!("Scanning {} ports on {}", self.ports.len(), self.target);
        // ... perform scan ...
        ScanResults {
            target: self.target,
            open_ports: vec![22, 80],  // Simulated results
        }
    }
}

struct ScanResults {
    target: String,
    open_ports: Vec<u16>,
}

fn main() {
    // Use associated function
    let mut scanner = Scanner::new("192.168.1.1");

    // Call methods
    scanner.add_port(22);
    scanner.add_port(80);
    scanner.add_port_range(443, 445);

    println!("Target: {}", scanner.target());

    // scan() consumes the scanner
    let results = scanner.scan();

    // scanner is no longer valid here
    println!("Open ports: {:?}", results.open_ports);
}
```

### Multiple impl Blocks

You can split implementations:

```rust
struct Target {
    ip: String,
    port: u16,
}

// Basic methods
impl Target {
    fn new(ip: &str, port: u16) -> Self {
        Self {
            ip: ip.to_string(),
            port,
        }
    }

    fn address(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

// Display methods
impl Target {
    fn display(&self) {
        println!("Target: {}", self.address());
    }
}

fn main() {
    let target = Target::new("10.0.0.1", 443);
    target.display();
}
```

---

## Enums

### Basic Enums

Enums define a type with a fixed set of variants:

```rust
enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

fn main() {
    let state = PortState::Open;

    match state {
        PortState::Open => println!("Port is OPEN"),
        PortState::Closed => println!("Port is closed"),
        PortState::Filtered => println!("Port is filtered"),
        PortState::Unknown => println!("State unknown"),
    }
}
```

### Enums with Data

Variants can hold data:

```rust
enum ScanResult {
    Success {
        port: u16,
        service: String,
        banner: Option<String>,
    },
    Timeout {
        port: u16,
        duration_ms: u64,
    },
    ConnectionRefused {
        port: u16,
    },
    Error(String),
}

fn scan_port(target: &str, port: u16) -> ScanResult {
    // Simulated scan logic
    match port {
        22 => ScanResult::Success {
            port,
            service: "SSH".to_string(),
            banner: Some("OpenSSH_9.0".to_string()),
        },
        80 => ScanResult::Success {
            port,
            service: "HTTP".to_string(),
            banner: None,
        },
        443 => ScanResult::Timeout {
            port,
            duration_ms: 5000,
        },
        _ => ScanResult::ConnectionRefused { port },
    }
}

fn main() {
    let ports = [22, 80, 443, 8080];

    for port in ports {
        let result = scan_port("192.168.1.1", port);

        match result {
            ScanResult::Success { port, service, banner } => {
                print!("Port {}: {} ({})", port, "OPEN", service);
                if let Some(b) = banner {
                    print!(" - {}", b);
                }
                println!();
            },
            ScanResult::Timeout { port, duration_ms } => {
                println!("Port {}: TIMEOUT after {}ms", port, duration_ms);
            },
            ScanResult::ConnectionRefused { port } => {
                println!("Port {}: CLOSED", port);
            },
            ScanResult::Error(msg) => {
                println!("ERROR: {}", msg);
            },
        }
    }
}
```

### The Option Enum

`Option<T>` represents a value that might be absent:

```rust
// Option is defined as:
// enum Option<T> {
//     Some(T),
//     None,
// }

fn find_service(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        80 => Some("HTTP"),
        443 => Some("HTTPS"),
        _ => None,
    }
}

fn main() {
    let ports = [22, 80, 9999];

    for port in ports {
        // Match on Option
        match find_service(port) {
            Some(service) => println!("Port {}: {}", port, service),
            None => println!("Port {}: Unknown service", port),
        }

        // Or use if let
        if let Some(service) = find_service(port) {
            println!("Found: {}", service);
        }

        // Or use unwrap_or
        let service = find_service(port).unwrap_or("Unknown");
        println!("Service: {}", service);
    }
}
```

### The Result Enum

`Result<T, E>` represents success or failure:

```rust
use std::net::TcpStream;
use std::time::Duration;
use std::io::{self, Read};

fn check_port(target: &str, port: u16) -> Result<String, String> {
    let address = format!("{}:{}", target, port);

    // Attempt connection
    let stream = TcpStream::connect_timeout(
        &address.parse().map_err(|e| format!("Invalid address: {}", e))?,
        Duration::from_millis(1000)
    ).map_err(|e| format!("Connection failed: {}", e))?;

    Ok(format!("Connected to {}", address))
}

fn main() {
    let results = [
        check_port("127.0.0.1", 22),
        check_port("invalid", 80),
    ];

    for result in results {
        match result {
            Ok(msg) => println!("SUCCESS: {}", msg),
            Err(err) => println!("FAILED: {}", err),
        }
    }
}
```

---

## Implementing Methods on Enums

```rust
enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
        }
    }

    fn severity(&self) -> u8 {
        match self {
            LogLevel::Debug => 1,
            LogLevel::Info => 2,
            LogLevel::Warning => 3,
            LogLevel::Error => 4,
            LogLevel::Critical => 5,
        }
    }

    fn should_alert(&self) -> bool {
        self.severity() >= 4
    }
}

fn main() {
    let levels = [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warning,
        LogLevel::Error,
        LogLevel::Critical,
    ];

    for level in levels {
        println!(
            "{}: severity={}, alert={}",
            level.as_str(),
            level.severity(),
            level.should_alert()
        );
    }
}
```

---

## Security Tool Examples

### Vulnerability Scanner Data Model

```rust
#[derive(Debug)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
struct Vulnerability {
    id: String,
    title: String,
    severity: Severity,
    cvss_score: f32,
    description: String,
    remediation: String,
}

impl Vulnerability {
    fn new(id: &str, title: &str, severity: Severity, cvss: f32) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            severity,
            cvss_score: cvss,
            description: String::new(),
            remediation: String::new(),
        }
    }

    fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    fn with_remediation(mut self, rem: &str) -> Self {
        self.remediation = rem.to_string();
        self
    }

    fn risk_rating(&self) -> &'static str {
        match self.cvss_score {
            s if s >= 9.0 => "CRITICAL",
            s if s >= 7.0 => "HIGH",
            s if s >= 4.0 => "MEDIUM",
            s if s >= 0.1 => "LOW",
            _ => "NONE",
        }
    }
}

struct ScanReport {
    target: String,
    vulnerabilities: Vec<Vulnerability>,
}

impl ScanReport {
    fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            vulnerabilities: Vec::new(),
        }
    }

    fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.vulnerabilities.push(vuln);
    }

    fn critical_count(&self) -> usize {
        self.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, Severity::Critical))
            .count()
    }

    fn summary(&self) {
        println!("=== Scan Report for {} ===", self.target);
        println!("Total vulnerabilities: {}", self.vulnerabilities.len());
        println!("Critical: {}", self.critical_count());

        for vuln in &self.vulnerabilities {
            println!("\n[{}] {} (CVSS: {})",
                vuln.id, vuln.title, vuln.cvss_score);
            println!("  Risk: {}", vuln.risk_rating());
            if !vuln.description.is_empty() {
                println!("  Description: {}", vuln.description);
            }
        }
    }
}

fn main() {
    let mut report = ScanReport::new("192.168.1.100");

    report.add_vulnerability(
        Vulnerability::new("CVE-2024-0001", "SQL Injection", Severity::Critical, 9.8)
            .with_description("Unsanitized input allows SQL injection")
            .with_remediation("Use parameterized queries")
    );

    report.add_vulnerability(
        Vulnerability::new("CVE-2024-0002", "Missing HSTS", Severity::Low, 3.1)
            .with_description("HTTP Strict Transport Security header missing")
    );

    report.summary();
}
```

### Network Protocol Parser

```rust
#[derive(Debug)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Unknown(value),
        }
    }
}

#[derive(Debug)]
struct PacketHeader {
    source_ip: [u8; 4],
    dest_ip: [u8; 4],
    protocol: Protocol,
    length: u16,
}

impl PacketHeader {
    fn source_ip_string(&self) -> String {
        format!("{}.{}.{}.{}",
            self.source_ip[0], self.source_ip[1],
            self.source_ip[2], self.source_ip[3])
    }

    fn dest_ip_string(&self) -> String {
        format!("{}.{}.{}.{}",
            self.dest_ip[0], self.dest_ip[1],
            self.dest_ip[2], self.dest_ip[3])
    }

    fn is_suspicious(&self) -> bool {
        // Check for suspicious patterns
        match self.protocol {
            Protocol::Icmp if self.length > 1000 => true,  // Large ICMP
            Protocol::Unknown(_) => true,                   // Unknown protocol
            _ => false,
        }
    }
}

fn main() {
    let packets = vec![
        PacketHeader {
            source_ip: [192, 168, 1, 100],
            dest_ip: [10, 0, 0, 1],
            protocol: Protocol::Tcp,
            length: 1500,
        },
        PacketHeader {
            source_ip: [10, 0, 0, 5],
            dest_ip: [192, 168, 1, 1],
            protocol: Protocol::Icmp,
            length: 64,
        },
        PacketHeader {
            source_ip: [172, 16, 0, 1],
            dest_ip: [8, 8, 8, 8],
            protocol: Protocol::from(255),  // Unknown
            length: 100,
        },
    ];

    for packet in &packets {
        println!("{} -> {} [{:?}] {} bytes {}",
            packet.source_ip_string(),
            packet.dest_ip_string(),
            packet.protocol,
            packet.length,
            if packet.is_suspicious() { "[SUSPICIOUS]" } else { "" }
        );
    }
}
```

---

## Exercises

### Exercise 1: Host Data Structure
Create a `Host` struct with:
- IP address
- Open ports (Vec)
- Operating system (Option)
- Methods: `add_port()`, `is_windows()`, `display()`

### Exercise 2: Alert System
Create an `Alert` enum with variants:
- `IntrusionAttempt { source_ip, target_port }`
- `MalwareDetected { filename, hash }`
- `PolicyViolation { user, action }`
- Implement `severity()` method returning 1-10

### Exercise 3: Builder Pattern
Implement a builder pattern for a `ScanConfig` struct with:
- target, ports, timeout, retries
- Methods that return `Self` for chaining

---

## Key Takeaways

1. **Structs group related data** - Use named fields for clarity
2. **Methods use `&self` or `&mut self`** - Choose based on whether you modify
3. **Associated functions don't take `self`** - Used for constructors (`new()`)
4. **Enums represent variants** - Each variant can hold different data
5. **Option for nullable values** - `Some(T)` or `None`
6. **Result for fallible operations** - `Ok(T)` or `Err(E)`
7. **impl blocks define behavior** - Keep related methods together

---

## Next Steps

Continue to [Lesson 06: Error Handling](./06_Error_Handling.md) to learn robust error handling patterns.

---

[← Previous: Ownership](./04_Ownership.md) | [Next: Error Handling →](./06_Error_Handling.md)
