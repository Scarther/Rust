# Lesson 08: Traits

## Overview

Traits define shared behavior. They're similar to interfaces in other languages but more powerful. Traits are fundamental to Rust's generic programming.

---

## Learning Objectives

By the end of this lesson, you will:
- Define and implement traits
- Use common standard library traits
- Understand trait bounds in generics
- Implement traits for security tools
- Use derive macros for common traits

---

## Defining Traits

### Basic Trait Definition

```rust
// Define a trait
trait Scannable {
    fn scan(&self) -> Vec<u16>;
    fn name(&self) -> &str;
}

// Implement the trait for a type
struct TcpScanner {
    target: String,
}

impl Scannable for TcpScanner {
    fn scan(&self) -> Vec<u16> {
        println!("TCP scanning {}", self.target);
        vec![22, 80, 443]  // Simulated results
    }

    fn name(&self) -> &str {
        "TCP Scanner"
    }
}

struct UdpScanner {
    target: String,
}

impl Scannable for UdpScanner {
    fn scan(&self) -> Vec<u16> {
        println!("UDP scanning {}", self.target);
        vec![53, 123, 161]  // Simulated results
    }

    fn name(&self) -> &str {
        "UDP Scanner"
    }
}

fn main() {
    let tcp = TcpScanner { target: "192.168.1.1".to_string() };
    let udp = UdpScanner { target: "192.168.1.1".to_string() };

    println!("{}: {:?}", tcp.name(), tcp.scan());
    println!("{}: {:?}", udp.name(), udp.scan());
}
```

### Default Implementations

```rust
trait Logger {
    // Required method - must be implemented
    fn log(&self, message: &str);

    // Default method - can be overridden
    fn info(&self, message: &str) {
        self.log(&format!("[INFO] {}", message));
    }

    fn warn(&self, message: &str) {
        self.log(&format!("[WARN] {}", message));
    }

    fn error(&self, message: &str) {
        self.log(&format!("[ERROR] {}", message));
    }
}

struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn log(&self, message: &str) {
        println!("{}", message);
    }
}

struct FileLogger {
    path: String,
}

impl Logger for FileLogger {
    fn log(&self, message: &str) {
        // In real code, write to file
        println!("[FILE:{}] {}", self.path, message);
    }

    // Override default implementation
    fn error(&self, message: &str) {
        self.log(&format!("[ERROR] {} *** ALERT ***", message));
    }
}

fn main() {
    let console = ConsoleLogger;
    console.info("Starting scan");
    console.error("Connection failed");

    let file = FileLogger { path: "security.log".to_string() };
    file.info("Starting scan");
    file.error("Connection failed");  // Custom implementation
}
```

---

## Trait Bounds

### Generic Functions with Traits

```rust
trait Scannable {
    fn scan(&self) -> Vec<u16>;
}

struct TcpScanner;
struct UdpScanner;

impl Scannable for TcpScanner {
    fn scan(&self) -> Vec<u16> { vec![22, 80, 443] }
}

impl Scannable for UdpScanner {
    fn scan(&self) -> Vec<u16> { vec![53, 123] }
}

// Function that takes any Scannable type
fn run_scan<T: Scannable>(scanner: &T) -> Vec<u16> {
    scanner.scan()
}

// Alternative syntax with where clause
fn run_scan_verbose<T>(scanner: &T) -> Vec<u16>
where
    T: Scannable,
{
    scanner.scan()
}

fn main() {
    let tcp = TcpScanner;
    let udp = UdpScanner;

    let tcp_results = run_scan(&tcp);
    let udp_results = run_scan(&udp);

    println!("TCP: {:?}", tcp_results);
    println!("UDP: {:?}", udp_results);
}
```

### Multiple Trait Bounds

```rust
use std::fmt::Display;

trait Scannable {
    fn scan(&self) -> Vec<u16>;
}

trait Named {
    fn name(&self) -> &str;
}

// Multiple bounds with +
fn scan_and_report<T: Scannable + Named>(scanner: &T) {
    println!("Running {}", scanner.name());
    let results = scanner.scan();
    println!("Found {} open ports", results.len());
}

// With where clause (cleaner for complex bounds)
fn detailed_scan<T>(scanner: &T)
where
    T: Scannable + Named + Display,
{
    println!("Scanner: {}", scanner);
    let results = scanner.scan();
    println!("Results: {:?}", results);
}
```

---

## Common Standard Library Traits

### Debug and Display

```rust
use std::fmt;

// Debug - for developer output, use {:?}
// Display - for user output, use {}

#[derive(Debug)]  // Auto-implement Debug
struct ScanResult {
    target: String,
    open_ports: Vec<u16>,
}

// Manual Display implementation
impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} open ports", self.target, self.open_ports.len())
    }
}

fn main() {
    let result = ScanResult {
        target: "192.168.1.1".to_string(),
        open_ports: vec![22, 80, 443],
    };

    // Debug output
    println!("{:?}", result);
    println!("{:#?}", result);  // Pretty-printed

    // Display output
    println!("{}", result);
}
```

### Clone and Copy

```rust
// Copy - simple bitwise copy (stack only)
// Clone - explicit deep copy

#[derive(Clone, Copy, Debug)]  // Copy requires Clone
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Clone, Debug)]  // Clone only (has String)
struct Target {
    ip: String,
    ports: Vec<u16>,
}

fn main() {
    // Copy types are automatically copied
    let range1 = PortRange { start: 1, end: 1024 };
    let range2 = range1;  // Copy
    println!("Range1: {:?}", range1);  // Still valid!
    println!("Range2: {:?}", range2);

    // Clone types must be explicitly cloned
    let target1 = Target {
        ip: "192.168.1.1".to_string(),
        ports: vec![22, 80],
    };
    let target2 = target1.clone();  // Explicit clone
    // let target3 = target1;  // This would move target1
    println!("Target1: {:?}", target1);
    println!("Target2: {:?}", target2);
}
```

### PartialEq and Eq

```rust
#[derive(Debug, PartialEq, Eq)]  // Eq requires PartialEq
struct Alert {
    source_ip: String,
    destination_port: u16,
    severity: u8,
}

fn main() {
    let alert1 = Alert {
        source_ip: "10.0.0.1".to_string(),
        destination_port: 22,
        severity: 5,
    };

    let alert2 = Alert {
        source_ip: "10.0.0.1".to_string(),
        destination_port: 22,
        severity: 5,
    };

    let alert3 = Alert {
        source_ip: "10.0.0.2".to_string(),
        destination_port: 80,
        severity: 3,
    };

    println!("alert1 == alert2: {}", alert1 == alert2);  // true
    println!("alert1 == alert3: {}", alert1 == alert3);  // false
    println!("alert1 != alert3: {}", alert1 != alert3);  // true
}
```

### PartialOrd and Ord

```rust
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Vulnerability {
    severity: u8,  // Fields are compared in order
    name: String,
}

fn main() {
    let mut vulns = vec![
        Vulnerability { severity: 5, name: "SQL Injection".to_string() },
        Vulnerability { severity: 9, name: "RCE".to_string() },
        Vulnerability { severity: 3, name: "XSS".to_string() },
        Vulnerability { severity: 9, name: "Auth Bypass".to_string() },
    ];

    // Sort by severity (then name)
    vulns.sort();

    println!("Sorted by severity:");
    for v in &vulns {
        println!("  [{}] {}", v.severity, v.name);
    }

    // Comparison operators work
    let high = Vulnerability { severity: 9, name: "Test".to_string() };
    let low = Vulnerability { severity: 1, name: "Test".to_string() };
    println!("\nhigh > low: {}", high > low);
}
```

### Hash

```rust
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, PartialEq, Eq, Hash)]
struct Endpoint {
    ip: String,
    port: u16,
}

fn main() {
    let mut connection_count: HashMap<Endpoint, u32> = HashMap::new();

    let endpoints = vec![
        Endpoint { ip: "192.168.1.1".to_string(), port: 22 },
        Endpoint { ip: "192.168.1.1".to_string(), port: 80 },
        Endpoint { ip: "192.168.1.1".to_string(), port: 22 },  // Duplicate
        Endpoint { ip: "10.0.0.1".to_string(), port: 443 },
    ];

    for endpoint in endpoints {
        *connection_count.entry(endpoint).or_insert(0) += 1;
    }

    for (endpoint, count) in &connection_count {
        println!("{:?}: {} connections", endpoint, count);
    }
}
```

### Default

```rust
#[derive(Debug)]
struct ScanConfig {
    timeout_ms: u64,
    retries: u32,
    threads: usize,
    verbose: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            retries: 3,
            threads: 10,
            verbose: false,
        }
    }
}

fn main() {
    // Use all defaults
    let config1 = ScanConfig::default();
    println!("Default: {:?}", config1);

    // Override some defaults
    let config2 = ScanConfig {
        timeout_ms: 5000,
        verbose: true,
        ..Default::default()
    };
    println!("Custom: {:?}", config2);
}
```

---

## Trait Objects

### Dynamic Dispatch with dyn

```rust
trait Reporter {
    fn report(&self, message: &str);
}

struct ConsoleReporter;
struct JsonReporter;
struct SyslogReporter;

impl Reporter for ConsoleReporter {
    fn report(&self, message: &str) {
        println!("CONSOLE: {}", message);
    }
}

impl Reporter for JsonReporter {
    fn report(&self, message: &str) {
        println!(r#"{{"message": "{}"}}"#, message);
    }
}

impl Reporter for SyslogReporter {
    fn report(&self, message: &str) {
        println!("SYSLOG: {}", message);
    }
}

fn main() {
    // Vector of trait objects
    let reporters: Vec<Box<dyn Reporter>> = vec![
        Box::new(ConsoleReporter),
        Box::new(JsonReporter),
        Box::new(SyslogReporter),
    ];

    for reporter in &reporters {
        reporter.report("Scan completed");
    }
}

// Function taking trait object
fn send_alert(reporter: &dyn Reporter, message: &str) {
    reporter.report(message);
}
```

---

## Security Tool Examples

### Pluggable Output System

```rust
trait OutputFormat {
    fn header(&self) -> String;
    fn format_result(&self, port: u16, state: &str, service: &str) -> String;
    fn footer(&self) -> String;
}

struct TextOutput;
struct JsonOutput;
struct CsvOutput;

impl OutputFormat for TextOutput {
    fn header(&self) -> String {
        format!("{:<8} {:<10} {}", "PORT", "STATE", "SERVICE")
    }

    fn format_result(&self, port: u16, state: &str, service: &str) -> String {
        format!("{:<8} {:<10} {}", port, state, service)
    }

    fn footer(&self) -> String {
        String::new()
    }
}

impl OutputFormat for JsonOutput {
    fn header(&self) -> String {
        r#"{"results": ["#.to_string()
    }

    fn format_result(&self, port: u16, state: &str, service: &str) -> String {
        format!(r#"{{"port": {}, "state": "{}", "service": "{}"}}"#, port, state, service)
    }

    fn footer(&self) -> String {
        "]}".to_string()
    }
}

impl OutputFormat for CsvOutput {
    fn header(&self) -> String {
        "port,state,service".to_string()
    }

    fn format_result(&self, port: u16, state: &str, service: &str) -> String {
        format!("{},{},{}", port, state, service)
    }

    fn footer(&self) -> String {
        String::new()
    }
}

fn generate_report<T: OutputFormat>(format: &T, results: &[(u16, &str, &str)]) {
    println!("{}", format.header());
    for (port, state, service) in results {
        println!("{}", format.format_result(*port, state, service));
    }
    let footer = format.footer();
    if !footer.is_empty() {
        println!("{}", footer);
    }
}

fn main() {
    let results = vec![
        (22, "open", "ssh"),
        (80, "open", "http"),
        (443, "open", "https"),
    ];

    println!("=== Text Output ===");
    generate_report(&TextOutput, &results);

    println!("\n=== JSON Output ===");
    generate_report(&JsonOutput, &results);

    println!("\n=== CSV Output ===");
    generate_report(&CsvOutput, &results);
}
```

### Rule-Based Detection System

```rust
trait DetectionRule {
    fn name(&self) -> &str;
    fn check(&self, data: &str) -> Option<String>;
}

struct SqlInjectionRule;
struct XssRule;
struct CommandInjectionRule;

impl DetectionRule for SqlInjectionRule {
    fn name(&self) -> &str {
        "SQL Injection"
    }

    fn check(&self, data: &str) -> Option<String> {
        let patterns = ["' OR ", "UNION SELECT", "--", "'; DROP"];
        for pattern in patterns {
            if data.to_uppercase().contains(pattern) {
                return Some(format!("Found pattern: {}", pattern));
            }
        }
        None
    }
}

impl DetectionRule for XssRule {
    fn name(&self) -> &str {
        "Cross-Site Scripting"
    }

    fn check(&self, data: &str) -> Option<String> {
        let patterns = ["<script", "javascript:", "onerror=", "onload="];
        for pattern in patterns {
            if data.to_lowercase().contains(pattern) {
                return Some(format!("Found pattern: {}", pattern));
            }
        }
        None
    }
}

impl DetectionRule for CommandInjectionRule {
    fn name(&self) -> &str {
        "Command Injection"
    }

    fn check(&self, data: &str) -> Option<String> {
        let patterns = ["; cat ", "| nc ", "$(", "`", "&& wget"];
        for pattern in patterns {
            if data.contains(pattern) {
                return Some(format!("Found pattern: {}", pattern));
            }
        }
        None
    }
}

struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl DetectionEngine {
    fn new() -> Self {
        Self { rules: Vec::new() }
    }

    fn add_rule(&mut self, rule: Box<dyn DetectionRule>) {
        self.rules.push(rule);
    }

    fn analyze(&self, input: &str) -> Vec<(String, String)> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            if let Some(detail) = rule.check(input) {
                findings.push((rule.name().to_string(), detail));
            }
        }

        findings
    }
}

fn main() {
    let mut engine = DetectionEngine::new();
    engine.add_rule(Box::new(SqlInjectionRule));
    engine.add_rule(Box::new(XssRule));
    engine.add_rule(Box::new(CommandInjectionRule));

    let test_inputs = vec![
        "SELECT * FROM users",
        "admin' OR '1'='1",
        "<script>alert('xss')</script>",
        "test; cat /etc/passwd",
        "normal input here",
    ];

    for input in test_inputs {
        println!("\nAnalyzing: {}", input);
        let findings = engine.analyze(input);

        if findings.is_empty() {
            println!("  No threats detected");
        } else {
            for (rule, detail) in findings {
                println!("  [!] {}: {}", rule, detail);
            }
        }
    }
}
```

---

## Derive Macros Summary

```rust
// Most common derives for security tools
#[derive(
    Debug,      // {:?} formatting
    Clone,      // .clone() method
    PartialEq,  // == and != operators
    Eq,         // Required for HashMap keys
    Hash,       // Required for HashMap keys
    Default,    // Default::default()
)]
struct ScanResult {
    target: String,
    ports: Vec<u16>,
}

// Serialization (with serde crate)
// #[derive(Serialize, Deserialize)]
```

---

## Exercises

### Exercise 1: Sortable Findings
Create a `Finding` struct with severity, title, and timestamp. Implement traits so it can be sorted by severity and used in a HashSet.

### Exercise 2: Multi-Protocol Scanner
Define a `Scanner` trait with `scan()` method. Implement it for `HttpScanner`, `FtpScanner`, and `SshScanner`.

### Exercise 3: Configurable Logger
Create a trait `Logger` with methods `log()`, `debug()`, `warn()`, `error()`. Implement for `FileLogger`, `SyslogLogger`, `NullLogger`.

---

## Key Takeaways

1. **Traits define shared behavior** - Like interfaces with default implementations
2. **Trait bounds constrain generics** - `T: Scannable` means T must implement Scannable
3. **Common derives** - Debug, Clone, PartialEq, Eq, Hash, Default
4. **Trait objects for dynamic dispatch** - `Box<dyn Trait>` for runtime polymorphism
5. **Multiple implementations** - Same trait, different types, different behavior

---

## Next Steps

You've completed the fundamentals! Continue to:
- [Chapter 02: Skill Levels](../Chapter_02_Skill_Levels/) for hands-on projects
- [Quick Reference](../Quick_Reference/) for cheat sheets
- [Cookbook](../Cookbook/) for copy-paste recipes

---

[← Previous: Collections](./07_Collections.md) | [Chapter 02: Skill Levels →](../Chapter_02_Skill_Levels/)
