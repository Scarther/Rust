# Lesson 07: Collections

## Overview

Collections store multiple values. Unlike arrays, collections are stored on the heap and can grow or shrink. The three most common are `Vec`, `String`, and `HashMap`.

---

## Learning Objectives

By the end of this lesson, you will:
- Use `Vec<T>` for dynamic arrays
- Understand `String` as a collection of characters
- Use `HashMap<K, V>` for key-value storage
- Iterate over collections efficiently
- Apply collections to security tools

---

## Vec<T> - Dynamic Arrays

### Creating Vectors

```rust
fn main() {
    // Empty vector
    let mut ports: Vec<u16> = Vec::new();

    // With initial values using macro
    let common_ports = vec![21, 22, 23, 25, 80, 443];

    // With capacity (performance optimization)
    let mut results: Vec<String> = Vec::with_capacity(1000);

    // Using collect from iterator
    let range_ports: Vec<u16> = (1..=1024).collect();

    println!("Common ports: {:?}", common_ports);
    println!("Range has {} ports", range_ports.len());
}
```

### Adding and Removing Elements

```rust
fn main() {
    let mut open_ports: Vec<u16> = Vec::new();

    // Add elements
    open_ports.push(22);
    open_ports.push(80);
    open_ports.push(443);

    println!("After push: {:?}", open_ports);

    // Remove last element
    if let Some(port) = open_ports.pop() {
        println!("Removed: {}", port);
    }

    // Insert at position
    open_ports.insert(0, 21);  // Insert at beginning
    println!("After insert: {:?}", open_ports);

    // Remove at position
    let removed = open_ports.remove(0);
    println!("Removed {}: {:?}", removed, open_ports);

    // Extend with another collection
    open_ports.extend([8080, 8443]);
    println!("After extend: {:?}", open_ports);
}
```

### Accessing Elements

```rust
fn main() {
    let ports = vec![22, 80, 443, 8080];

    // By index - panics if out of bounds!
    let first = ports[0];
    println!("First port: {}", first);

    // Safe access with get() - returns Option
    match ports.get(10) {
        Some(port) => println!("Port: {}", port),
        None => println!("Index out of bounds"),
    }

    // Using get with unwrap_or
    let port = ports.get(10).unwrap_or(&0);
    println!("Port (or default): {}", port);

    // First and last
    if let Some(first) = ports.first() {
        println!("First: {}", first);
    }
    if let Some(last) = ports.last() {
        println!("Last: {}", last);
    }
}
```

### Iterating Over Vectors

```rust
fn main() {
    let ports = vec![22, 80, 443];

    // Immutable iteration
    println!("Scanning ports:");
    for port in &ports {
        println!("  Port {}", port);
    }

    // Mutable iteration
    let mut values = vec![1, 2, 3];
    for value in &mut values {
        *value *= 2;  // Double each value
    }
    println!("Doubled: {:?}", values);

    // With index
    for (i, port) in ports.iter().enumerate() {
        println!("  [{}] Port {}", i, port);
    }

    // Consuming iteration (takes ownership)
    for port in ports {  // ports moved here
        println!("Processing {}", port);
    }
    // ports is no longer valid here
}
```

### Useful Vector Methods

```rust
fn main() {
    let mut ports = vec![80, 22, 443, 22, 8080, 80];

    // Length and capacity
    println!("Length: {}, Capacity: {}", ports.len(), ports.capacity());

    // Check if empty
    println!("Empty: {}", ports.is_empty());

    // Contains
    println!("Has port 22: {}", ports.contains(&22));

    // Sort
    ports.sort();
    println!("Sorted: {:?}", ports);

    // Remove duplicates (must be sorted first)
    ports.dedup();
    println!("Deduped: {:?}", ports);

    // Reverse
    ports.reverse();
    println!("Reversed: {:?}", ports);

    // Retain only elements matching predicate
    ports.retain(|&p| p < 1000);
    println!("< 1000: {:?}", ports);

    // Clear all elements
    ports.clear();
    println!("Cleared: {:?}", ports);
}
```

### Slices

```rust
fn main() {
    let ports = vec![21, 22, 23, 25, 80, 110, 443];

    // Create slices
    let first_three: &[u16] = &ports[0..3];
    let last_three: &[u16] = &ports[ports.len()-3..];

    println!("First 3: {:?}", first_three);
    println!("Last 3: {:?}", last_three);

    // Functions that take slices work with both Vec and arrays
    print_ports(&ports);      // From Vec
    print_ports(&[80, 443]);  // From array
}

fn print_ports(ports: &[u16]) {
    println!("Ports: {:?}", ports);
}
```

---

## String - Text Collection

### Creating Strings

```rust
fn main() {
    // Empty string
    let mut s = String::new();

    // From string literal
    let s1 = String::from("hello");
    let s2 = "hello".to_string();

    // With capacity
    let s3 = String::with_capacity(100);

    // From format macro
    let ip = "192.168.1.1";
    let port = 22;
    let address = format!("{}:{}", ip, port);

    println!("Address: {}", address);
}
```

### Modifying Strings

```rust
fn main() {
    let mut log = String::new();

    // Append string slice
    log.push_str("[INFO] ");
    log.push_str("Connection established");

    // Append single character
    log.push('\n');

    // Concatenate with +
    let prefix = String::from("[WARN] ");
    let message = "Suspicious activity";
    let warning = prefix + message;  // prefix is moved!

    // Better: use format!
    let level = "ERROR";
    let msg = "Connection failed";
    let entry = format!("[{}] {}", level, msg);

    println!("{}", log);
    println!("{}", warning);
    println!("{}", entry);
}
```

### String Slicing

```rust
fn main() {
    let log_line = "2024-01-15 10:30:45 [ERROR] Connection timeout";

    // Slice by byte indices (careful with UTF-8!)
    let date = &log_line[0..10];
    let time = &log_line[11..19];
    let level = &log_line[21..26];

    println!("Date: {}", date);
    println!("Time: {}", time);
    println!("Level: {}", level);

    // Split into parts
    let parts: Vec<&str> = log_line.split_whitespace().collect();
    println!("Parts: {:?}", parts);
}
```

### String Methods

```rust
fn main() {
    let input = "  SELECT * FROM users WHERE id=1  ";

    // Trim whitespace
    let trimmed = input.trim();
    println!("Trimmed: '{}'", trimmed);

    // Case conversion
    let upper = trimmed.to_uppercase();
    let lower = trimmed.to_lowercase();
    println!("Upper: {}", upper);
    println!("Lower: {}", lower);

    // Check content
    println!("Starts with SELECT: {}", trimmed.starts_with("SELECT"));
    println!("Contains 'users': {}", trimmed.contains("users"));

    // Replace
    let safe = trimmed.replace("*", "id, username");
    println!("Replaced: {}", safe);

    // Split
    let url = "https://example.com/api/users";
    let parts: Vec<&str> = url.split('/').collect();
    println!("URL parts: {:?}", parts);

    // Lines
    let multiline = "line1\nline2\nline3";
    for line in multiline.lines() {
        println!("  {}", line);
    }
}
```

### String vs &str

```rust
// &str - borrowed string slice (immutable view)
// String - owned, heap-allocated, growable

fn takes_str(s: &str) {
    println!("Got: {}", s);
}

fn takes_string(s: String) {
    println!("Owned: {}", s);
}

fn main() {
    let literal: &str = "hello";           // String literal is &str
    let owned: String = String::from("hello");

    // &str works with both
    takes_str(literal);
    takes_str(&owned);  // Borrow String as &str

    // String requires ownership
    takes_string(literal.to_string());  // Convert &str to String
    takes_string(owned);                 // Move ownership
    // owned is no longer valid here
}
```

---

## HashMap<K, V> - Key-Value Storage

### Creating HashMaps

```rust
use std::collections::HashMap;

fn main() {
    // Empty HashMap
    let mut services: HashMap<u16, String> = HashMap::new();

    // Insert values
    services.insert(22, String::from("SSH"));
    services.insert(80, String::from("HTTP"));
    services.insert(443, String::from("HTTPS"));

    // From iterator of tuples
    let port_data = vec![
        (21, "FTP"),
        (25, "SMTP"),
        (53, "DNS"),
    ];

    let more_services: HashMap<u16, &str> = port_data.into_iter().collect();

    println!("Services: {:?}", services);
    println!("More: {:?}", more_services);
}
```

### Accessing Values

```rust
use std::collections::HashMap;

fn main() {
    let mut services: HashMap<u16, &str> = HashMap::new();
    services.insert(22, "SSH");
    services.insert(80, "HTTP");
    services.insert(443, "HTTPS");

    // Get returns Option
    match services.get(&22) {
        Some(service) => println!("Port 22: {}", service),
        None => println!("Port 22: Unknown"),
    }

    // With unwrap_or
    let service = services.get(&9999).unwrap_or(&"Unknown");
    println!("Port 9999: {}", service);

    // Check if key exists
    if services.contains_key(&80) {
        println!("HTTP service found");
    }
}
```

### Updating Values

```rust
use std::collections::HashMap;

fn main() {
    let mut port_count: HashMap<u16, u32> = HashMap::new();

    // Insert or update
    port_count.insert(22, 1);
    port_count.insert(22, 2);  // Overwrites previous value

    // Only insert if key doesn't exist
    port_count.entry(80).or_insert(1);
    port_count.entry(80).or_insert(999);  // Won't overwrite

    println!("Port 80 count: {}", port_count.get(&80).unwrap());

    // Update based on old value
    let count = port_count.entry(22).or_insert(0);
    *count += 1;

    println!("Port 22 count: {}", port_count.get(&22).unwrap());

    // Count occurrences
    let ports = [22, 80, 22, 443, 22, 80];
    let mut counts: HashMap<u16, u32> = HashMap::new();

    for port in ports {
        *counts.entry(port).or_insert(0) += 1;
    }

    println!("Counts: {:?}", counts);
}
```

### Iterating HashMaps

```rust
use std::collections::HashMap;

fn main() {
    let mut services: HashMap<u16, &str> = HashMap::new();
    services.insert(22, "SSH");
    services.insert(80, "HTTP");
    services.insert(443, "HTTPS");

    // Iterate over key-value pairs
    for (port, service) in &services {
        println!("Port {}: {}", port, service);
    }

    // Just keys
    for port in services.keys() {
        println!("Port: {}", port);
    }

    // Just values
    for service in services.values() {
        println!("Service: {}", service);
    }

    // Mutable iteration
    for (_, service) in services.iter_mut() {
        // Can modify values
        // *service = "Modified";  // Would need String, not &str
    }
}
```

---

## Security Tool Examples

### Port Scan Results Aggregator

```rust
use std::collections::HashMap;

#[derive(Debug)]
struct ScanResult {
    open_ports: Vec<u16>,
    services: HashMap<u16, String>,
    banners: HashMap<u16, String>,
}

impl ScanResult {
    fn new() -> Self {
        Self {
            open_ports: Vec::new(),
            services: HashMap::new(),
            banners: HashMap::new(),
        }
    }

    fn add_port(&mut self, port: u16, service: Option<&str>, banner: Option<&str>) {
        self.open_ports.push(port);

        if let Some(svc) = service {
            self.services.insert(port, svc.to_string());
        }

        if let Some(ban) = banner {
            self.banners.insert(port, ban.to_string());
        }
    }

    fn summary(&self) {
        println!("Open ports: {}", self.open_ports.len());

        for port in &self.open_ports {
            let service = self.services.get(port)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            print!("  {}: {}", port, service);

            if let Some(banner) = self.banners.get(port) {
                print!(" ({})", banner);
            }
            println!();
        }
    }
}

fn main() {
    let mut results = ScanResult::new();

    results.add_port(22, Some("SSH"), Some("OpenSSH_9.0"));
    results.add_port(80, Some("HTTP"), None);
    results.add_port(443, Some("HTTPS"), Some("nginx/1.18"));
    results.add_port(3306, Some("MySQL"), Some("5.7.32"));

    results.summary();
}
```

### Log Analyzer

```rust
use std::collections::HashMap;

fn analyze_logs(logs: &[&str]) -> HashMap<String, Vec<String>> {
    let mut by_level: HashMap<String, Vec<String>> = HashMap::new();

    for log in logs {
        // Parse log format: "LEVEL: message"
        if let Some((level, message)) = log.split_once(": ") {
            by_level
                .entry(level.to_uppercase())
                .or_insert_with(Vec::new)
                .push(message.to_string());
        }
    }

    by_level
}

fn main() {
    let logs = vec![
        "INFO: User login successful",
        "ERROR: Database connection failed",
        "INFO: Processing request",
        "WARNING: High memory usage",
        "ERROR: Authentication failed",
        "INFO: Request completed",
        "CRITICAL: System overload",
    ];

    let analyzed = analyze_logs(&logs);

    for (level, messages) in &analyzed {
        println!("\n=== {} ({} entries) ===", level, messages.len());
        for msg in messages {
            println!("  - {}", msg);
        }
    }
}
```

### IP Tracker

```rust
use std::collections::HashMap;

struct ConnectionTracker {
    connections: HashMap<String, ConnectionInfo>,
}

struct ConnectionInfo {
    count: u32,
    ports: Vec<u16>,
    first_seen: String,
    last_seen: String,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    fn record(&mut self, ip: &str, port: u16, timestamp: &str) {
        let entry = self.connections
            .entry(ip.to_string())
            .or_insert_with(|| ConnectionInfo {
                count: 0,
                ports: Vec::new(),
                first_seen: timestamp.to_string(),
                last_seen: String::new(),
            });

        entry.count += 1;
        entry.last_seen = timestamp.to_string();

        if !entry.ports.contains(&port) {
            entry.ports.push(port);
        }
    }

    fn report(&self) {
        println!("{:<16} {:>6} {:>8} Ports", "IP", "Count", "Unique");
        println!("{}", "-".repeat(50));

        for (ip, info) in &self.connections {
            println!(
                "{:<16} {:>6} {:>8} {:?}",
                ip, info.count, info.ports.len(), info.ports
            );
        }
    }

    fn suspicious_ips(&self, threshold: u32) -> Vec<&String> {
        self.connections
            .iter()
            .filter(|(_, info)| info.count > threshold)
            .map(|(ip, _)| ip)
            .collect()
    }
}

fn main() {
    let mut tracker = ConnectionTracker::new();

    // Simulate incoming connections
    let events = [
        ("192.168.1.100", 22, "10:00:01"),
        ("192.168.1.100", 80, "10:00:02"),
        ("10.0.0.50", 443, "10:00:03"),
        ("192.168.1.100", 22, "10:00:04"),
        ("192.168.1.100", 22, "10:00:05"),
        ("10.0.0.50", 80, "10:00:06"),
        ("172.16.0.1", 8080, "10:00:07"),
    ];

    for (ip, port, time) in events {
        tracker.record(ip, port, time);
    }

    println!("=== Connection Report ===\n");
    tracker.report();

    println!("\n=== Suspicious IPs (>2 connections) ===");
    for ip in tracker.suspicious_ips(2) {
        println!("  {}", ip);
    }
}
```

---

## Exercises

### Exercise 1: Unique Ports
Write a function that takes a `Vec<u16>` of ports and returns a new `Vec<u16>` with duplicates removed, sorted ascending.

### Exercise 2: Word Counter
Write a function that takes a string and returns a `HashMap<String, u32>` counting word occurrences.

### Exercise 3: Service Database
Create a `ServiceDB` struct that:
- Maps ports to service names
- Provides lookup by port
- Lists all known services
- Suggests services for unknown ports based on common patterns

---

## Key Takeaways

1. **Vec for dynamic arrays** - `push()`, `pop()`, `get()`, iteration
2. **String for growable text** - `push_str()`, `format!()`, slicing
3. **HashMap for key-value** - `insert()`, `get()`, `entry().or_insert()`
4. **Prefer iteration** - Use `for` loops and iterators over indexing
5. **Use `get()` for safe access** - Returns `Option` instead of panicking
6. **Slices work with multiple types** - `&[T]` works with Vec, arrays, etc.

---

## Next Steps

Continue to [Lesson 08: Traits](./08_Traits.md) to learn about defining shared behavior.

---

[← Previous: Error Handling](./06_Error_Handling.md) | [Next: Traits →](./08_Traits.md)
