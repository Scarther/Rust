# Port Scanning in Rust

## Overview

Port scanning is the foundation of network reconnaissance. This lesson covers building professional-grade port scanners with proper error handling, rate limiting, and output options.

---

## Learning Objectives

- Understand TCP connection mechanics
- Implement synchronous and async port scanners
- Add service detection and banner grabbing
- Handle rate limiting and timeouts
- Generate professional output

---

## TCP Connection Basics

### Understanding the TCP Handshake

```
Client                     Server
  |                          |
  |   SYN (port 22)          |
  |------------------------->|
  |                          |
  |   SYN-ACK (port open)    |
  |<-------------------------|
  |                          |
  |   ACK                    |
  |------------------------->|
  |                          |
  |   Connection established |

If port is closed:
  |   SYN (port 9999)        |
  |------------------------->|
  |                          |
  |   RST (port closed)      |
  |<-------------------------|
```

---

## Basic Port Scanner

### Simple TCP Connect Scanner

```rust
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

fn check_port(target: &str, port: u16, timeout_ms: u64) -> bool {
    let address = format!("{}:{}", target, port);

    match address.parse::<SocketAddr>() {
        Ok(addr) => {
            TcpStream::connect_timeout(
                &addr,
                Duration::from_millis(timeout_ms)
            ).is_ok()
        }
        Err(_) => false,
    }
}

fn main() {
    let target = "127.0.0.1";
    let ports = vec![22, 80, 443, 8080, 3306];

    println!("Scanning {}", target);
    println!("{}", "-".repeat(30));

    for port in ports {
        let status = if check_port(target, port, 1000) {
            "OPEN"
        } else {
            "closed"
        };
        println!("Port {:>5}: {}", port, status);
    }
}
```

### With Service Detection

```rust
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::Duration;

fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        6379 => "redis",
        8080 => "http-proxy",
        27017 => "mongodb",
        _ => "unknown",
    }
}

fn grab_banner(target: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let address = format!("{}:{}", target, port);
    let addr = address.parse().ok()?;

    let mut stream = TcpStream::connect_timeout(
        &addr,
        Duration::from_millis(timeout_ms)
    ).ok()?;

    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;

    // Some services send banner on connect
    let mut buffer = [0u8; 1024];
    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n])
                .trim()
                .to_string();
            Some(banner)
        }
        _ => None,
    }
}

fn main() {
    let target = "127.0.0.1";
    let ports: Vec<u16> = (20..=25).chain([80, 443, 8080]).collect();

    println!("{:<6} {:<8} {:<12} {}", "PORT", "STATE", "SERVICE", "BANNER");
    println!("{}", "-".repeat(60));

    for port in ports {
        let address = format!("{}:{}", target, port);
        if let Ok(addr) = address.parse() {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(1000)).is_ok() {
                let service = get_service_name(port);
                let banner = grab_banner(target, port, 2000)
                    .unwrap_or_default();

                println!("{:<6} {:<8} {:<12} {}",
                    port, "open", service,
                    banner.chars().take(40).collect::<String>()
                );
            }
        }
    }
}
```

---

## Async Port Scanner

### High-Performance Scanner with Tokio

```toml
# Cargo.toml
[dependencies]
tokio = { version = "1", features = ["full"] }
futures = "0.3"
```

```rust
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use futures::stream::{self, StreamExt};

#[derive(Debug, Clone)]
struct ScanResult {
    port: u16,
    open: bool,
    banner: Option<String>,
}

async fn scan_port(target: Arc<String>, port: u16, timeout_ms: u64) -> ScanResult {
    let address = format!("{}:{}", target, port);

    let result = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&address)
    ).await;

    match result {
        Ok(Ok(_stream)) => ScanResult {
            port,
            open: true,
            banner: None,  // Add banner grabbing here
        },
        _ => ScanResult {
            port,
            open: false,
            banner: None,
        },
    }
}

#[tokio::main]
async fn main() {
    let target = Arc::new("127.0.0.1".to_string());
    let ports: Vec<u16> = (1..=1024).collect();
    let timeout_ms = 1000u64;
    let concurrency = 100;

    println!("Scanning {} ports on {} with {} concurrent connections",
        ports.len(), target, concurrency);

    let target_clone = target.clone();

    let results: Vec<ScanResult> = stream::iter(ports)
        .map(|port| {
            let target = target_clone.clone();
            async move {
                scan_port(target, port, timeout_ms).await
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let open_ports: Vec<_> = results.iter()
        .filter(|r| r.open)
        .collect();

    println!("\nOpen ports:");
    for result in open_ports {
        println!("  Port {}", result.port);
    }
}
```

### With Progress Reporting

```rust
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::sync::mpsc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
enum ScanEvent {
    PortScanned(u16, bool),
    Complete,
}

async fn scan_with_progress(
    target: &str,
    ports: Vec<u16>,
    timeout_ms: u64,
    concurrency: usize,
) -> Vec<u16> {
    let target = Arc::new(target.to_string());
    let scanned = Arc::new(AtomicUsize::new(0));
    let total = ports.len();
    let (tx, mut rx) = mpsc::channel(100);

    // Spawn progress reporter
    let progress_handle = tokio::spawn(async move {
        let mut open_ports = Vec::new();

        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::PortScanned(port, open) => {
                    if open {
                        println!("  [+] Port {} OPEN", port);
                        open_ports.push(port);
                    }
                }
                ScanEvent::Complete => break,
            }
        }

        open_ports
    });

    // Scan ports with semaphore for concurrency control
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));

    let mut handles = Vec::new();

    for port in ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let target = target.clone();
        let tx = tx.clone();
        let scanned = scanned.clone();

        let handle = tokio::spawn(async move {
            let address = format!("{}:{}", target, port);
            let open = timeout(
                Duration::from_millis(timeout_ms),
                TcpStream::connect(&address)
            ).await.map(|r| r.is_ok()).unwrap_or(false);

            let _ = tx.send(ScanEvent::PortScanned(port, open)).await;

            let count = scanned.fetch_add(1, Ordering::SeqCst) + 1;
            if count % 100 == 0 {
                eprintln!("Progress: {}/{} ports scanned", count, total);
            }

            drop(permit);
        });

        handles.push(handle);
    }

    // Wait for all scans
    for handle in handles {
        let _ = handle.await;
    }

    let _ = tx.send(ScanEvent::Complete).await;

    progress_handle.await.unwrap()
}

#[tokio::main]
async fn main() {
    let target = "127.0.0.1";
    let ports: Vec<u16> = (1..=1024).collect();

    println!("Starting scan of {} on ports 1-1024", target);

    let open = scan_with_progress(target, ports, 1000, 200).await;

    println!("\n=== Scan Complete ===");
    println!("Open ports: {:?}", open);
}
```

---

## Rate Limiting

### Token Bucket Rate Limiter

```rust
use std::time::{Instant, Duration};
use std::sync::Mutex;

struct RateLimiter {
    tokens: Mutex<f64>,
    rate: f64,          // tokens per second
    max_tokens: f64,
    last_update: Mutex<Instant>,
}

impl RateLimiter {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: Mutex::new(burst),
            rate,
            max_tokens: burst,
            last_update: Mutex::new(Instant::now()),
        }
    }

    fn acquire(&self) -> bool {
        let mut tokens = self.tokens.lock().unwrap();
        let mut last_update = self.last_update.lock().unwrap();

        let now = Instant::now();
        let elapsed = now.duration_since(*last_update).as_secs_f64();

        // Replenish tokens
        *tokens = (*tokens + elapsed * self.rate).min(self.max_tokens);
        *last_update = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn wait_for_token(&self) {
        while !self.acquire() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn main() {
    let limiter = RateLimiter::new(100.0, 10.0);  // 100/sec, burst of 10

    for i in 0..50 {
        limiter.wait_for_token();
        println!("Scanning port {}", i);
    }
}
```

---

## Complete Scanner Tool

### Production-Ready Implementation

```rust
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use std::collections::HashMap;
use std::io::{Read, Write};

#[derive(Debug)]
struct ScanConfig {
    target: String,
    ports: Vec<u16>,
    timeout_ms: u64,
    banner_grab: bool,
    output_format: OutputFormat,
}

#[derive(Debug)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Debug)]
struct PortResult {
    port: u16,
    state: String,
    service: String,
    banner: Option<String>,
}

impl PortResult {
    fn to_text(&self) -> String {
        let banner = self.banner.as_deref().unwrap_or("");
        format!("{:<6} {:<8} {:<12} {}",
            self.port, self.state, self.service, banner)
    }

    fn to_json(&self) -> String {
        format!(
            r#"{{"port": {}, "state": "{}", "service": "{}", "banner": {}}}"#,
            self.port,
            self.state,
            self.service,
            self.banner.as_ref()
                .map(|b| format!(r#""{}""#, b.replace('"', "\\\"")))
                .unwrap_or("null".to_string())
        )
    }

    fn to_csv(&self) -> String {
        format!("{},{},{},\"{}\"",
            self.port,
            self.state,
            self.service,
            self.banner.as_deref().unwrap_or("")
        )
    }
}

fn get_service(port: u16) -> &'static str {
    let services: HashMap<u16, &str> = [
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
        (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
        (443, "https"), (445, "smb"), (3306, "mysql"), (3389, "rdp"),
        (5432, "postgresql"), (6379, "redis"), (8080, "http-proxy"),
    ].iter().cloned().collect();

    services.get(&port).unwrap_or(&"unknown")
}

fn grab_banner(addr: &SocketAddr, timeout: Duration) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    let mut buffer = [0u8; 1024];

    // Try reading banner (some services send on connect)
    if let Ok(n) = stream.read(&mut buffer) {
        if n > 0 {
            return Some(
                String::from_utf8_lossy(&buffer[..n])
                    .trim()
                    .chars()
                    .take(100)
                    .collect()
            );
        }
    }

    None
}

fn scan_port(target: &str, port: u16, config: &ScanConfig) -> Option<PortResult> {
    let address = format!("{}:{}", target, port);
    let addr: SocketAddr = address.parse().ok()?;
    let timeout = Duration::from_millis(config.timeout_ms);

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => {
            let banner = if config.banner_grab {
                grab_banner(&addr, timeout)
            } else {
                None
            };

            Some(PortResult {
                port,
                state: "open".to_string(),
                service: get_service(port).to_string(),
                banner,
            })
        }
        Err(_) => None,
    }
}

fn run_scan(config: &ScanConfig) -> Vec<PortResult> {
    let mut results = Vec::new();

    for port in &config.ports {
        if let Some(result) = scan_port(&config.target, *port, config) {
            results.push(result);
        }
    }

    results
}

fn print_results(results: &[PortResult], format: &OutputFormat) {
    match format {
        OutputFormat::Text => {
            println!("{:<6} {:<8} {:<12} {}", "PORT", "STATE", "SERVICE", "BANNER");
            println!("{}", "-".repeat(60));
            for r in results {
                println!("{}", r.to_text());
            }
        }
        OutputFormat::Json => {
            println!("[");
            for (i, r) in results.iter().enumerate() {
                let comma = if i < results.len() - 1 { "," } else { "" };
                println!("  {}{}", r.to_json(), comma);
            }
            println!("]");
        }
        OutputFormat::Csv => {
            println!("port,state,service,banner");
            for r in results {
                println!("{}", r.to_csv());
            }
        }
    }
}

fn main() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![21, 22, 23, 25, 80, 443, 3306, 5432, 8080],
        timeout_ms: 2000,
        banner_grab: true,
        output_format: OutputFormat::Text,
    };

    println!("Scanning {} ...\n", config.target);

    let results = run_scan(&config);

    print_results(&results, &config.output_format);

    println!("\n{} open ports found", results.len());
}
```

---

## Blue Team Detection

### How Defenders Detect Port Scans

1. **Connection volume** - Many connections from single IP
2. **Sequential access** - Ports scanned in order
3. **Failed connections** - High rate of RST packets
4. **SYN-only traffic** - Half-open scans
5. **Known scanner signatures** - Timing patterns, packet sizes

### Evasion Techniques (For Testing)

```rust
use std::time::Duration;
use rand::seq::SliceRandom;
use rand::Rng;

fn randomize_ports(ports: &mut Vec<u16>) {
    let mut rng = rand::thread_rng();
    ports.shuffle(&mut rng);
}

fn random_delay() -> Duration {
    let mut rng = rand::thread_rng();
    Duration::from_millis(rng.gen_range(100..500))
}
```

---

## Exercises

1. **SYN Scanner**: Research raw sockets and implement a SYN-only scanner
2. **Service Fingerprinting**: Extend banner grabbing to identify service versions
3. **XML Output**: Add Nmap-compatible XML output format
4. **Top Ports**: Create a "top 1000 ports" mode based on common services

---

## Key Takeaways

1. **TCP connect is the simplest** - Full connection, easy to detect
2. **Async for performance** - Handle thousands of connections
3. **Rate limiting matters** - Avoid network overload and detection
4. **Banner grabbing adds value** - Identify services and versions
5. **Output formats** - JSON for automation, text for humans

---

[← Back to Reconnaissance](./README.md) | [Next: Web Scanning →](./02_Web_Scanning.md)
