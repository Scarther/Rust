# Rust Security Programming Cheatsheet

## Quick Reference for Security Tool Development

---

## Project Setup

### Cargo.toml Template (Security Tool)
```toml
[package]
name = "security-tool"
version = "0.1.0"
edition = "2021"

[dependencies]
# CLI
clap = { version = "4.4", features = ["derive"] }
colored = "2.1"

# Async Runtime
tokio = { version = "1.35", features = ["full"] }

# Networking
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }
pnet = "0.34"

# Crypto
sha2 = "0.10"
aes-gcm = "0.10"
rand = "0.8"

# Parsing
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
regex = "1.10"

# Error handling
anyhow = "1.0"
thiserror = "1.0"

[profile.release]
opt-level = 3
lto = true
strip = true
```

---

## Common Patterns

### CLI Argument Parsing
```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "tool", version = "1.0")]
struct Args {
    /// Target to scan
    #[arg(short, long)]
    target: String,

    /// Port range (e.g., 1-1024)
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Number of threads
    #[arg(short = 'T', long, default_value_t = 100)]
    threads: usize,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    println!("Target: {}", args.target);
}
```

### Error Handling with anyhow
```rust
use anyhow::{Context, Result, bail};

fn read_config(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .context("Failed to read config file")?;

    let config: Config = serde_json::from_str(&content)
        .context("Failed to parse config")?;

    if config.threads == 0 {
        bail!("Thread count must be > 0");
    }

    Ok(config)
}
```

### Custom Error Types
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

---

## Networking

### TCP Connection with Timeout
```rust
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

fn connect(addr: SocketAddr, timeout_ms: u64) -> Result<TcpStream, std::io::Error> {
    let timeout = Duration::from_millis(timeout_ms);
    TcpStream::connect_timeout(&addr, timeout)
}
```

### Async HTTP Request
```rust
use reqwest::Client;

async fn fetch_url(url: &str) -> Result<String, reqwest::Error> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("SecurityScanner/1.0")
        .build()?;

    let response = client.get(url)
        .send()
        .await?
        .text()
        .await?;

    Ok(response)
}
```

### DNS Resolution
```rust
use std::net::ToSocketAddrs;

fn resolve(host: &str) -> Vec<std::net::IpAddr> {
    format!("{}:0", host)
        .to_socket_addrs()
        .map(|iter| iter.map(|addr| addr.ip()).collect())
        .unwrap_or_default()
}
```

### Raw Packet Capture (pnet)
```rust
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;

fn capture(interface_name: &str) {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface_name)
        .expect("Interface not found");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to create channel"),
    };

    loop {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                println!("Packet: {:?}", eth);
            }
        }
    }
}
```

---

## Cryptography

### Hashing (SHA-256)
```rust
use sha2::{Sha256, Digest};

fn hash_data(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

fn hash_file(path: &str) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}
```

### AES-GCM Encryption
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, OsRng}};
use rand::RngCore;

fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    result
}

fn decrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).expect("decryption failed")
}
```

### Random Bytes
```rust
use rand::Rng;

fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen()).collect()
}

fn random_string(len: usize) -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
```

---

## Concurrency

### Multi-threaded Scanning
```rust
use std::sync::{Arc, Mutex};
use std::thread;

fn parallel_scan(targets: Vec<String>, threads: usize) -> Vec<Result> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let targets = Arc::new(targets);
    let chunk_size = (targets.len() / threads).max(1);

    let handles: Vec<_> = (0..threads)
        .map(|i| {
            let results = Arc::clone(&results);
            let targets = Arc::clone(&targets);

            thread::spawn(move || {
                let start = i * chunk_size;
                let end = (start + chunk_size).min(targets.len());

                for target in &targets[start..end] {
                    let result = scan_target(target);
                    results.lock().unwrap().push(result);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
}
```

### Async Concurrency
```rust
use tokio::task::JoinSet;

async fn async_scan(targets: Vec<String>) -> Vec<Result> {
    let mut set = JoinSet::new();

    for target in targets {
        set.spawn(async move {
            scan_target(&target).await
        });
    }

    let mut results = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(result) = res {
            results.push(result);
        }
    }

    results
}
```

### Channels for Communication
```rust
use std::sync::mpsc;
use std::thread;

fn producer_consumer() {
    let (tx, rx) = mpsc::channel();

    // Producer
    let producer = thread::spawn(move || {
        for i in 0..100 {
            tx.send(i).unwrap();
        }
    });

    // Consumer
    let consumer = thread::spawn(move || {
        while let Ok(value) = rx.recv() {
            println!("Received: {}", value);
        }
    });

    producer.join().unwrap();
    consumer.join().unwrap();
}
```

---

## File Operations

### Read File
```rust
use std::fs;

// Read entire file
let content = fs::read_to_string("file.txt")?;

// Read binary
let bytes = fs::read("file.bin")?;

// Read lines
use std::io::{BufRead, BufReader};
let file = fs::File::open("file.txt")?;
for line in BufReader::new(file).lines() {
    println!("{}", line?);
}
```

### Write File
```rust
use std::fs::File;
use std::io::Write;

// Simple write
fs::write("output.txt", "content")?;

// Buffered write
let mut file = File::create("output.txt")?;
writeln!(file, "Line 1")?;
writeln!(file, "Line 2")?;
file.flush()?;
```

### Directory Walking
```rust
use std::fs;
use std::path::Path;

fn walk_dir(path: &Path) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();

    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                files.extend(walk_dir(&path)?);
            } else {
                files.push(path.display().to_string());
            }
        }
    }

    Ok(files)
}
```

---

## Regex Patterns

### Common Security Patterns
```rust
use regex::Regex;

// IP Address
let ip_re = Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}$").unwrap();

// Email
let email_re = Regex::new(r"[\w.+-]+@[\w.-]+\.\w+").unwrap();

// URL
let url_re = Regex::new(r"https?://[^\s]+").unwrap();

// Hash patterns
let md5_re = Regex::new(r"^[a-fA-F0-9]{32}$").unwrap();
let sha256_re = Regex::new(r"^[a-fA-F0-9]{64}$").unwrap();

// JWT
let jwt_re = Regex::new(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$").unwrap();

// Private key
let privkey_re = Regex::new(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----").unwrap();
```

---

## Output Formatting

### Colored Output
```rust
use colored::*;

println!("{} Scan complete", "[+]".green().bold());
println!("{} Warning detected", "[!]".yellow().bold());
println!("{} Error occurred", "[-]".red().bold());
println!("{} Processing...", "[*]".cyan());

// Status line
println!("{:<20} {}", "Target:".bold(), "192.168.1.1");
println!("{:<20} {}", "Open ports:".bold(), "22, 80, 443".green());
```

### Table Output
```rust
fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    // Calculate column widths
    let widths: Vec<usize> = headers.iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .map(|r| r.get(i).map(|s| s.len()).unwrap_or(0))
                .max()
                .unwrap_or(0)
                .max(h.len())
        })
        .collect();

    // Print header
    for (i, h) in headers.iter().enumerate() {
        print!("{:width$}  ", h, width = widths[i]);
    }
    println!();

    // Print separator
    for w in &widths {
        print!("{:-<width$}  ", "", width = *w);
    }
    println!();

    // Print rows
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            print!("{:width$}  ", cell, width = widths[i]);
        }
        println!();
    }
}
```

### JSON Output
```rust
use serde::Serialize;

#[derive(Serialize)]
struct ScanResult {
    target: String,
    ports: Vec<u16>,
    timestamp: String,
}

fn output_json(result: &ScanResult) {
    let json = serde_json::to_string_pretty(result).unwrap();
    println!("{}", json);
}
```

---

## Testing

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let result = hash_data(b"hello");
        assert_eq!(result.len(), 64); // SHA-256 = 64 hex chars
    }

    #[test]
    fn test_parse_ports() {
        assert_eq!(parse_ports("80"), Ok(vec![80]));
        assert_eq!(parse_ports("1-5"), Ok(vec![1, 2, 3, 4, 5]));
        assert!(parse_ports("invalid").is_err());
    }

    #[test]
    #[should_panic(expected = "invalid")]
    fn test_panic() {
        panic!("invalid input");
    }
}
```

### Async Tests
```rust
#[tokio::test]
async fn test_async_fetch() {
    let result = fetch_url("https://httpbin.org/get").await;
    assert!(result.is_ok());
}
```

---

## Quick Build Commands

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run with args
cargo run -- -t 192.168.1.1 -p 1-1000

# Run tests
cargo test

# Check code
cargo clippy

# Format code
cargo fmt

# Cross-compile to Linux static
cargo build --release --target x86_64-unknown-linux-musl

# Cross-compile to Windows
cargo build --release --target x86_64-pc-windows-gnu
```

---

[← Back to Main](../README.md)
