# Essential Crates for Security Tools

## Quick Reference

Curated list of crates commonly used in security tool development.

---

## Networking

### reqwest - HTTP Client
```toml
[dependencies]
reqwest = { version = "0.11", features = ["json", "blocking"] }
```
```rust
// Async
let resp = reqwest::get("https://api.example.com").await?.json().await?;

// Blocking
let resp = reqwest::blocking::get("https://api.example.com")?.text()?;
```

### tokio - Async Runtime
```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
```
```rust
#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
}
```

### socket2 - Low-level Sockets
```toml
[dependencies]
socket2 = "0.5"
```
```rust
use socket2::{Socket, Domain, Type, Protocol};
let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
```

### pnet - Packet Manipulation
```toml
[dependencies]
pnet = "0.34"
```
```rust
use pnet::datalink::{self, Channel::Ethernet};
let interfaces = datalink::interfaces();
```

### trust-dns-resolver - DNS
```toml
[dependencies]
trust-dns-resolver = "0.23"
```
```rust
let resolver = Resolver::tokio_from_system_conf()?;
let response = resolver.lookup_ip("example.com").await?;
```

---

## Cryptography

### sha2 - SHA Hashing
```toml
[dependencies]
sha2 = "0.10"
```
```rust
use sha2::{Sha256, Digest};
let hash = Sha256::digest(b"hello world");
println!("{:x}", hash);
```

### md-5 - MD5 Hashing
```toml
[dependencies]
md-5 = "0.10"
```
```rust
use md5::{Md5, Digest};
let hash = Md5::digest(b"hello");
```

### aes-gcm - AES Encryption
```toml
[dependencies]
aes-gcm = "0.10"
```
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
let cipher = Aes256Gcm::new(&key);
let ciphertext = cipher.encrypt(&nonce, plaintext)?;
```

### argon2 - Password Hashing
```toml
[dependencies]
argon2 = "0.5"
```
```rust
use argon2::{Argon2, PasswordHasher};
let hash = Argon2::default().hash_password(password, &salt)?;
```

### rand - Random Numbers
```toml
[dependencies]
rand = "0.8"
```
```rust
use rand::Rng;
let n: u32 = rand::thread_rng().gen_range(0..100);
```

---

## CLI & Output

### clap - Argument Parsing
```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
```
```rust
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    target: String,
    #[arg(short, long, default_value = "1000")]
    timeout: u64,
}
```

### colored - Terminal Colors
```toml
[dependencies]
colored = "2"
```
```rust
use colored::*;
println!("{}", "Success!".green().bold());
println!("{}", "Error!".red());
```

### indicatif - Progress Bars
```toml
[dependencies]
indicatif = "0.17"
```
```rust
use indicatif::{ProgressBar, ProgressStyle};
let pb = ProgressBar::new(100);
pb.set_style(ProgressStyle::default_bar());
pb.inc(1);
```

### tabled - Tables
```toml
[dependencies]
tabled = "0.14"
```
```rust
use tabled::{Table, Tabled};
#[derive(Tabled)]
struct Port { number: u16, state: String }
println!("{}", Table::new(ports));
```

---

## Parsing & Data

### serde - Serialization
```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```
```rust
#[derive(Serialize, Deserialize)]
struct Config { target: String, ports: Vec<u16> }
let json = serde_json::to_string(&config)?;
```

### regex - Regular Expressions
```toml
[dependencies]
regex = "1"
```
```rust
use regex::Regex;
let re = Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")?;
for cap in re.find_iter(text) { println!("{}", cap.as_str()); }
```

### nom - Parser Combinators
```toml
[dependencies]
nom = "7"
```
```rust
use nom::{bytes::complete::tag, IResult};
fn parse_header(input: &str) -> IResult<&str, &str> {
    tag("HTTP/1.1")(input)
}
```

### goblin - Binary Parsing
```toml
[dependencies]
goblin = "0.7"
```
```rust
use goblin::Object;
let buffer = std::fs::read("binary")?;
match Object::parse(&buffer)? {
    Object::Elf(elf) => println!("ELF: {:?}", elf.header),
    Object::PE(pe) => println!("PE: {:?}", pe.header),
    _ => {}
}
```

---

## File Operations

### walkdir - Directory Walking
```toml
[dependencies]
walkdir = "2"
```
```rust
use walkdir::WalkDir;
for entry in WalkDir::new("/path").into_iter().filter_map(|e| e.ok()) {
    println!("{}", entry.path().display());
}
```

### notify - File Watching
```toml
[dependencies]
notify = "6"
```
```rust
use notify::{Watcher, RecursiveMode, watcher};
let mut watcher = watcher(tx, Duration::from_secs(2))?;
watcher.watch("/path", RecursiveMode::Recursive)?;
```

### tempfile - Temporary Files
```toml
[dependencies]
tempfile = "3"
```
```rust
use tempfile::NamedTempFile;
let file = NamedTempFile::new()?;
```

---

## Error Handling

### thiserror - Custom Errors
```toml
[dependencies]
thiserror = "1"
```
```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum ScanError {
    #[error("Connection failed: {0}")]
    Connection(#[from] std::io::Error),
    #[error("Timeout after {0}ms")]
    Timeout(u64),
}
```

### anyhow - Simple Errors
```toml
[dependencies]
anyhow = "1"
```
```rust
use anyhow::{Context, Result};
fn scan() -> Result<()> {
    let data = std::fs::read("config.json")
        .context("Failed to read config")?;
    Ok(())
}
```

---

## Logging

### log + env_logger
```toml
[dependencies]
log = "0.4"
env_logger = "0.10"
```
```rust
use log::{info, warn, error, debug};
env_logger::init();
info!("Starting scan");
error!("Connection failed");
```

### tracing - Structured Logging
```toml
[dependencies]
tracing = "0.1"
tracing-subscriber = "0.3"
```
```rust
use tracing::{info, instrument};

#[instrument]
fn scan_port(port: u16) {
    info!("Scanning port");
}
```

---

## Async Utilities

### futures - Async Helpers
```toml
[dependencies]
futures = "0.3"
```
```rust
use futures::stream::{self, StreamExt};
let results: Vec<_> = stream::iter(ports)
    .map(|p| scan_port(p))
    .buffer_unordered(100)
    .collect()
    .await;
```

### async-trait - Async in Traits
```toml
[dependencies]
async-trait = "0.1"
```
```rust
use async_trait::async_trait;

#[async_trait]
trait Scanner {
    async fn scan(&self) -> Vec<u16>;
}
```

---

## Testing

### assert_cmd - CLI Testing
```toml
[dev-dependencies]
assert_cmd = "2"
predicates = "3"
```
```rust
use assert_cmd::Command;
Command::cargo_bin("mytool")?
    .arg("--help")
    .assert()
    .success();
```

### mockall - Mocking
```toml
[dev-dependencies]
mockall = "0.11"
```
```rust
#[automock]
trait Database {
    fn get(&self, key: &str) -> Option<String>;
}
```

---

## Common Cargo.toml for Security Tools

```toml
[package]
name = "security-tool"
version = "0.1.0"
edition = "2021"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Networking
reqwest = { version = "0.11", features = ["json"] }

# CLI
clap = { version = "4", features = ["derive"] }
colored = "2"
indicatif = "0.17"

# Crypto
sha2 = "0.10"

# Parsing
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1"

# Files
walkdir = "2"

# Errors
anyhow = "1"
thiserror = "1"

# Logging
log = "0.4"
env_logger = "0.10"

# Time
chrono = "0.4"

[profile.release]
opt-level = 3
lto = true
strip = true
```

---

[← Back to Quick Reference](./README.md)
