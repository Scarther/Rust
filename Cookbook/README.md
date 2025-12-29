# Rust Security Cookbook

## Overview

Quick, copy-paste recipes for common security programming tasks. Each recipe is self-contained and battle-tested.

---

## Recipe Categories

| Category | Description |
|----------|-------------|
| [Networking](#networking-recipes) | TCP, UDP, HTTP, DNS |
| [Cryptography](#cryptography-recipes) | Hashing, encryption, signatures |
| [File Operations](#file-operation-recipes) | Reading, writing, parsing |
| [System Information](#system-information-recipes) | Processes, users, environment |
| [Parsing](#parsing-recipes) | JSON, YAML, binary, logs |
| [CLI Tools](#cli-tool-recipes) | Arguments, colors, progress |
| [Concurrency](#concurrency-recipes) | Threads, async, parallelism |
| [Security Checks](#security-check-recipes) | Validation, sanitization |

---

## Networking Recipes

### Recipe: TCP Connect Scan

```rust
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

fn check_port(target: &str, port: u16, timeout_ms: u64) -> bool {
    let addr: SocketAddr = format!("{}:{}", target, port)
        .parse()
        .expect("Invalid address");

    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
}

fn main() {
    let target = "127.0.0.1";
    let ports = [22, 80, 443, 8080];

    for port in ports {
        if check_port(target, port, 500) {
            println!("Port {} is OPEN", port);
        }
    }
}
```

### Recipe: Async Port Scanner with Tokio

```rust
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use tokio::sync::Semaphore;

async fn scan_port(target: &str, port: u16, timeout_ms: u64) -> Option<u16> {
    let addr = format!("{}:{}", target, port);

    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Some(port),
        _ => None,
    }
}

#[tokio::main]
async fn main() {
    let target = "127.0.0.1";
    let ports: Vec<u16> = (1..=1024).collect();
    let semaphore = Arc::new(Semaphore::new(100)); // Limit concurrent connections

    let mut handles = Vec::new();

    for port in ports {
        let sem = semaphore.clone();
        let target = target.to_string();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_port(&target, port, 500).await
        }));
    }

    let mut open_ports = Vec::new();
    for handle in handles {
        if let Ok(Some(port)) = handle.await {
            open_ports.push(port);
        }
    }

    println!("Open ports: {:?}", open_ports);
}
```

### Recipe: HTTP GET Request

```rust
// Cargo.toml: reqwest = { version = "0.11", features = ["blocking"] }

use reqwest::blocking::Client;

fn http_get(url: &str) -> Result<String, reqwest::Error> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (compatible; SecurityScanner/1.0)")
        .build()?;

    let response = client.get(url).send()?;
    let body = response.text()?;
    Ok(body)
}

fn main() {
    match http_get("https://httpbin.org/get") {
        Ok(body) => println!("Response: {}", body),
        Err(e) => println!("Error: {}", e),
    }
}
```

### Recipe: Async HTTP with Headers

```rust
// Cargo.toml: reqwest = { version = "0.11", features = ["json"] }

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT};

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("CustomScanner/1.0"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let response = client
        .get("https://api.example.com/data")
        .header("X-Custom-Header", "value")
        .send()
        .await?;

    println!("Status: {}", response.status());
    println!("Headers: {:?}", response.headers());
    println!("Body: {}", response.text().await?);

    Ok(())
}
```

### Recipe: DNS Lookup

```rust
use std::net::ToSocketAddrs;

fn resolve_hostname(hostname: &str) -> Vec<std::net::IpAddr> {
    format!("{}:0", hostname)
        .to_socket_addrs()
        .map(|iter| iter.map(|addr| addr.ip()).collect())
        .unwrap_or_default()
}

fn main() {
    let host = "google.com";
    let ips = resolve_hostname(host);
    println!("{} resolves to: {:?}", host, ips);
}
```

### Recipe: Banner Grabbing

```rust
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn grab_banner(target: &str, port: u16) -> Option<String> {
    let addr = format!("{}:{}", target, port);

    let mut stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(3)
    ).ok()?;

    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;

    // Send probe for HTTP
    if port == 80 || port == 8080 {
        stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").ok()?;
    }

    let mut buffer = vec![0u8; 1024];
    let n = stream.read(&mut buffer).ok()?;

    String::from_utf8_lossy(&buffer[..n])
        .lines()
        .next()
        .map(|s| s.to_string())
}

fn main() {
    if let Some(banner) = grab_banner("127.0.0.1", 22) {
        println!("Banner: {}", banner);
    }
}
```

---

## Cryptography Recipes

### Recipe: SHA-256 Hash

```rust
// Cargo.toml: sha2 = "0.10"

use sha2::{Sha256, Digest};

fn sha256_string(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn sha256_file(path: &str) -> std::io::Result<String> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn main() {
    println!("Hash: {}", sha256_string("hello world"));
}
```

### Recipe: MD5 Hash (for compatibility)

```rust
// Cargo.toml: md-5 = "0.10", hex = "0.4"

use md5::{Md5, Digest};

fn md5_hash(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn main() {
    let hash = md5_hash("password123");
    println!("MD5: {}", hash);  // 482c811da5d5b4bc6d497ffa98491e38
}
```

### Recipe: AES-256-GCM Encryption

```rust
// Cargo.toml: aes-gcm = "0.10", rand = "0.8"

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher.decrypt(nonce, ciphertext)
}

fn main() {
    let key = [0u8; 32]; // Use a real key!
    let plaintext = b"Secret message";

    let encrypted = encrypt(&key, plaintext).unwrap();
    let decrypted = decrypt(&key, &encrypted).unwrap();

    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}
```

### Recipe: Password Hashing with Argon2

```rust
// Cargo.toml: argon2 = "0.5", rand = "0.8"

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn main() {
    let password = "correct horse battery staple";
    let hash = hash_password(password);
    println!("Hash: {}", hash);

    let valid = verify_password(password, &hash);
    println!("Valid: {}", valid);
}
```

### Recipe: Base64 Encode/Decode

```rust
// Cargo.toml: base64 = "0.21"

use base64::{Engine as _, engine::general_purpose};

fn encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(encoded)
}

fn main() {
    let original = b"Hello, World!";
    let encoded = encode(original);
    println!("Encoded: {}", encoded);  // SGVsbG8sIFdvcmxkIQ==

    let decoded = decode(&encoded).unwrap();
    println!("Decoded: {}", String::from_utf8_lossy(&decoded));
}
```

---

## File Operation Recipes

### Recipe: Read File to String

```rust
use std::fs;

fn read_file(path: &str) -> Result<String, std::io::Error> {
    fs::read_to_string(path)
}

fn main() {
    match read_file("config.txt") {
        Ok(contents) => println!("{}", contents),
        Err(e) => eprintln!("Error: {}", e),
    }
}
```

### Recipe: Read File Line by Line

```rust
use std::fs::File;
use std::io::{BufRead, BufReader};

fn process_lines(path: &str) -> std::io::Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        println!("{}: {}", line_num + 1, line);
    }

    Ok(())
}
```

### Recipe: Walk Directory Tree

```rust
// Cargo.toml: walkdir = "2"

use walkdir::WalkDir;

fn find_files(path: &str, extension: &str) -> Vec<String> {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == extension))
        .map(|e| e.path().display().to_string())
        .collect()
}

fn main() {
    let rust_files = find_files(".", "rs");
    for file in rust_files {
        println!("{}", file);
    }
}
```

### Recipe: Watch File for Changes

```rust
// Cargo.toml: notify = "6"

use notify::{Watcher, RecursiveMode, Result};
use std::path::Path;

fn watch_file(path: &str) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = notify::recommended_watcher(move |res| {
        tx.send(res).unwrap();
    })?;

    watcher.watch(Path::new(path), RecursiveMode::NonRecursive)?;

    println!("Watching {}...", path);

    for res in rx {
        match res {
            Ok(event) => println!("Event: {:?}", event),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    Ok(())
}
```

---

## Parsing Recipes

### Recipe: Parse JSON

```rust
// Cargo.toml: serde = { version = "1", features = ["derive"] }, serde_json = "1"

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    host: String,
    port: u16,
    enabled: bool,
}

fn parse_json(json_str: &str) -> Result<Config, serde_json::Error> {
    serde_json::from_str(json_str)
}

fn to_json(config: &Config) -> String {
    serde_json::to_string_pretty(config).unwrap()
}

fn main() {
    let json = r#"{"host": "127.0.0.1", "port": 8080, "enabled": true}"#;

    let config: Config = parse_json(json).unwrap();
    println!("{:?}", config);

    println!("{}", to_json(&config));
}
```

### Recipe: Parse Command Line Arguments

```rust
// Cargo.toml: clap = { version = "4", features = ["derive"] }

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "scanner")]
#[command(about = "A network scanner")]
struct Args {
    /// Target IP or hostname
    #[arg(short, long)]
    target: String,

    /// Port range (e.g., 1-1000)
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Timeout in milliseconds
    #[arg(short = 'T', long, default_value = "1000")]
    timeout: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    println!("Target: {}", args.target);
    println!("Ports: {}", args.ports);
    println!("Timeout: {}ms", args.timeout);
    println!("Verbose: {}", args.verbose);
}
```

### Recipe: Parse Log Files with Regex

```rust
// Cargo.toml: regex = "1"

use regex::Regex;

#[derive(Debug)]
struct LogEntry {
    timestamp: String,
    level: String,
    message: String,
}

fn parse_log_line(line: &str) -> Option<LogEntry> {
    let re = Regex::new(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\w+)\] (.+)$").ok()?;

    re.captures(line).map(|caps| LogEntry {
        timestamp: caps[1].to_string(),
        level: caps[2].to_string(),
        message: caps[3].to_string(),
    })
}

fn main() {
    let log_line = "[2024-01-15 10:30:45] [ERROR] Connection failed";

    if let Some(entry) = parse_log_line(log_line) {
        println!("{:?}", entry);
    }
}
```

---

## CLI Tool Recipes

### Recipe: Colored Output

```rust
// Cargo.toml: colored = "2"

use colored::*;

fn main() {
    println!("{}", "Success!".green());
    println!("{}", "Warning!".yellow());
    println!("{}", "Error!".red().bold());
    println!("{}", "Info".blue().italic());

    // Security tool style
    println!("{} Scanning target...", "[*]".blue());
    println!("{} Port 80 is open", "[+]".green());
    println!("{} Port 443 timed out", "[-]".yellow());
    println!("{} Connection refused", "[!]".red());
}
```

### Recipe: Progress Bar

```rust
// Cargo.toml: indicatif = "0.17"

use indicatif::{ProgressBar, ProgressStyle};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let total = 100;
    let pb = ProgressBar::new(total);

    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    for _ in 0..total {
        pb.inc(1);
        sleep(Duration::from_millis(50));
    }

    pb.finish_with_message("Done!");
}
```

---

## Security Check Recipes

### Recipe: Validate IP Address

```rust
use std::net::{IpAddr, Ipv4Addr};

fn is_valid_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

fn is_private_ip(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local()
        }
        Ok(IpAddr::V6(ip)) => ip.is_loopback(),
        Err(_) => false,
    }
}

fn main() {
    println!("Valid: {}", is_valid_ip("192.168.1.1"));    // true
    println!("Valid: {}", is_valid_ip("999.999.999.999")); // false
    println!("Private: {}", is_private_ip("192.168.1.1")); // true
    println!("Private: {}", is_private_ip("8.8.8.8"));     // false
}
```

### Recipe: Sanitize User Input

```rust
fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .take(255)
        .collect()
}

fn sanitize_for_shell(input: &str) -> String {
    // Remove or escape dangerous characters
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_' || *c == '/')
        .collect()
}

fn main() {
    let dangerous = "../../etc/passwd; rm -rf /";
    println!("Sanitized: {}", sanitize_filename(dangerous));
    // Output: "..etcpasswd rm -rf "
}
```

---

## Quick Copy-Paste Index

| Task | Jump To |
|------|---------|
| Port scan | [TCP Connect Scan](#recipe-tcp-connect-scan) |
| HTTP request | [HTTP GET Request](#recipe-http-get-request) |
| Hash file | [SHA-256 Hash](#recipe-sha-256-hash) |
| Encrypt data | [AES-256-GCM](#recipe-aes-256-gcm-encryption) |
| Parse JSON | [Parse JSON](#recipe-parse-json) |
| CLI args | [Command Line Arguments](#recipe-parse-command-line-arguments) |
| Progress bar | [Progress Bar](#recipe-progress-bar) |
| Walk directory | [Walk Directory Tree](#recipe-walk-directory-tree) |

---

[← Back to Main](../README.md)
