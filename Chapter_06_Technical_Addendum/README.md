# Chapter 6: Technical Addendum

## Essential Crates Reference

This chapter provides a comprehensive reference for crates used throughout the Rust Security Bible.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CRATE CATEGORIES                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  NETWORKING          CRYPTO              PARSING            ASYNC            │
│  ──────────          ──────              ───────            ─────            │
│  • tokio             • sha2              • serde            • tokio          │
│  • reqwest           • aes-gcm           • nom              • async-std      │
│  • pnet              • rsa               • pest             • futures        │
│  • pcap              • x25519            • regex            • smol           │
│  • trust-dns         • argon2            • goblin           • async-trait    │
│                                                                              │
│  SYSTEM              CLI                 LOGGING            TESTING          │
│  ──────              ───                 ───────            ───────          │
│  • sysinfo           • clap              • log              • criterion      │
│  • nix               • dialoguer         • tracing          • proptest       │
│  • libc              • indicatif         • env_logger       • mockall        │
│  • procfs            • colored           • slog             • tempfile       │
│  • notify            • tabled            • flexi_logger     • assert_cmd     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Networking Crates

### 1.1 tokio - Async Runtime

```toml
[dependencies]
tokio = { version = "1.35", features = ["full"] }
```

```rust
//! Tokio is the most popular async runtime for Rust
//!
//! Key features:
//! - Async TCP/UDP sockets
//! - Async file I/O
//! - Timers and timeouts
//! - Task spawning
//! - Channels for inter-task communication

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn concurrent tasks
    let handle1 = tokio::spawn(async {
        // Task 1
        println!("Task 1 running");
    });

    let handle2 = tokio::spawn(async {
        // Task 2
        println!("Task 2 running");
    });

    // Wait for both
    let _ = tokio::join!(handle1, handle2);

    // TCP client with timeout
    let connect_future = TcpStream::connect("127.0.0.1:8080");
    match timeout(Duration::from_secs(5), connect_future).await {
        Ok(Ok(stream)) => println!("Connected!"),
        Ok(Err(e)) => println!("Connection failed: {}", e),
        Err(_) => println!("Connection timed out"),
    }

    Ok(())
}
```

### 1.2 reqwest - HTTP Client

```toml
[dependencies]
reqwest = { version = "0.11", features = ["json", "cookies", "rustls-tls"] }
```

```rust
//! reqwest provides a high-level HTTP client
//!
//! Features:
//! - Async and blocking modes
//! - JSON serialization
//! - Cookie support
//! - TLS (native-tls or rustls)
//! - Proxy support

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

async fn http_examples() -> Result<(), reqwest::Error> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("SecurityScanner/1.0")
        .build()?;

    // GET request
    let response = client.get("https://api.example.com/data")
        .header("Authorization", "Bearer token123")
        .send()
        .await?;

    let body = response.text().await?;
    println!("Response: {}", body);

    // POST with JSON
    let login = LoginRequest {
        username: "admin".to_string(),
        password: "password".to_string(),
    };

    let response: ApiResponse = client.post("https://api.example.com/login")
        .json(&login)
        .send()
        .await?
        .json()
        .await?;

    println!("Login success: {}", response.success);

    Ok(())
}
```

### 1.3 pnet - Low-Level Networking

```toml
[dependencies]
pnet = "0.34"
```

```rust
//! pnet provides low-level networking primitives
//!
//! Use cases:
//! - Raw packet capture
//! - Packet crafting
//! - Network interface enumeration
//! - Protocol implementation

use pnet::datalink::{self, NetworkInterface, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

fn capture_packets(interface_name: &str) {
    // Find the network interface
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Interface not found");

    // Create a channel to receive packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Error creating channel: {}", e),
    };

    println!("Capturing on interface: {}", interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();

                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        println!(
                            "{} -> {} ({})",
                            ipv4.get_source(),
                            ipv4.get_destination(),
                            ipv4.get_next_level_protocol()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}
```

---

## 2. Cryptography Crates

### 2.1 sha2 - SHA-2 Hash Functions

```toml
[dependencies]
sha2 = "0.10"
```

```rust
//! SHA-2 family of hash functions
//!
//! Includes: SHA-224, SHA-256, SHA-384, SHA-512

use sha2::{Sha256, Sha512, Digest};

fn hash_examples() {
    // SHA-256
    let mut hasher = Sha256::new();
    hasher.update(b"hello world");
    let result = hasher.finalize();
    println!("SHA-256: {:x}", result);

    // One-liner
    let hash = Sha256::digest(b"hello world");
    println!("SHA-256: {:x}", hash);

    // SHA-512
    let hash = Sha512::digest(b"hello world");
    println!("SHA-512: {:x}", hash);

    // Incremental hashing (for large files)
    let mut hasher = Sha256::new();
    hasher.update(b"part 1");
    hasher.update(b"part 2");
    hasher.update(b"part 3");
    let result = hasher.finalize();
    println!("Combined: {:x}", result);
}

// File hashing
use std::fs::File;
use std::io::{BufReader, Read};

fn hash_file(path: &str) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();

    let mut buffer = [0; 8192];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}
```

### 2.2 aes-gcm - Authenticated Encryption

```toml
[dependencies]
aes-gcm = "0.10"
rand = "0.8"
```

```rust
//! AES-GCM provides authenticated encryption
//!
//! Features:
//! - Confidentiality (encryption)
//! - Integrity (authentication tag)
//! - Associated data support

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;

fn aes_gcm_example() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random 256-bit key
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let cipher = Aes256Gcm::new(key);

    // Generate a random 96-bit nonce (NEVER reuse with same key!)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = b"Secret message to encrypt";

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .expect("Encryption failed");

    println!("Ciphertext: {:?}", ciphertext);

    // Decrypt
    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref())
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
```

### 2.3 argon2 - Password Hashing

```toml
[dependencies]
argon2 = "0.5"
password-hash = "0.5"
```

```rust
//! Argon2 is the recommended password hashing algorithm
//!
//! Winner of the Password Hashing Competition (2015)
//! Provides resistance against GPU/ASIC attacks

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

fn password_example() -> Result<(), Box<dyn std::error::Error>> {
    let password = b"hunter2";

    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);

    // Hash the password
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, &salt)?
        .to_string();

    println!("Hashed password: {}", password_hash);

    // Verify the password
    let parsed_hash = PasswordHash::new(&password_hash)?;

    // Correct password
    assert!(argon2.verify_password(b"hunter2", &parsed_hash).is_ok());

    // Wrong password
    assert!(argon2.verify_password(b"wrong", &parsed_hash).is_err());

    println!("Password verification successful!");

    Ok(())
}
```

---

## 3. Parsing Crates

### 3.1 serde - Serialization Framework

```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
```

```rust
//! serde is the standard serialization framework for Rust
//!
//! Supports: JSON, YAML, TOML, MessagePack, and many more

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    server: ServerConfig,
    database: DatabaseConfig,
    #[serde(default)]
    debug: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

fn default_timeout() -> u64 { 30 }

#[derive(Debug, Serialize, Deserialize)]
struct DatabaseConfig {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

fn serde_example() -> Result<(), Box<dyn std::error::Error>> {
    // JSON
    let json_str = r#"{
        "server": {
            "host": "0.0.0.0",
            "port": 8080
        },
        "database": {
            "url": "postgres://localhost/db",
            "password": "secret"
        }
    }"#;

    let config: Config = serde_json::from_str(json_str)?;
    println!("Config: {:?}", config);

    // Serialize to pretty JSON
    let json = serde_json::to_string_pretty(&config)?;
    println!("JSON:\n{}", json);

    // TOML
    let toml_str = r#"
    debug = true

    [server]
    host = "0.0.0.0"
    port = 8080
    timeout_secs = 60

    [database]
    url = "postgres://localhost/db"
    "#;

    let config: Config = toml::from_str(toml_str)?;
    println!("TOML Config: {:?}", config);

    Ok(())
}
```

### 3.2 regex - Regular Expressions

```toml
[dependencies]
regex = "1.10"
```

```rust
//! regex provides Perl-compatible regular expressions
//!
//! Features:
//! - Fast (uses finite automata)
//! - Unicode support
//! - Named capture groups

use regex::Regex;

fn regex_examples() {
    // Basic matching
    let re = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
    assert!(re.is_match("192.168.1.1"));
    assert!(!re.is_match("not.an.ip.address"));

    // Capture groups
    let re = Regex::new(r"(\d+)\.(\d+)\.(\d+)\.(\d+)").unwrap();
    if let Some(caps) = re.captures("192.168.1.1") {
        println!("Octet 1: {}", &caps[1]);
        println!("Octet 2: {}", &caps[2]);
        println!("Octet 3: {}", &caps[3]);
        println!("Octet 4: {}", &caps[4]);
    }

    // Named capture groups
    let re = Regex::new(
        r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    ).unwrap();

    if let Some(caps) = re.captures("2024-01-15") {
        println!("Year: {}", &caps["year"]);
        println!("Month: {}", &caps["month"]);
        println!("Day: {}", &caps["day"]);
    }

    // Find all matches
    let re = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
    let text = "Contact: alice@example.com or bob@test.org";

    for email in re.find_iter(text) {
        println!("Found email: {}", email.as_str());
    }

    // Replace
    let re = Regex::new(r"\bpassword\b").unwrap();
    let result = re.replace_all("password is password123", "[REDACTED]");
    println!("Redacted: {}", result);
}
```

### 3.3 goblin - Binary Parsing

```toml
[dependencies]
goblin = "0.7"
```

```rust
//! goblin parses PE, ELF, and Mach-O binaries
//!
//! Use cases:
//! - Malware analysis
//! - Binary inspection
//! - Security tooling

use goblin::Object;
use std::fs;

fn parse_binary(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let buffer = fs::read(path)?;

    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            println!("ELF binary detected");
            println!("  Entry point: 0x{:x}", elf.entry);
            println!("  Is 64-bit: {}", elf.is_64);
            println!("  Interpreter: {:?}", elf.interpreter);

            println!("\n  Sections:");
            for section in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
                println!("    {} (size: {} bytes)", name, section.sh_size);
            }

            println!("\n  Dynamic symbols:");
            for sym in &elf.dynsyms {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        println!("    {}", name);
                    }
                }
            }
        }
        Object::PE(pe) => {
            println!("PE binary detected");
            println!("  Is 64-bit: {}", pe.is_64);

            if let Some(optional) = pe.header.optional_header {
                println!("  Entry point: 0x{:x}", optional.standard_fields.address_of_entry_point);
            }

            println!("\n  Sections:");
            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name);
                println!("    {} (size: {} bytes)", name.trim_end_matches('\0'), section.size_of_raw_data);
            }

            println!("\n  Imports:");
            for import in &pe.imports {
                println!("    {} -> {}", import.dll, import.name);
            }
        }
        Object::Mach(mach) => {
            println!("Mach-O binary detected");
        }
        _ => {
            println!("Unknown or archive format");
        }
    }

    Ok(())
}
```

---

## 4. CLI Crates

### 4.1 clap - Command Line Parser

```toml
[dependencies]
clap = { version = "4.4", features = ["derive", "env"] }
```

```rust
//! clap is the most popular CLI parser for Rust
//!
//! Features:
//! - Derive macros for declarative CLIs
//! - Subcommands
//! - Environment variable support
//! - Shell completions

use clap::{Parser, Subcommand, Args, ValueEnum};

#[derive(Parser)]
#[command(name = "security-tool")]
#[command(about = "A comprehensive security tool")]
#[command(version = "1.0")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for vulnerabilities
    Scan(ScanArgs),
    /// Analyze a file
    Analyze {
        /// File to analyze
        #[arg(required = true)]
        file: String,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Generate a report
    Report {
        /// Report type
        #[arg(short, long)]
        report_type: String,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// Target to scan
    #[arg(required = true)]
    target: String,

    /// Port range
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Number of threads
    #[arg(short, long, default_value_t = 10)]
    threads: usize,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Xml,
}

fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        println!("Verbose mode enabled");
    }

    match cli.command {
        Commands::Scan(args) => {
            println!("Scanning {} on ports {} with {} threads",
                args.target, args.ports, args.threads);
        }
        Commands::Analyze { file, format } => {
            println!("Analyzing file: {}", file);
        }
        Commands::Report { report_type } => {
            println!("Generating {} report", report_type);
        }
    }
}
```

### 4.2 colored - Terminal Colors

```toml
[dependencies]
colored = "2.1"
```

```rust
//! colored provides easy terminal text coloring

use colored::*;

fn colored_output() {
    // Basic colors
    println!("{}", "This is red".red());
    println!("{}", "This is green".green());
    println!("{}", "This is blue".blue());

    // Styles
    println!("{}", "This is bold".bold());
    println!("{}", "This is italic".italic());
    println!("{}", "This is underlined".underline());

    // Combined
    println!("{}", "Bold and red".red().bold());

    // Background colors
    println!("{}", "White on black".white().on_black());

    // Security-focused output
    println!("{} Connection established", "[+]".green().bold());
    println!("{} Warning: weak cipher", "[!]".yellow().bold());
    println!("{} Error: connection refused", "[-]".red().bold());
    println!("{} Scanning port 80...", "[*]".cyan());
}
```

---

## 5. Cross-Compilation Guide

### 5.1 Setting Up Cross-Compilation

```bash
# Install cross-compilation targets
rustup target add x86_64-unknown-linux-musl
rustup target add x86_64-pc-windows-gnu
rustup target add aarch64-unknown-linux-gnu

# For Windows cross-compilation on Linux
sudo apt-get install mingw-w64

# For static Linux binaries
sudo apt-get install musl-tools
```

### 5.2 Cargo Configuration

```toml
# .cargo/config.toml

[target.x86_64-unknown-linux-musl]
linker = "musl-gcc"

[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"

[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
```

### 5.3 Building for Different Targets

```bash
# Static Linux binary (no glibc dependency)
cargo build --release --target x86_64-unknown-linux-musl

# Windows executable
cargo build --release --target x86_64-pc-windows-gnu

# ARM64 Linux
cargo build --release --target aarch64-unknown-linux-gnu
```

### 5.4 Using cross for Docker-Based Cross-Compilation

```bash
# Install cross
cargo install cross

# Build for various targets (uses Docker)
cross build --release --target x86_64-unknown-linux-musl
cross build --release --target x86_64-pc-windows-gnu
cross build --release --target armv7-unknown-linux-gnueabihf
```

---

## 6. Performance Optimization

### 6.1 Release Profile Configuration

```toml
# Cargo.toml

[profile.release]
opt-level = 3          # Maximum optimization
lto = true             # Link-time optimization
codegen-units = 1      # Better optimization, slower compile
panic = "abort"        # Smaller binary
strip = true           # Strip symbols
```

### 6.2 Benchmarking with Criterion

```toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "my_benchmark"
harness = false
```

```rust
// benches/my_benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_hash(c: &mut Criterion) {
    use sha2::{Sha256, Digest};

    let data = vec![0u8; 1024 * 1024]; // 1MB

    c.bench_function("sha256 1MB", |b| {
        b.iter(|| {
            let hash = Sha256::digest(black_box(&data));
            hash
        })
    });
}

criterion_group!(benches, benchmark_hash);
criterion_main!(benches);
```

---

## 7. Security Best Practices

### 7.1 Secure Memory Handling

```toml
[dependencies]
zeroize = { version = "1.7", features = ["derive"] }
secrecy = "0.8"
```

```rust
//! Secure handling of sensitive data

use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};

#[derive(ZeroizeOnDrop)]
struct Credentials {
    username: String,
    #[zeroize(skip)]  // Don't zeroize username
    password: String,
}

fn secure_memory_example() {
    // Secret wrapper prevents accidental logging
    let api_key = Secret::new("super_secret_key".to_string());

    // Must explicitly expose to use
    println!("Using key: {}", api_key.expose_secret());

    // Password is zeroed when dropped
    let mut password = String::from("hunter2");
    // ... use password ...
    password.zeroize();  // Memory is zeroed
}
```

### 7.2 Constant-Time Operations

```toml
[dependencies]
subtle = "2.5"
```

```rust
//! Constant-time operations prevent timing attacks

use subtle::{Choice, ConstantTimeEq};

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// For password verification
fn verify_token(provided: &[u8], stored: &[u8]) -> bool {
    if provided.len() != stored.len() {
        return false;
    }
    constant_time_compare(provided, stored)
}
```

---

## 8. Testing Strategies

### 8.1 Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    #[should_panic(expected = "divide by zero")]
    fn test_panic() {
        let _ = 1 / 0;
    }

    #[test]
    fn test_result() -> Result<(), String> {
        if true {
            Ok(())
        } else {
            Err("Test failed".to_string())
        }
    }
}
```

### 8.2 Integration Testing

```rust
// tests/integration_test.rs
use my_crate::*;

#[test]
fn test_full_workflow() {
    // Setup
    let scanner = Scanner::new();

    // Execute
    let result = scanner.scan("127.0.0.1");

    // Verify
    assert!(result.is_ok());
}
```

### 8.3 Property-Based Testing

```toml
[dev-dependencies]
proptest = "1.4"
```

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_parse_always_succeeds_for_valid_input(
        input in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
    ) {
        // If regex matches, parsing should work
        let _ = input.parse::<std::net::Ipv4Addr>();
    }

    #[test]
    fn test_encode_decode_roundtrip(data: Vec<u8>) {
        let encoded = base64::encode(&data);
        let decoded = base64::decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }
}
```

---

This chapter serves as a quick reference for the crates and techniques used throughout the Rust Security Bible. For detailed implementations, see the respective project directories.
