```
██████╗ ██╗   ██╗███████╗████████╗    ██████╗ ██╗██████╗ ██╗     ███████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝    ██╔══██╗██║██╔══██╗██║     ██╔════╝
██████╔╝██║   ██║███████╗   ██║       ██████╔╝██║██████╔╝██║     █████╗
██╔══██╗██║   ██║╚════██║   ██║       ██╔══██╗██║██╔══██╗██║     ██╔══╝
██║  ██║╚██████╔╝███████║   ██║       ██████╔╝██║██████╔╝███████╗███████╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝

███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝

         ████████╗██████╗  █████╗ ██╗███╗   ██╗██╗███╗   ██╗ ██████╗
         ╚══██╔══╝██╔══██╗██╔══██╗██║████╗  ██║██║████╗  ██║██╔════╝
            ██║   ██████╔╝███████║██║██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
            ██║   ██╔══██╗██╔══██║██║██║╚██╗██║██║██║╚██╗██║██║   ██║
            ██║   ██║  ██║██║  ██║██║██║ ╚████║██║██║ ╚████║╚██████╔╝
            ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
```

# THE RUST SECURITY BIBLE
## The Definitive Reference Guide
### From Zero to Security Professional - Complete Mastery

---

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   Version: 1.0 SECURITY TRAINING EDITION                                  ║
║   Last Updated: December 2025                                             ║
║   Focus: Automation, Red Team, Blue Team, Security Operations             ║
║   Projects: 50+ Hands-On Exercises (Basic → Expert)                       ║
║   Real-World Scenarios: Offensive & Defensive Security Training           ║
║                                                                           ║
║   For authorized security testing and education only.                     ║
║   Always obtain proper written authorization before testing.              ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

# MASTER TABLE OF CONTENTS

## QUICK NAVIGATION

| Section | Volume | Description |
|---------|--------|-------------|
| [Quick Start Guide](#quick-start-guide) | Intro | Get started with Rust in 15 minutes |
| [Chapter 1: Fundamentals](#chapter-1-rust-fundamentals) | Vol 1 | Core Rust concepts |
| [Chapter 2: Skill Levels](#chapter-2-skill-level-progression) | Vol 2 | Basic → Expert progression |
| [Chapter 3: Red Team](#chapter-3-red-team-rust) | Vol 3 | Offensive security with Rust |
| [Chapter 4: Blue Team](#chapter-4-blue-team-rust) | Vol 4 | Defensive security with Rust |
| [Chapter 5: Automation](#chapter-5-automation-mastery) | Vol 5 | System automation & DevOps |
| [Chapter 6: Technical Addendum](#chapter-6-technical-addendum) | Vol 6 | References & deep dives |
| [Chapter 7: GUI Development](#chapter-7-gui-development) | Vol 7 | Building security tool interfaces |
| [Chapter 8: Malware Analysis](#chapter-8-malware-analysis) | Vol 8 | Static & dynamic analysis tools |
| [Chapter 9: IDS Development](#chapter-9-ids-development) | Vol 9 | Network intrusion detection |
| [Chapter 10: Real World Scenarios](#chapter-10-real-world-scenarios) | Vol 10 | Practical security exercises |

---

## COMPLETE TABLE OF CONTENTS

### VOLUME 1: RUST FUNDAMENTALS
```
CHAPTER 1: RUST FUNDAMENTALS
├── Why Rust for Security?
│   ├── Memory Safety Without GC
│   ├── Zero-Cost Abstractions
│   ├── Fearless Concurrency
│   └── Cross-Platform Compilation
│
├── Development Environment
│   ├── Installing Rust (rustup)
│   ├── Cargo Package Manager
│   ├── IDE Setup (VS Code, CLion)
│   └── Essential Tools (clippy, rustfmt)
│
├── Core Syntax
│   ├── Variables & Mutability
│   ├── Data Types (Scalars & Compounds)
│   ├── Functions & Control Flow
│   └── Comments & Documentation
│
├── Ownership System (THE KEY TO RUST)
│   ├── What is Ownership?
│   ├── References & Borrowing
│   ├── The Slice Type
│   └── Ownership in Practice
│
├── Structs & Enums
│   ├── Defining Structs
│   ├── Method Syntax (impl blocks)
│   ├── Enums & Pattern Matching
│   └── Option & Result Types
│
└── Error Handling
    ├── Recoverable Errors (Result)
    ├── Unrecoverable Errors (panic!)
    ├── The ? Operator
    └── Custom Error Types
```

### VOLUME 2: SKILL LEVEL PROGRESSION
```
CHAPTER 2: SKILL LEVELS
├── Basic Level (B01-B15)
│   ├── B01: Hello Security World
│   ├── B02: Command-Line Arguments
│   ├── B03: File Operations
│   ├── B04: Environment Variables
│   ├── B05: Process Information
│   ├── B06: Simple HTTP Client
│   ├── B07: JSON Parsing
│   ├── B08: Base64 Encoding/Decoding
│   ├── B09: Hash Calculator (MD5/SHA)
│   ├── B10: Directory Walker
│   ├── B11: Simple Logger
│   ├── B12: Config File Parser
│   ├── B13: String Manipulation
│   ├── B14: Regex Basics
│   └── B15: Error Handling Patterns
│
├── Intermediate Level (I01-I15)
│   ├── I01: Network Scanner
│   ├── I02: Port Scanner
│   ├── I03: DNS Resolver
│   ├── I04: HTTP Server
│   ├── I05: File Integrity Monitor
│   ├── I06: Process Monitor
│   ├── I07: Log Parser & Analyzer
│   ├── I08: Async Operations
│   ├── I09: Multi-threading
│   ├── I10: Database Operations (SQLite)
│   ├── I11: REST API Client
│   ├── I12: WebSocket Client
│   ├── I13: System Information Collector
│   ├── I14: Binary File Analysis
│   └── I15: Memory Forensics Basics
│
├── Advanced Level (A01-A10)
│   ├── A01: Custom Protocol Parser
│   ├── A02: Packet Sniffer
│   ├── A03: Credential Harvester (Educational)
│   ├── A04: Reverse Shell Handler
│   ├── A05: C2 Framework Basics
│   ├── A06: PE/ELF Parser
│   ├── A07: Syscall Wrapper
│   ├── A08: Hooking Framework
│   ├── A09: YARA Rule Engine
│   └── A10: Sandbox Detection
│
└── Expert Level (E01-E05)
    ├── E01: Full C2 Infrastructure
    ├── E02: EDR Bypass Techniques
    ├── E03: Memory Injection Framework
    ├── E04: Kernel Module Development
    └── E05: Custom Implant Development
```

### VOLUME 3: RED TEAM RUST
```
CHAPTER 3: RED TEAM OPERATIONS
├── Reconnaissance
│   ├── Network Enumeration
│   ├── Service Detection
│   ├── Web Scraping
│   ├── OSINT Automation
│   └── Subdomain Enumeration
│
├── Exploitation
│   ├── Vulnerability Scanners
│   ├── Exploit Frameworks
│   ├── Buffer Overflow Tools
│   └── Web Exploitation
│
├── Post-Exploitation
│   ├── Privilege Escalation
│   ├── Lateral Movement
│   ├── Data Exfiltration
│   └── Credential Dumping
│
├── Persistence
│   ├── Scheduled Tasks
│   ├── Registry/Cron Persistence
│   ├── Service Creation
│   └── Bootkit Concepts
│
├── Evasion Techniques
│   ├── AMSI Bypass
│   ├── ETW Patching
│   ├── AV Evasion
│   └── EDR Bypass
│
└── MITRE ATT&CK Mapping
    └── Technique-to-Code Reference
```

### VOLUME 4: BLUE TEAM RUST
```
CHAPTER 4: BLUE TEAM OPERATIONS
├── Detection Engineering
│   ├── Log Analysis Tools
│   ├── SIEM Integration
│   ├── Threat Hunting Scripts
│   └── IOC Scanners
│
├── Forensics
│   ├── Memory Analysis
│   ├── Disk Forensics
│   ├── Network Forensics
│   └── Timeline Analysis
│
├── Hardening
│   ├── Configuration Auditors
│   ├── Vulnerability Scanners
│   ├── Compliance Checkers
│   └── Baseline Validators
│
├── Incident Response
│   ├── Artifact Collectors
│   ├── Triage Tools
│   ├── Evidence Preservation
│   └── Automated Response
│
└── Threat Intelligence
    ├── IOC Management
    ├── YARA Integration
    ├── Feed Processing
    └── Threat Scoring
```

### VOLUME 5: AUTOMATION MASTERY
```
CHAPTER 5: AUTOMATION
├── System Administration
│   ├── Service Managers
│   ├── User Management
│   ├── Backup Automation
│   └── System Monitoring
│
├── Network Automation
│   ├── Configuration Management
│   ├── Network Monitoring
│   ├── Traffic Analysis
│   └── Protocol Implementation
│
├── File Processing
│   ├── Batch Processing
│   ├── Data Transformation
│   ├── Report Generation
│   └── Archive Management
│
└── DevOps Integration
    ├── CI/CD Pipelines
    ├── Container Management
    ├── Infrastructure as Code
    └── Secrets Management
```

### VOLUME 6: TECHNICAL ADDENDUM
```
CHAPTER 6: TECHNICAL REFERENCE
├── Rust Ecosystem
│   ├── Essential Crates
│   ├── Security-Focused Libraries
│   └── Build Optimization
│
├── Cross-Compilation
│   ├── Windows from Linux
│   ├── Linux from Windows
│   ├── ARM Targets
│   └── Minimal Binaries
│
├── FFI & Interoperability
│   ├── C Bindings
│   ├── Python Integration
│   ├── Windows API
│   └── Linux Syscalls
│
├── Performance Optimization
│   ├── Profiling Tools
│   ├── Memory Optimization
│   └── Binary Size Reduction
│
└── Resources
    ├── Official Documentation
    ├── Security Crates
    ├── Learning Resources
    └── Community
```

---

# QUICK START GUIDE

## Install Rust in 5 Minutes

### Linux/macOS
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version
```

### Windows
```powershell
# Download and run rustup-init.exe from https://rustup.rs
# Or use winget:
winget install Rustlang.Rustup
```

### Verify Installation
```bash
rustc --version    # Compiler
cargo --version    # Package manager
rustup --version   # Toolchain manager
```

---

## Your First Security Tool (5 Minutes)

### Step 1: Create Project
```bash
cargo new hello_security
cd hello_security
```

### Step 2: Write Code
Replace `src/main.rs`:
```rust
use std::env;
use std::process::Command;

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║   RUST SECURITY TOOL - SYSTEM INFO     ║");
    println!("╚════════════════════════════════════════╝");

    // Get current user
    let user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| String::from("Unknown"));

    println!("\n[+] Current User: {}", user);

    // Get hostname
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| String::from("Unknown"));

    println!("[+] Hostname: {}", hostname);

    // Get current directory
    let cwd = env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| String::from("Unknown"));

    println!("[+] Working Directory: {}", cwd);

    // Get OS info
    println!("[+] OS: {}", env::consts::OS);
    println!("[+] Architecture: {}", env::consts::ARCH);

    println!("\n[*] Security reconnaissance complete!");
}
```

### Step 3: Add Dependency
Edit `Cargo.toml`:
```toml
[package]
name = "hello_security"
version = "0.1.0"
edition = "2021"

[dependencies]
hostname = "0.3"
```

### Step 4: Build & Run
```bash
cargo run
```

### Expected Output
```
╔════════════════════════════════════════╗
║   RUST SECURITY TOOL - SYSTEM INFO     ║
╚════════════════════════════════════════╝

[+] Current User: operator
[+] Hostname: workstation
[+] Working Directory: /home/operator/hello_security
[+] OS: linux
[+] Architecture: x86_64

[*] Security reconnaissance complete!
```

---

## Development Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                   RUST DEVELOPMENT CYCLE                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │     cargo new project_name     │
              │     Create new project         │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │     Edit src/main.rs           │
              │     Write your code            │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │     cargo check                │
              │     Fast syntax/type check     │
              └───────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                 Errors?             No Errors
                    │                   │
                    ▼                   ▼
              ┌──────────┐    ┌───────────────────┐
              │  Fix     │    │   cargo build     │
              │  Issues  │    │   Compile debug   │
              └──────────┘    └───────────────────┘
                    │                   │
                    └─────────►         ▼
                              ┌───────────────────┐
                              │   cargo run       │
                              │   Execute         │
                              └───────────────────┘
                                        │
                                        ▼
                              ┌───────────────────┐
                              │   cargo test      │
                              │   Run tests       │
                              └───────────────────┘
                                        │
                                        ▼
                              ┌───────────────────┐
                              │ cargo build       │
                              │ --release         │
                              │ Production build  │
                              └───────────────────┘
```

---

## Essential Cargo Commands

| Command | Purpose |
|---------|---------|
| `cargo new name` | Create new project |
| `cargo build` | Compile debug build |
| `cargo build --release` | Compile optimized build |
| `cargo run` | Build and run |
| `cargo check` | Fast type checking |
| `cargo test` | Run tests |
| `cargo doc --open` | Generate documentation |
| `cargo clippy` | Lint code |
| `cargo fmt` | Format code |
| `cargo add crate_name` | Add dependency |

---

# CHAPTER 1: RUST FUNDAMENTALS

## Why Rust for Security?

### Memory Safety Without Garbage Collection

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MEMORY SAFETY COMPARISON                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   C/C++              Java/Python              Rust                          │
│   ──────             ───────────              ────                          │
│   Manual Memory      Garbage                  Ownership System              │
│   Management         Collector                                              │
│                                                                              │
│   ❌ Buffer Overflow  ✅ No Buffer Overflow    ✅ No Buffer Overflow         │
│   ❌ Use After Free   ✅ No Use After Free     ✅ No Use After Free          │
│   ❌ Double Free      ✅ No Double Free        ✅ No Double Free             │
│   ❌ Null Pointer     ✅ Null Safety           ✅ No Null (Option<T>)        │
│   ✅ High Performance ❌ GC Pauses             ✅ High Performance           │
│   ✅ Low Level Access ❌ Limited Access        ✅ Low Level Access           │
│                                                                              │
│   For Security Tools: Rust gives you C-level performance with              │
│   memory safety guarantees - the best of both worlds.                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Tool Advantages

1. **No Runtime Vulnerabilities**: Buffer overflows, use-after-free eliminated at compile time
2. **Single Binary Deployment**: No runtime dependencies (unlike Python/Java)
3. **Cross-Platform**: Compile for Windows, Linux, macOS from single codebase
4. **High Performance**: Critical for network tools, parsers, scanners
5. **Safe Concurrency**: Thread safety guaranteed by compiler

---

## The Ownership System

**This is THE most important concept in Rust. Master this, master Rust.**

### The Three Rules of Ownership

```rust
// RULE 1: Each value has exactly one owner
let s1 = String::from("hello");  // s1 owns this String

// RULE 2: When owner goes out of scope, value is dropped
{
    let s2 = String::from("world");
    // s2 is valid here
}   // s2 goes out of scope, memory freed

// RULE 3: Only one owner at a time
let s3 = String::from("security");
let s4 = s3;  // s3's ownership MOVES to s4
// println!("{}", s3);  // ERROR! s3 no longer valid
println!("{}", s4);     // OK - s4 is the owner
```

### Borrowing: References Without Ownership

```rust
fn main() {
    let data = String::from("sensitive_data");

    // Immutable borrow - can have many
    let r1 = &data;
    let r2 = &data;
    println!("{} and {}", r1, r2);  // OK

    // Mutable borrow - can only have one
    let mut mutable_data = String::from("changeable");
    let r3 = &mut mutable_data;
    r3.push_str("_modified");
    // let r4 = &mut mutable_data;  // ERROR! Only one mutable ref

    println!("{}", r3);
}
```

### Visual Representation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OWNERSHIP VISUALIZATION                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   OWNERSHIP (Move)                  BORROWING (Reference)                   │
│   ─────────────────                 ──────────────────────                  │
│                                                                              │
│   let s1 = String::from("x");       let s1 = String::from("x");            │
│   let s2 = s1;                      let s2 = &s1;                          │
│                                                                              │
│   Stack:         Heap:              Stack:         Heap:                    │
│   ┌─────┐       ┌─────┐            ┌─────┐       ┌─────┐                   │
│   │ s1  │──X    │ "x" │            │ s1  │──────►│ "x" │                   │
│   └─────┘       └─────┘            └─────┘       └─────┘                   │
│   ┌─────┐          ▲               ┌─────┐          ▲                      │
│   │ s2  │──────────┘               │ s2  │──────────┘                      │
│   └─────┘                          └─────┘                                  │
│                                    (pointer to s1)                          │
│   s1 INVALID                       Both valid, s2 borrows                   │
│   s2 now owns                      s1 still owns                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Structs: Custom Data Types

### Defining and Using Structs

```rust
/// Represents a network target for scanning
#[derive(Debug, Clone)]
struct Target {
    ip: String,
    port: u16,
    service: Option<String>,
    is_open: bool,
}

impl Target {
    /// Creates a new Target
    fn new(ip: &str, port: u16) -> Self {
        Target {
            ip: ip.to_string(),
            port,
            service: None,
            is_open: false,
        }
    }

    /// Formats target as socket address
    fn socket_addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    /// Marks target as open with optional service
    fn mark_open(&mut self, service: Option<&str>) {
        self.is_open = true;
        self.service = service.map(String::from);
    }

    /// Returns display string for reporting
    fn report(&self) -> String {
        let status = if self.is_open { "OPEN" } else { "CLOSED" };
        let svc = self.service.as_deref().unwrap_or("unknown");
        format!("{:<15} {:>5} {:>8} {}", self.ip, self.port, status, svc)
    }
}

fn main() {
    let mut target = Target::new("192.168.1.1", 22);
    target.mark_open(Some("SSH"));
    println!("{}", target.report());
    // Output: 192.168.1.1        22     OPEN SSH
}
```

### Struct Patterns for Security Tools

```rust
/// Configuration struct with builder pattern
#[derive(Debug, Default)]
struct ScanConfig {
    targets: Vec<String>,
    ports: Vec<u16>,
    timeout_ms: u64,
    threads: usize,
    verbose: bool,
}

impl ScanConfig {
    fn new() -> Self {
        ScanConfig {
            timeout_ms: 1000,
            threads: 10,
            ..Default::default()
        }
    }

    fn targets(mut self, targets: Vec<String>) -> Self {
        self.targets = targets;
        self
    }

    fn ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    fn timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    fn verbose(mut self, v: bool) -> Self {
        self.verbose = v;
        self
    }
}

// Usage with builder pattern
fn main() {
    let config = ScanConfig::new()
        .targets(vec!["192.168.1.1".to_string()])
        .ports(vec![22, 80, 443])
        .timeout(500)
        .verbose(true);

    println!("{:?}", config);
}
```

---

## Enums and Pattern Matching

### Security-Relevant Enums

```rust
/// Represents the result of a port scan
#[derive(Debug, Clone)]
enum PortStatus {
    Open { service: Option<String>, banner: Option<String> },
    Closed,
    Filtered,
    Unknown,
}

/// Represents possible attack techniques
#[derive(Debug)]
enum AttackVector {
    Network { port: u16, protocol: String },
    Web { endpoint: String, method: String },
    Physical { location: String },
    Social { target_role: String },
}

/// Represents log severity levels
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl PortStatus {
    fn description(&self) -> &str {
        match self {
            PortStatus::Open { .. } => "Port is open and accepting connections",
            PortStatus::Closed => "Port is closed, host responded with RST",
            PortStatus::Filtered => "Port is filtered, no response received",
            PortStatus::Unknown => "Port status could not be determined",
        }
    }

    fn is_interesting(&self) -> bool {
        matches!(self, PortStatus::Open { .. } | PortStatus::Filtered)
    }
}

fn main() {
    let status = PortStatus::Open {
        service: Some("SSH".to_string()),
        banner: Some("OpenSSH_8.9".to_string()),
    };

    // Pattern matching with destructuring
    match &status {
        PortStatus::Open { service: Some(svc), banner } => {
            println!("[+] Open: {} ({:?})", svc, banner);
        }
        PortStatus::Open { service: None, .. } => {
            println!("[+] Open: unknown service");
        }
        PortStatus::Closed => println!("[-] Closed"),
        PortStatus::Filtered => println!("[?] Filtered"),
        PortStatus::Unknown => println!("[!] Unknown"),
    }
}
```

---

## Error Handling

### The Result Type

```rust
use std::fs::File;
use std::io::{self, Read};
use std::num::ParseIntError;

/// Custom error type for our security tool
#[derive(Debug)]
enum SecurityError {
    NetworkError(String),
    FileError(io::Error),
    ParseError(String),
    AuthenticationFailed,
    AccessDenied,
    Timeout,
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            SecurityError::FileError(e) => write!(f, "File error: {}", e),
            SecurityError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            SecurityError::AuthenticationFailed => write!(f, "Authentication failed"),
            SecurityError::AccessDenied => write!(f, "Access denied"),
            SecurityError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for SecurityError {}

// Convert io::Error to SecurityError
impl From<io::Error> for SecurityError {
    fn from(error: io::Error) -> Self {
        SecurityError::FileError(error)
    }
}

/// Reads a configuration file
fn read_config(path: &str) -> Result<String, SecurityError> {
    let mut file = File::open(path)?;  // ? operator with From trait
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Parses a port number from string
fn parse_port(s: &str) -> Result<u16, SecurityError> {
    s.parse::<u16>()
        .map_err(|e| SecurityError::ParseError(e.to_string()))
}

fn main() {
    // Using match for fine-grained control
    match read_config("config.toml") {
        Ok(contents) => println!("Config loaded: {} bytes", contents.len()),
        Err(SecurityError::FileError(e)) if e.kind() == io::ErrorKind::NotFound => {
            println!("Config file not found, using defaults");
        }
        Err(e) => eprintln!("Error: {}", e),
    }

    // Using if let for simple cases
    if let Ok(port) = parse_port("8080") {
        println!("Port: {}", port);
    }

    // Using unwrap_or_else for defaults
    let port = parse_port("invalid")
        .unwrap_or_else(|_| 80);
    println!("Using port: {}", port);
}
```

---

# CHAPTER 2: SKILL LEVEL PROGRESSION

## Learning Path Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       RUST SECURITY SKILL PROGRESSION                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  BASIC (B01-B15)           INTERMEDIATE (I01-I15)                           │
│  ════════════════          ═══════════════════════                          │
│  • Syntax mastery          • Networking                                     │
│  • File I/O                • Async/Await                                    │
│  • CLI tools               • Multi-threading                                │
│  • Basic parsing           • Database ops                                   │
│  • Error handling          • Protocol parsing                               │
│                                                                              │
│         │                           │                                        │
│         ▼                           ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │                    SKILL CHECKPOINT                               │       │
│  │  Can you build a multi-threaded port scanner with                │       │
│  │  JSON output and timeout handling? If yes, proceed.              │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                              │
│  ADVANCED (A01-A10)        EXPERT (E01-E05)                                 │
│  ══════════════════        ════════════════                                 │
│  • Raw sockets             • C2 frameworks                                  │
│  • Packet crafting         • EDR bypass                                     │
│  • Syscalls                • Memory injection                               │
│  • PE/ELF parsing          • Kernel development                             │
│  • Hook frameworks         • Custom implants                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Basic Level Projects (B01-B15)

### B01: Hello Security World

**Objective**: Understand Rust project structure and basic output.

**What You'll Learn**:
- Cargo project structure
- println! macro
- Basic formatting
- Main function

**The Code**:

```rust
// src/main.rs
// B01: Hello Security World
// Purpose: Introduction to Rust syntax and project structure

fn main() {
    // ASCII art banner - common in security tools
    let banner = r#"
    ╔═══════════════════════════════════════════╗
    ║     RUST SECURITY TRAINING - B01          ║
    ║     Hello Security World                  ║
    ╚═══════════════════════════════════════════╝
    "#;

    println!("{}", banner);

    // String variables
    let tool_name = "RustRecon";
    let version = "1.0.0";
    let author = "Security Student";

    // Formatted output
    println!("[*] Tool: {} v{}", tool_name, version);
    println!("[*] Author: {}", author);
    println!();

    // Different log levels (common pattern)
    println!("[+] Success message (action completed)");
    println!("[-] Failure message (action failed)");
    println!("[*] Info message (general information)");
    println!("[!] Warning message (attention needed)");
    println!("[?] Question/uncertain status");
    println!();

    // Security-style output
    let target = "192.168.1.1";
    let ports_found = 3;

    println!("═══════════════════════════════════════════");
    println!(" SCAN RESULTS");
    println!("═══════════════════════════════════════════");
    println!(" Target:     {}", target);
    println!(" Open Ports: {}", ports_found);
    println!("═══════════════════════════════════════════");
}
```

**Line-by-Line Breakdown**:

| Line | Code | Explanation |
|------|------|-------------|
| 1 | `fn main()` | Entry point - every Rust program starts here |
| 3-9 | `r#"..."#` | Raw string literal - no escaping needed |
| 11 | `println!` | Macro (!) for printing with newline |
| 14-16 | `let x = ...` | Variable binding (immutable by default) |
| 19 | `{}` | Format placeholder (like printf %s) |

**Red Team Perspective**:
- Consistent output formatting helps with log analysis
- ASCII banners can be used for tool identification
- Log levels help distinguish action types

**Blue Team Perspective**:
- Recognizing tool signatures in logs
- Output patterns can be IOCs
- Banner strings detectable in memory

**Exercise**:
1. Add your own ASCII art banner
2. Add a timestamp to the output
3. Add color using the `colored` crate

---

### B02: Command-Line Arguments

**Objective**: Parse and handle command-line arguments.

**What You'll Learn**:
- std::env for arguments
- Clap crate for CLI parsing
- Match expressions
- Input validation

**Cargo.toml**:
```toml
[package]
name = "b02_cli_args"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
```

**The Code**:

```rust
use clap::Parser;

/// B02: Security Tool CLI Parser
/// A demonstration of command-line argument handling for security tools
#[derive(Parser, Debug)]
#[command(name = "rustscan")]
#[command(author = "Security Student")]
#[command(version = "1.0")]
#[command(about = "A Rust-based network scanner", long_about = None)]
struct Args {
    /// Target IP address or hostname
    #[arg(short, long)]
    target: String,

    /// Ports to scan (comma-separated or range like 1-1000)
    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    /// Connection timeout in milliseconds
    #[arg(short = 'T', long, default_value_t = 1000)]
    timeout: u64,

    /// Number of concurrent threads
    #[arg(long, default_value_t = 100)]
    threads: usize,

    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Output format (text, json, csv)
    #[arg(short, long, default_value = "text")]
    output: String,
}

fn parse_port_range(port_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        let part = part.trim();

        if part.contains('-') {
            // Range like "1-1000"
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid range: {}", part));
            }

            let start: u16 = bounds[0].parse()
                .map_err(|_| format!("Invalid port: {}", bounds[0]))?;
            let end: u16 = bounds[1].parse()
                .map_err(|_| format!("Invalid port: {}", bounds[1]))?;

            if start > end {
                return Err(format!("Invalid range: {} > {}", start, end));
            }

            ports.extend(start..=end);
        } else {
            // Single port
            let port: u16 = part.parse()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }

    Ok(ports)
}

fn main() {
    let args = Args::parse();

    println!("╔════════════════════════════════════════╗");
    println!("║        RUSTSCAN - Port Scanner         ║");
    println!("╚════════════════════════════════════════╝");
    println!();

    // Parse ports
    let ports = match parse_port_range(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Error: {}", e);
            std::process::exit(1);
        }
    };

    // Validate output format
    let valid_formats = ["text", "json", "csv"];
    if !valid_formats.contains(&args.output.as_str()) {
        eprintln!("[!] Invalid output format. Use: text, json, csv");
        std::process::exit(1);
    }

    // Display configuration
    println!("[*] Configuration:");
    println!("    Target:  {}", args.target);
    println!("    Ports:   {} ports ({} to {})",
        ports.len(),
        ports.first().unwrap_or(&0),
        ports.last().unwrap_or(&0)
    );
    println!("    Timeout: {}ms", args.timeout);
    println!("    Threads: {}", args.threads);
    println!("    Output:  {}", args.output);
    println!("    Verbose: {}", args.verbose);
    println!();

    if args.verbose {
        println!("[+] Verbose mode enabled");
        println!("[*] Initializing scanner...");
    }

    println!("[*] Ready to scan (actual scanning not implemented in B02)");
}
```

**Usage Examples**:
```bash
# Basic usage
./rustscan -t 192.168.1.1

# Custom ports
./rustscan -t 192.168.1.1 -p 22,80,443

# Port range
./rustscan -t 192.168.1.1 -p 1-1000

# Full options
./rustscan -t 192.168.1.1 -p 1-65535 -T 500 --threads 200 -v -o json

# Help
./rustscan --help
```

**Red Team Perspective**:
- CLI tools need flexible input for different scenarios
- Port ranges allow targeted vs. comprehensive scans
- JSON output enables automation and chaining

**Blue Team Perspective**:
- Command-line arguments visible in process listings
- Can be logged via command-line auditing
- Arguments may contain sensitive info (targets, creds)

---

### B03: File Operations

**Objective**: Read, write, and manipulate files securely.

```rust
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

/// File operations for security tools
fn main() -> io::Result<()> {
    println!("╔════════════════════════════════════════╗");
    println!("║   B03: Secure File Operations          ║");
    println!("╚════════════════════════════════════════╝\n");

    // ═══════════════════════════════════════════
    // READING FILES
    // ═══════════════════════════════════════════

    // Method 1: Read entire file to string (for small files)
    println!("[*] Method 1: Read to String");
    let path = "/etc/passwd";
    match fs::read_to_string(path) {
        Ok(contents) => {
            println!("[+] Read {} bytes from {}", contents.len(), path);
            // Print first 3 lines
            for (i, line) in contents.lines().take(3).enumerate() {
                println!("    Line {}: {}", i + 1, line);
            }
        }
        Err(e) => println!("[-] Failed to read {}: {}", path, e),
    }
    println!();

    // Method 2: Buffered reading (for large files)
    println!("[*] Method 2: Buffered Reading");
    if let Ok(file) = File::open("/etc/hosts") {
        let reader = BufReader::new(file);
        for (i, line) in reader.lines().enumerate() {
            if let Ok(line) = line {
                if !line.starts_with('#') && !line.is_empty() {
                    println!("    Host entry {}: {}", i + 1, line);
                }
            }
        }
    }
    println!();

    // Method 3: Read binary file
    println!("[*] Method 3: Binary File Reading");
    match fs::read("/bin/ls") {
        Ok(bytes) => {
            println!("[+] Read {} bytes from /bin/ls", bytes.len());
            // Print first 16 bytes (ELF header)
            print!("    Magic bytes: ");
            for byte in bytes.iter().take(16) {
                print!("{:02x} ", byte);
            }
            println!();
        }
        Err(e) => println!("[-] Error: {}", e),
    }
    println!();

    // ═══════════════════════════════════════════
    // WRITING FILES
    // ═══════════════════════════════════════════

    println!("[*] Writing files...");

    // Create output directory
    let output_dir = "/tmp/rust_training";
    fs::create_dir_all(output_dir)?;

    // Write text file
    let log_path = format!("{}/scan_results.txt", output_dir);
    let mut file = File::create(&log_path)?;
    writeln!(file, "Scan Results")?;
    writeln!(file, "============")?;
    writeln!(file, "Target: 192.168.1.1")?;
    writeln!(file, "Ports: 22, 80, 443")?;
    writeln!(file, "Status: Complete")?;
    println!("[+] Created: {}", log_path);

    // Append to existing file
    let mut file = OpenOptions::new()
        .append(true)
        .open(&log_path)?;
    writeln!(file, "\n--- Additional Entry ---")?;
    writeln!(file, "Timestamp: {}", chrono_lite_timestamp())?;
    println!("[+] Appended to: {}", log_path);

    // Write binary file
    let bin_path = format!("{}/data.bin", output_dir);
    let binary_data: Vec<u8> = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
    fs::write(&bin_path, &binary_data)?;
    println!("[+] Created binary: {}", bin_path);
    println!();

    // ═══════════════════════════════════════════
    // FILE METADATA & PERMISSIONS
    // ═══════════════════════════════════════════

    println!("[*] File Metadata");
    if let Ok(metadata) = fs::metadata(&log_path) {
        println!("    File: {}", log_path);
        println!("    Size: {} bytes", metadata.len());
        println!("    Type: {}", if metadata.is_file() { "File" } else { "Dir" });

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            println!("    Mode: {:o}", mode & 0o777);
        }
    }
    println!();

    // ═══════════════════════════════════════════
    // DIRECTORY OPERATIONS
    // ═══════════════════════════════════════════

    println!("[*] Directory Listing");
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        println!("    {:>10} bytes  {}",
            metadata.len(),
            path.file_name().unwrap_or_default().to_string_lossy()
        );
    }
    println!();

    // ═══════════════════════════════════════════
    // SECURE FILE HANDLING
    // ═══════════════════════════════════════════

    println!("[*] Security Considerations:");
    println!("    - Always validate paths (prevent path traversal)");
    println!("    - Check permissions before writing");
    println!("    - Use temp files for sensitive data");
    println!("    - Securely delete sensitive files");

    // Demonstrate path validation
    let user_input = "../../../etc/passwd";
    if is_path_safe(user_input) {
        println!("    Path '{}' is safe", user_input);
    } else {
        println!("    [!] Path '{}' is potentially malicious", user_input);
    }

    Ok(())
}

/// Simple timestamp without external crate
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// Check if a path is safe (no path traversal)
fn is_path_safe(path: &str) -> bool {
    let path = Path::new(path);

    // Check for path traversal attempts
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return false;
        }
    }

    // Check for absolute paths if we want relative only
    if path.is_absolute() {
        return false;
    }

    true
}
```

---

[Continue to B04-B15 in Chapter_02_Skill_Levels/01_Basic/]

---

# CHAPTER 3: RED TEAM RUST

## Reconnaissance Tools

### Network Scanner Foundation

```rust
use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::thread;

/// A simple but educational port scanner
/// For authorized security testing only
#[derive(Debug, Clone)]
struct ScanResult {
    ip: String,
    port: u16,
    status: PortStatus,
    response_time_ms: u64,
}

#[derive(Debug, Clone)]
enum PortStatus {
    Open,
    Closed,
    Filtered,
}

struct Scanner {
    target: String,
    ports: Vec<u16>,
    timeout: Duration,
    threads: usize,
}

impl Scanner {
    fn new(target: &str, ports: Vec<u16>) -> Self {
        Scanner {
            target: target.to_string(),
            ports,
            timeout: Duration::from_millis(1000),
            threads: 100,
        }
    }

    fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout = Duration::from_millis(ms);
        self
    }

    fn with_threads(mut self, n: usize) -> Self {
        self.threads = n;
        self
    }

    fn scan(&self) -> Vec<ScanResult> {
        let results = Arc::new(Mutex::new(Vec::new()));
        let ports = Arc::new(self.ports.clone());
        let target = self.target.clone();
        let timeout = self.timeout;

        let mut handles = vec![];
        let chunk_size = (self.ports.len() / self.threads).max(1);

        for chunk in self.ports.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let target = target.clone();
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                for port in chunk {
                    let addr = format!("{}:{}", target, port);
                    let start = std::time::Instant::now();

                    let status = match addr.to_socket_addrs() {
                        Ok(mut addrs) => {
                            if let Some(addr) = addrs.next() {
                                match TcpStream::connect_timeout(&addr, timeout) {
                                    Ok(_) => PortStatus::Open,
                                    Err(e) => {
                                        if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                            PortStatus::Closed
                                        } else {
                                            PortStatus::Filtered
                                        }
                                    }
                                }
                            } else {
                                PortStatus::Filtered
                            }
                        }
                        Err(_) => PortStatus::Filtered,
                    };

                    let elapsed = start.elapsed().as_millis() as u64;

                    if matches!(status, PortStatus::Open) {
                        let mut results = results.lock().unwrap();
                        results.push(ScanResult {
                            ip: target.clone(),
                            port,
                            status,
                            response_time_ms: elapsed,
                        });
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = results.lock().unwrap().clone();
        results.sort_by_key(|r| r.port);
        results
    }
}

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║   RUST PORT SCANNER - Educational      ║");
    println!("╚════════════════════════════════════════╝\n");

    let target = "127.0.0.1";  // Only scan localhost for demo
    let ports: Vec<u16> = (1..=1024).collect();

    println!("[*] Target: {}", target);
    println!("[*] Ports: 1-1024");
    println!("[*] Starting scan...\n");

    let scanner = Scanner::new(target, ports)
        .with_timeout(500)
        .with_threads(50);

    let start = std::time::Instant::now();
    let results = scanner.scan();
    let elapsed = start.elapsed();

    println!("PORT     STATE    RESPONSE");
    println!("────────────────────────────");

    for result in &results {
        println!("{:<8} {:?}  {}ms",
            result.port,
            result.status,
            result.response_time_ms
        );
    }

    println!("\n[*] Scan complete: {} open ports found", results.len());
    println!("[*] Time elapsed: {:.2}s", elapsed.as_secs_f64());
}
```

**MITRE ATT&CK Mapping**:
- T1046: Network Service Scanning
- T1018: Remote System Discovery

---

## Post-Exploitation Framework

### System Enumeration Module

```rust
use std::collections::HashMap;
use std::process::Command;
use std::env;

/// System enumeration for post-exploitation
/// Educational purposes - authorized testing only
struct SystemEnumerator {
    data: HashMap<String, String>,
}

impl SystemEnumerator {
    fn new() -> Self {
        SystemEnumerator {
            data: HashMap::new(),
        }
    }

    fn enumerate(&mut self) {
        self.get_user_info();
        self.get_system_info();
        self.get_network_info();
        self.get_process_info();
    }

    fn get_user_info(&mut self) {
        // Current user
        let user = env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "Unknown".to_string());
        self.data.insert("user".to_string(), user);

        // Home directory
        let home = env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .unwrap_or_else(|_| "Unknown".to_string());
        self.data.insert("home".to_string(), home);

        // Check for elevated privileges
        #[cfg(unix)]
        {
            let uid = unsafe { libc::getuid() };
            self.data.insert("uid".to_string(), uid.to_string());
            self.data.insert("is_root".to_string(), (uid == 0).to_string());
        }
    }

    fn get_system_info(&mut self) {
        self.data.insert("os".to_string(), env::consts::OS.to_string());
        self.data.insert("arch".to_string(), env::consts::ARCH.to_string());

        // Hostname
        if let Ok(output) = Command::new("hostname").output() {
            let hostname = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_string();
            self.data.insert("hostname".to_string(), hostname);
        }

        // Kernel version (Linux)
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("uname").arg("-r").output() {
                let kernel = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_string();
                self.data.insert("kernel".to_string(), kernel);
            }
        }
    }

    fn get_network_info(&mut self) {
        // Get IP addresses
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("ip")
                .args(["addr", "show"])
                .output()
            {
                let ip_info = String::from_utf8_lossy(&output.stdout);
                // Parse for inet addresses (simplified)
                let ips: Vec<&str> = ip_info
                    .lines()
                    .filter(|l| l.contains("inet ") && !l.contains("127.0.0.1"))
                    .collect();
                self.data.insert("network_interfaces".to_string(),
                    format!("{} found", ips.len()));
            }
        }
    }

    fn get_process_info(&mut self) {
        // Current PID
        self.data.insert("pid".to_string(),
            std::process::id().to_string());

        // Parent PID (Unix)
        #[cfg(unix)]
        {
            let ppid = unsafe { libc::getppid() };
            self.data.insert("ppid".to_string(), ppid.to_string());
        }
    }

    fn report(&self) -> String {
        let mut report = String::new();
        report.push_str("╔════════════════════════════════════════╗\n");
        report.push_str("║      SYSTEM ENUMERATION REPORT         ║\n");
        report.push_str("╚════════════════════════════════════════╝\n\n");

        let sections = [
            ("User Information", vec!["user", "home", "uid", "is_root"]),
            ("System Information", vec!["os", "arch", "hostname", "kernel"]),
            ("Network Information", vec!["network_interfaces"]),
            ("Process Information", vec!["pid", "ppid"]),
        ];

        for (section, keys) in sections {
            report.push_str(&format!("═══ {} ═══\n", section));
            for key in keys {
                if let Some(value) = self.data.get(key) {
                    report.push_str(&format!("  {}: {}\n", key, value));
                }
            }
            report.push('\n');
        }

        report
    }
}

fn main() {
    let mut enumerator = SystemEnumerator::new();
    enumerator.enumerate();
    println!("{}", enumerator.report());
}
```

---

# CHAPTER 4: BLUE TEAM RUST

## Detection Engineering

### File Integrity Monitor

```rust
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration};
use sha2::{Sha256, Digest};

/// File Integrity Monitor for detecting unauthorized changes
/// Blue Team defensive tool
#[derive(Debug, Clone)]
struct FileRecord {
    path: PathBuf,
    hash: String,
    size: u64,
    modified: SystemTime,
}

struct IntegrityMonitor {
    baseline: HashMap<PathBuf, FileRecord>,
    watch_paths: Vec<PathBuf>,
}

impl IntegrityMonitor {
    fn new() -> Self {
        IntegrityMonitor {
            baseline: HashMap::new(),
            watch_paths: Vec::new(),
        }
    }

    fn add_watch_path<P: AsRef<Path>>(&mut self, path: P) {
        self.watch_paths.push(path.as_ref().to_path_buf());
    }

    fn calculate_hash<P: AsRef<Path>>(path: P) -> Result<String, std::io::Error> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn create_baseline(&mut self) -> Result<usize, std::io::Error> {
        self.baseline.clear();
        let mut count = 0;

        for watch_path in &self.watch_paths.clone() {
            self.scan_directory(watch_path, &mut count)?;
        }

        Ok(count)
    }

    fn scan_directory(&mut self, path: &Path, count: &mut usize) -> Result<(), std::io::Error> {
        if path.is_file() {
            self.add_file_to_baseline(path)?;
            *count += 1;
        } else if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();

                if entry_path.is_file() {
                    self.add_file_to_baseline(&entry_path)?;
                    *count += 1;
                } else if entry_path.is_dir() {
                    self.scan_directory(&entry_path, count)?;
                }
            }
        }
        Ok(())
    }

    fn add_file_to_baseline(&mut self, path: &Path) -> Result<(), std::io::Error> {
        let metadata = fs::metadata(path)?;
        let hash = Self::calculate_hash(path)?;

        let record = FileRecord {
            path: path.to_path_buf(),
            hash,
            size: metadata.len(),
            modified: metadata.modified()?,
        };

        self.baseline.insert(path.to_path_buf(), record);
        Ok(())
    }

    fn check_integrity(&self) -> Vec<IntegrityAlert> {
        let mut alerts = Vec::new();

        // Check for modified or deleted files
        for (path, baseline_record) in &self.baseline {
            if !path.exists() {
                alerts.push(IntegrityAlert {
                    path: path.clone(),
                    alert_type: AlertType::Deleted,
                    details: "File no longer exists".to_string(),
                });
                continue;
            }

            if let Ok(current_hash) = Self::calculate_hash(path) {
                if current_hash != baseline_record.hash {
                    alerts.push(IntegrityAlert {
                        path: path.clone(),
                        alert_type: AlertType::Modified,
                        details: format!(
                            "Hash changed from {} to {}",
                            &baseline_record.hash[..16],
                            &current_hash[..16]
                        ),
                    });
                }
            }
        }

        // Check for new files
        for watch_path in &self.watch_paths {
            self.find_new_files(watch_path, &mut alerts);
        }

        alerts
    }

    fn find_new_files(&self, path: &Path, alerts: &mut Vec<IntegrityAlert>) {
        if path.is_file() && !self.baseline.contains_key(path) {
            alerts.push(IntegrityAlert {
                path: path.to_path_buf(),
                alert_type: AlertType::Created,
                details: "New file detected".to_string(),
            });
        } else if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    self.find_new_files(&entry.path(), alerts);
                }
            }
        }
    }
}

#[derive(Debug)]
enum AlertType {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug)]
struct IntegrityAlert {
    path: PathBuf,
    alert_type: AlertType,
    details: String,
}

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║   FILE INTEGRITY MONITOR               ║");
    println!("╚════════════════════════════════════════╝\n");

    let mut monitor = IntegrityMonitor::new();

    // Add paths to monitor
    monitor.add_watch_path("/tmp/rust_training");

    // Create baseline
    println!("[*] Creating baseline...");
    match monitor.create_baseline() {
        Ok(count) => println!("[+] Baseline created: {} files indexed\n", count),
        Err(e) => {
            eprintln!("[-] Error creating baseline: {}", e);
            return;
        }
    }

    // Check integrity
    println!("[*] Checking file integrity...\n");
    let alerts = monitor.check_integrity();

    if alerts.is_empty() {
        println!("[+] No integrity violations detected");
    } else {
        println!("[!] {} integrity alerts detected:\n", alerts.len());
        for alert in &alerts {
            let severity = match alert.alert_type {
                AlertType::Created => "[NEW]",
                AlertType::Modified => "[MOD]",
                AlertType::Deleted => "[DEL]",
            };
            println!("{} {} - {}", severity, alert.path.display(), alert.details);
        }
    }
}
```

---

### Process Monitor

```rust
use std::collections::HashMap;
use std::process::Command;

/// Process monitoring for threat detection
#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cmdline: String,
    user: String,
}

struct ProcessMonitor {
    baseline: HashMap<u32, ProcessInfo>,
    suspicious_patterns: Vec<String>,
}

impl ProcessMonitor {
    fn new() -> Self {
        ProcessMonitor {
            baseline: HashMap::new(),
            suspicious_patterns: vec![
                "nc -e".to_string(),
                "bash -i".to_string(),
                "/dev/tcp/".to_string(),
                "python -c".to_string(),
                "powershell -enc".to_string(),
                "certutil -urlcache".to_string(),
            ],
        }
    }

    fn get_processes(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("ps")
                .args(["aux", "--no-headers"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 11 {
                        let pid: u32 = parts[1].parse().unwrap_or(0);
                        let user = parts[0].to_string();
                        let name = parts[10].to_string();
                        let cmdline = parts[10..].join(" ");

                        processes.push(ProcessInfo {
                            pid,
                            name,
                            cmdline,
                            user,
                        });
                    }
                }
            }
        }

        processes
    }

    fn check_suspicious(&self, process: &ProcessInfo) -> Option<String> {
        let cmdline_lower = process.cmdline.to_lowercase();

        for pattern in &self.suspicious_patterns {
            if cmdline_lower.contains(&pattern.to_lowercase()) {
                return Some(format!("Matches pattern: {}", pattern));
            }
        }

        None
    }

    fn scan(&self) -> Vec<(ProcessInfo, String)> {
        let mut findings = Vec::new();
        let processes = self.get_processes();

        for process in processes {
            if let Some(reason) = self.check_suspicious(&process) {
                findings.push((process, reason));
            }
        }

        findings
    }
}

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║      PROCESS MONITOR - Blue Team       ║");
    println!("╚════════════════════════════════════════╝\n");

    let monitor = ProcessMonitor::new();

    println!("[*] Scanning running processes...\n");
    let findings = monitor.scan();

    if findings.is_empty() {
        println!("[+] No suspicious processes detected");
    } else {
        println!("[!] {} suspicious processes found:\n", findings.len());
        for (process, reason) in &findings {
            println!("PID: {} | User: {} | Cmd: {}",
                process.pid, process.user, process.cmdline);
            println!("    Reason: {}\n", reason);
        }
    }
}
```

---

# CHAPTER 5: AUTOMATION MASTERY

## System Administration Tools

### Service Manager

```rust
use std::process::{Command, ExitStatus};

/// Cross-platform service management
enum ServiceAction {
    Start,
    Stop,
    Restart,
    Status,
}

struct ServiceManager {
    name: String,
}

impl ServiceManager {
    fn new(name: &str) -> Self {
        ServiceManager {
            name: name.to_string(),
        }
    }

    #[cfg(target_os = "linux")]
    fn execute(&self, action: ServiceAction) -> Result<String, String> {
        let action_str = match action {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
            ServiceAction::Status => "status",
        };

        let output = Command::new("systemctl")
            .args([action_str, &self.name])
            .output()
            .map_err(|e| format!("Failed to execute: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            Ok(stdout.to_string())
        } else {
            Err(stderr.to_string())
        }
    }

    fn is_active(&self) -> bool {
        if let Ok(result) = self.execute(ServiceAction::Status) {
            result.contains("active (running)")
        } else {
            false
        }
    }
}

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║      SERVICE MANAGER                   ║");
    println!("╚════════════════════════════════════════╝\n");

    let services = ["sshd", "nginx", "docker"];

    println!("{:<15} STATUS", "SERVICE");
    println!("─────────────────────────");

    for svc in &services {
        let manager = ServiceManager::new(svc);
        let status = if manager.is_active() {
            "● Active"
        } else {
            "○ Inactive"
        };
        println!("{:<15} {}", svc, status);
    }
}
```

---

# CHAPTER 6: TECHNICAL ADDENDUM

## Essential Security Crates

| Crate | Purpose | Use Case |
|-------|---------|----------|
| `tokio` | Async runtime | Network tools, concurrent ops |
| `reqwest` | HTTP client | Web scanning, API interaction |
| `clap` | CLI parsing | All command-line tools |
| `serde` | Serialization | JSON/YAML config, output |
| `sha2` | SHA hashing | File integrity, checksums |
| `aes` | AES encryption | Secure communications |
| `ring` | Cryptography | TLS, signatures |
| `pcap` | Packet capture | Network monitoring |
| `goblin` | Binary parsing | PE/ELF analysis |
| `windows` | Windows API | Windows-specific tools |

## Cross-Compilation

### Linux → Windows
```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install linker
sudo apt install mingw-w64

# Build
cargo build --target x86_64-pc-windows-gnu --release
```

### Minimal Binary Size
```toml
# Cargo.toml
[profile.release]
opt-level = "z"     # Size optimization
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit
panic = "abort"     # No unwinding
strip = true        # Strip symbols
```

---

## Learning Resources

### Official
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Rustlings](https://github.com/rust-lang/rustlings)

### Security-Focused
- [Black Hat Rust](https://github.com/skerkour/black-hat-rust)
- [RustSec Advisory Database](https://rustsec.org/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)

---

## Legal Notice

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                           IMPORTANT NOTICE                                 ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  This training material is for AUTHORIZED SECURITY TESTING and           ║
║  EDUCATIONAL PURPOSES only.                                               ║
║                                                                           ║
║  Before using any techniques described:                                   ║
║  1. Obtain WRITTEN authorization from system owners                       ║
║  2. Document scope and rules of engagement                                ║
║  3. Operate within legal boundaries of your jurisdiction                  ║
║  4. Follow responsible disclosure practices                               ║
║                                                                           ║
║  Unauthorized access to computer systems is ILLEGAL.                      ║
║  The authors assume no liability for misuse of this material.             ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

# CHAPTER 7: GUI DEVELOPMENT

## Overview

Build graphical interfaces for security tools using Rust GUI frameworks.

### Recommended Frameworks

| Framework | Best For | Complexity |
|-----------|----------|------------|
| **egui/eframe** | Quick tools, cross-platform | Low |
| **iced** | Beautiful native apps | Medium |
| **Tauri** | Web-based UIs, complex apps | Medium |
| **gtk-rs** | Linux native apps | High |

## Quick Start with egui

```rust
use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    eframe::run_native(
        "Security Tool",
        eframe::NativeOptions::default(),
        Box::new(|_| Box::new(MyApp::default())),
    )
}

struct MyApp {
    target: String,
    results: Vec<String>,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            target: String::new(),
            results: Vec::new(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Security Scanner");

            ui.horizontal(|ui| {
                ui.label("Target:");
                ui.text_edit_singleline(&mut self.target);
                if ui.button("Scan").clicked() {
                    self.results.push(format!("Scanning {}...", self.target));
                }
            });

            for result in &self.results {
                ui.label(result);
            }
        });
    }
}
```

## GUI Projects

| ID | Name | Description |
|----|------|-------------|
| G01 | Hello GUI | Basic window and widgets |
| G02 | Forms & Input | Text fields, buttons, validation |
| G06 | Port Scanner GUI | Visual port scanning tool |
| G11 | Google Dorking | Template-based query builder |
| G12 | Multi-Tool Launcher | Launch and manage multiple tools |

## Key Concepts

### Immediate Mode GUI
- UI rebuilt every frame
- State stored in your structs
- Simple mental model

### Threading for Long Operations
```rust
use std::sync::mpsc::{channel, Receiver};
use std::thread;

// Spawn background work
let (tx, rx) = channel();
thread::spawn(move || {
    // Do work...
    tx.send("Result".to_string()).unwrap();
});

// In update(), check for results:
while let Ok(msg) = rx.try_recv() {
    self.results.push(msg);
}
```

### Clipboard Operations
```rust
use arboard::Clipboard;

let mut clipboard = Clipboard::new().unwrap();
clipboard.set_text("Copied!").unwrap();
```

### Open URLs in Browser
```rust
open::that("https://example.com").unwrap();
```

---

See [Chapter_07_GUI_Development](Chapter_07_GUI_Development/) for complete projects including:
- Google Dorking Interface with templates
- Multi-tool launcher with process management
- Security dashboards and monitoring tools

---

[Continue to detailed chapters in respective folders]
