//! # Service Scanner
//!
//! An advanced service detection tool with banner grabbing, version detection,
//! and protocol-specific probes.
//!
//! ## Rust Concepts Demonstrated:
//! - **Async/Await**: Tokio-based asynchronous operations
//! - **Pin and Polling**: Low-level async concepts
//! - **Type Aliases**: Simplifying complex types
//! - **Associated Types**: Traits with associated types
//! - **Box<dyn Error>**: Type-erased error handling
//! - **Async Trait Pattern**: Async methods in traits

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Service Scanner - Advanced network service detection
///
/// # INTERMEDIATE RUST CONCEPTS:
///
/// 1. **Async/Await**:
///    Rust's async model is based on futures. `async fn` returns a Future,
///    and `await` drives it to completion without blocking the thread.
///
/// 2. **Pin<Box<dyn Future>>**:
///    Futures that borrow data must be pinned in memory.
///    Pin ensures the future won't be moved while being polled.
///
/// 3. **Type Aliases**:
///    `type Result<T> = std::result::Result<T, Box<dyn Error>>`
///    Simplifies complex type signatures for readability.
///
/// 4. **Associated Types**:
///    Traits can define types that implementations must specify.
///    `trait Iterator { type Item; fn next(&mut self) -> Option<Self::Item>; }`
#[derive(Parser)]
#[command(name = "service_scanner")]
#[command(author = "Security Researcher")]
#[command(version = "1.0")]
#[command(about = "Detect services and grab banners from network hosts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Scan target for services
    Scan {
        /// Target IP or network (CIDR notation)
        #[arg(short, long)]
        target: String,

        /// Ports to scan (comma-separated or range)
        #[arg(short, long, default_value = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017")]
        ports: String,

        /// Connection timeout in milliseconds
        #[arg(long, default_value = "3000")]
        timeout: u64,

        /// Maximum concurrent connections
        #[arg(short, long, default_value = "100")]
        concurrency: usize,

        /// Perform banner grabbing
        #[arg(short, long)]
        banner: bool,

        /// Perform version detection
        #[arg(short, long)]
        version: bool,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        output: OutputFormat,

        /// Export results to file
        #[arg(short, long)]
        export: Option<String>,
    },

    /// Probe specific service
    Probe {
        /// Target host
        #[arg(short, long)]
        target: String,

        /// Target port
        #[arg(short, long)]
        port: u16,

        /// Protocol to probe
        #[arg(short = 'P', long, value_enum)]
        protocol: Protocol,

        /// Connection timeout in milliseconds
        #[arg(long, default_value = "5000")]
        timeout: u64,
    },

    /// Show known service signatures
    Signatures {
        /// Filter by port
        #[arg(short, long)]
        port: Option<u16>,

        /// Filter by name
        #[arg(short, long)]
        name: Option<String>,
    },
}

/// Output format
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

/// Supported protocols for probing
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Protocol {
    Http,
    Https,
    Ssh,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Mysql,
    Postgres,
    Redis,
    Mongodb,
    Telnet,
}

// ============================================================================
// TYPE ALIASES
// ============================================================================

/// Type alias for scan results
///
/// # TYPE ALIAS:
/// Simplifies complex type signatures. This alias means:
/// "A vector of tuples containing socket address and scan result"
type ScanResults = Vec<(SocketAddr, ScanResult)>;

/// Type alias for banner data
type Banner = Option<String>;

// ============================================================================
// LAZY STATIC - Service signatures
// ============================================================================

lazy_static! {
    /// Known service signatures for banner matching
    static ref SERVICE_SIGNATURES: HashMap<&'static str, Vec<ServiceSignature>> = {
        let mut m = HashMap::new();

        // SSH signatures
        m.insert("ssh", vec![
            ServiceSignature::new("OpenSSH", r"SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)", Some("openssh")),
            ServiceSignature::new("Dropbear", r"SSH-[\d.]+-dropbear[_\s]*([\d.]+)?", Some("dropbear")),
            ServiceSignature::new("libssh", r"SSH-[\d.]+-libssh[_\s]*([\d.]+)?", Some("libssh")),
        ]);

        // HTTP signatures
        m.insert("http", vec![
            ServiceSignature::new("Apache", r"Apache/([\d.]+)", Some("apache")),
            ServiceSignature::new("nginx", r"nginx/([\d.]+)", Some("nginx")),
            ServiceSignature::new("IIS", r"Microsoft-IIS/([\d.]+)", Some("iis")),
            ServiceSignature::new("LiteSpeed", r"LiteSpeed", Some("litespeed")),
            ServiceSignature::new("Tomcat", r"Apache-Coyote/([\d.]+)", Some("tomcat")),
        ]);

        // Database signatures
        m.insert("mysql", vec![
            ServiceSignature::new("MySQL", r"(\d+\.\d+\.\d+)-MySQL", Some("mysql")),
            ServiceSignature::new("MariaDB", r"(\d+\.\d+\.\d+)-MariaDB", Some("mariadb")),
        ]);

        m.insert("postgres", vec![
            ServiceSignature::new("PostgreSQL", r"PostgreSQL\s+([\d.]+)", Some("postgresql")),
        ]);

        m.insert("ftp", vec![
            ServiceSignature::new("vsftpd", r"vsftpd\s+([\d.]+)", Some("vsftpd")),
            ServiceSignature::new("ProFTPD", r"ProFTPD\s+([\d.]+)", Some("proftpd")),
            ServiceSignature::new("Pure-FTPd", r"Pure-FTPd", Some("pure-ftpd")),
        ]);

        m.insert("smtp", vec![
            ServiceSignature::new("Postfix", r"Postfix", Some("postfix")),
            ServiceSignature::new("Sendmail", r"Sendmail", Some("sendmail")),
            ServiceSignature::new("Exim", r"Exim\s+([\d.]+)", Some("exim")),
        ]);

        m
    };

    /// Common ports to service mapping
    static ref PORT_SERVICES: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(21, "ftp");
        m.insert(22, "ssh");
        m.insert(23, "telnet");
        m.insert(25, "smtp");
        m.insert(53, "dns");
        m.insert(80, "http");
        m.insert(110, "pop3");
        m.insert(111, "rpc");
        m.insert(135, "msrpc");
        m.insert(139, "netbios");
        m.insert(143, "imap");
        m.insert(443, "https");
        m.insert(445, "smb");
        m.insert(993, "imaps");
        m.insert(995, "pop3s");
        m.insert(1433, "mssql");
        m.insert(1521, "oracle");
        m.insert(3306, "mysql");
        m.insert(3389, "rdp");
        m.insert(5432, "postgres");
        m.insert(5900, "vnc");
        m.insert(6379, "redis");
        m.insert(8080, "http-proxy");
        m.insert(8443, "https-alt");
        m.insert(27017, "mongodb");
        m
    };
}

/// Service signature for identification
#[derive(Debug, Clone)]
struct ServiceSignature {
    name: &'static str,
    pattern: Regex,
    product: Option<&'static str>,
}

impl ServiceSignature {
    fn new(name: &'static str, pattern: &str, product: Option<&'static str>) -> Self {
        Self {
            name,
            pattern: Regex::new(pattern).unwrap(),
            product,
        }
    }

    fn matches(&self, banner: &str) -> Option<ServiceMatch> {
        self.pattern.captures(banner).map(|caps| {
            ServiceMatch {
                name: self.name.to_string(),
                version: caps.get(1).map(|m| m.as_str().to_string()),
                product: self.product.map(|s| s.to_string()),
            }
        })
    }
}

/// Matched service information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceMatch {
    name: String,
    version: Option<String>,
    product: Option<String>,
}

/// Result of scanning a single port
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanResult {
    port: u16,
    state: PortState,
    service: String,
    banner: Option<String>,
    version: Option<ServiceMatch>,
    response_time_ms: u64,
}

/// Port state
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

impl PortState {
    fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        }
    }

    fn color(&self) -> colored::Color {
        match self {
            PortState::Open => colored::Color::Green,
            PortState::Closed => colored::Color::Red,
            PortState::Filtered => colored::Color::Yellow,
        }
    }
}

/// Protocol probe definitions
///
/// # ASSOCIATED TYPES PATTERN:
/// While not using associated types directly here, the pattern would be:
/// ```rust
/// trait Probe {
///     type Response;  // Associated type
///     fn probe(&self) -> Self::Response;
/// }
/// ```
struct ProtocolProbe {
    protocol: Protocol,
    data: Vec<u8>,
    tls: bool,
}

impl ProtocolProbe {
    fn http() -> Self {
        Self {
            protocol: Protocol::Http,
            data: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n".to_vec(),
            tls: false,
        }
    }

    fn ssh() -> Self {
        Self {
            protocol: Protocol::Ssh,
            data: Vec::new(), // SSH sends banner first
            tls: false,
        }
    }

    fn ftp() -> Self {
        Self {
            protocol: Protocol::Ftp,
            data: Vec::new(), // FTP sends banner first
            tls: false,
        }
    }

    fn smtp() -> Self {
        Self {
            protocol: Protocol::Smtp,
            data: b"EHLO scanner\r\n".to_vec(),
            tls: false,
        }
    }

    fn mysql() -> Self {
        Self {
            protocol: Protocol::Mysql,
            data: Vec::new(), // MySQL sends greeting packet
            tls: false,
        }
    }

    fn redis() -> Self {
        Self {
            protocol: Protocol::Redis,
            data: b"*1\r\n$4\r\nPING\r\n".to_vec(),
            tls: false,
        }
    }

    fn for_port(port: u16) -> Self {
        match port {
            21 => Self::ftp(),
            22 => Self::ssh(),
            25 | 587 => Self::smtp(),
            80 | 8080 => Self::http(),
            3306 => Self::mysql(),
            6379 => Self::redis(),
            _ => Self::http(), // Default to HTTP probe
        }
    }
}

/// Service Scanner implementation
///
/// # ASYNC PATTERNS:
/// Uses Tokio for async I/O, with semaphore-based concurrency limiting.
struct ServiceScanner {
    timeout: Duration,
    concurrency: usize,
    grab_banner: bool,
    detect_version: bool,
}

impl ServiceScanner {
    fn new(timeout_ms: u64, concurrency: usize, grab_banner: bool, detect_version: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            concurrency,
            grab_banner,
            detect_version,
        }
    }

    /// Scan multiple targets and ports
    ///
    /// # ASYNC STREAM PROCESSING:
    /// Uses futures::stream for concurrent async operations with backpressure.
    async fn scan(&self, targets: Vec<IpAddr>, ports: Vec<u16>) -> ScanResults {
        let total = targets.len() * ports.len();

        println!(
            "{} Scanning {} targets, {} ports ({} total)",
            "[*]".blue(),
            targets.len(),
            ports.len(),
            total
        );

        let progress = ProgressBar::new(total as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Semaphore for limiting concurrent connections
        // # SEMAPHORE PATTERN:
        // Limits the number of concurrent async operations
        let semaphore = Arc::new(Semaphore::new(self.concurrency));

        // Create all scan tasks
        let mut tasks = Vec::new();
        for target in &targets {
            for port in &ports {
                let sem = Arc::clone(&semaphore);
                let addr = SocketAddr::new(*target, *port);
                let timeout = self.timeout;
                let grab_banner = self.grab_banner;
                let detect_version = self.detect_version;
                let progress = progress.clone();

                // Spawn async task for each target:port
                tasks.push(tokio::spawn(async move {
                    // Acquire semaphore permit before proceeding
                    let _permit = sem.acquire().await.unwrap();
                    let result = scan_port(addr, timeout, grab_banner, detect_version).await;
                    progress.inc(1);
                    (addr, result)
                }));
            }
        }

        // Collect results
        let mut results = Vec::new();
        for task in tasks {
            if let Ok((addr, result)) = task.await {
                if result.state == PortState::Open {
                    results.push((addr, result));
                }
            }
        }

        progress.finish_with_message("Scan complete");

        results
    }
}

/// Scan a single port
///
/// # ASYNC/AWAIT:
/// This function is async - it returns a Future that must be awaited.
/// The function doesn't block; it yields control when waiting for I/O.
async fn scan_port(
    addr: SocketAddr,
    timeout_duration: Duration,
    grab_banner: bool,
    detect_version: bool,
) -> ScanResult {
    let start = std::time::Instant::now();
    let port = addr.port();

    // Get default service name for port
    let default_service = PORT_SERVICES
        .get(&port)
        .copied()
        .unwrap_or("unknown");

    // Try to connect with timeout
    let connect_result = timeout(timeout_duration, TcpStream::connect(addr)).await;

    match connect_result {
        Ok(Ok(mut stream)) => {
            let response_time = start.elapsed().as_millis() as u64;

            let mut banner = None;
            let mut version = None;

            if grab_banner {
                banner = grab_service_banner(&mut stream, port, timeout_duration).await;

                if detect_version {
                    if let Some(ref banner_text) = banner {
                        version = identify_service(banner_text, default_service);
                    }
                }
            }

            ScanResult {
                port,
                state: PortState::Open,
                service: default_service.to_string(),
                banner,
                version,
                response_time_ms: response_time,
            }
        }
        Ok(Err(_)) => {
            // Connection refused - port closed
            ScanResult {
                port,
                state: PortState::Closed,
                service: default_service.to_string(),
                banner: None,
                version: None,
                response_time_ms: start.elapsed().as_millis() as u64,
            }
        }
        Err(_) => {
            // Timeout - port filtered
            ScanResult {
                port,
                state: PortState::Filtered,
                service: default_service.to_string(),
                banner: None,
                version: None,
                response_time_ms: timeout_duration.as_millis() as u64,
            }
        }
    }
}

/// Grab service banner
///
/// # ASYNC READ/WRITE:
/// AsyncReadExt and AsyncWriteExt traits provide async versions of
/// read/write operations. They don't block the thread while waiting.
async fn grab_service_banner(
    stream: &mut TcpStream,
    port: u16,
    timeout_duration: Duration,
) -> Banner {
    let probe = ProtocolProbe::for_port(port);
    let mut buffer = vec![0u8; 4096];

    // Some protocols send banner immediately, others need a probe
    let result = if probe.data.is_empty() {
        // Wait for server to send data
        timeout(timeout_duration, stream.read(&mut buffer)).await
    } else {
        // Send probe first
        if stream.write_all(&probe.data).await.is_err() {
            return None;
        }
        timeout(timeout_duration, stream.read(&mut buffer)).await
    };

    match result {
        Ok(Ok(n)) if n > 0 => {
            // Clean up banner - handle both text and binary
            let banner = if buffer[..n].iter().all(|&b| b.is_ascii() || b == 0) {
                String::from_utf8_lossy(&buffer[..n])
                    .trim()
                    .lines()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" | ")
            } else {
                // Binary data - show hex preview
                format!("(binary) {}", hex::encode(&buffer[..n.min(32)]))
            };

            if banner.is_empty() {
                None
            } else {
                Some(banner.chars().take(200).collect())
            }
        }
        _ => None,
    }
}

/// Identify service from banner
fn identify_service(banner: &str, service_type: &str) -> Option<ServiceMatch> {
    // Try service-specific signatures
    if let Some(signatures) = SERVICE_SIGNATURES.get(service_type) {
        for sig in signatures {
            if let Some(matched) = sig.matches(banner) {
                return Some(matched);
            }
        }
    }

    // Try all signatures
    for signatures in SERVICE_SIGNATURES.values() {
        for sig in signatures {
            if let Some(matched) = sig.matches(banner) {
                return Some(matched);
            }
        }
    }

    None
}

/// Parse port specification
fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].parse().context("Invalid port range start")?;
                let end: u16 = range[1].parse().context("Invalid port range end")?;
                ports.extend(start..=end);
            }
        } else {
            let port: u16 = part.parse().context("Invalid port number")?;
            ports.push(port);
        }
    }

    Ok(ports)
}

/// Parse target specification
fn parse_targets(spec: &str) -> Result<Vec<IpAddr>> {
    if spec.contains('/') {
        // CIDR notation
        let network: IpNetwork = spec.parse().context("Invalid CIDR notation")?;
        Ok(network.iter().collect())
    } else {
        // Single IP
        let ip: IpAddr = spec.parse().context("Invalid IP address")?;
        Ok(vec![ip])
    }
}

/// Display scan results
fn display_results(results: &ScanResults, format: OutputFormat) {
    match format {
        OutputFormat::Text => display_text(results),
        OutputFormat::Json => display_json(results),
        OutputFormat::Csv => display_csv(results),
    }
}

fn display_text(results: &ScanResults) {
    if results.is_empty() {
        println!("\n{} No open ports found", "[!]".yellow());
        return;
    }

    // Group by host
    let mut by_host: HashMap<IpAddr, Vec<&ScanResult>> = HashMap::new();
    for (addr, result) in results {
        by_host.entry(addr.ip()).or_default().push(result);
    }

    for (host, ports) in &by_host {
        println!("\n{}", "═".repeat(70).cyan());
        println!("{} {}", "Host:".cyan().bold(), host);
        println!("{}", "═".repeat(70).cyan());

        println!(
            "\n{:<8} {:<12} {:<15} {}",
            "PORT".dimmed(),
            "STATE".dimmed(),
            "SERVICE".dimmed(),
            "VERSION/BANNER".dimmed()
        );
        println!("{}", "─".repeat(70));

        for result in ports {
            let state_colored = result.state.as_str().color(result.state.color());

            let version_info = if let Some(ref ver) = result.version {
                format!(
                    "{} {}",
                    ver.name,
                    ver.version.as_deref().unwrap_or("")
                )
            } else if let Some(ref banner) = result.banner {
                banner.chars().take(40).collect()
            } else {
                String::new()
            };

            println!(
                "{:<8} {:<12} {:<15} {}",
                format!("{}/tcp", result.port),
                state_colored,
                result.service,
                version_info.dimmed()
            );
        }
    }

    println!("\n{}", "═".repeat(70).cyan());
    println!("Total: {} open ports found", results.len());
}

fn display_json(results: &ScanResults) {
    let output: Vec<_> = results
        .iter()
        .map(|(addr, result)| {
            serde_json::json!({
                "host": addr.ip().to_string(),
                "port": result.port,
                "state": result.state.as_str(),
                "service": result.service,
                "banner": result.banner,
                "version": result.version,
                "response_time_ms": result.response_time_ms,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn display_csv(results: &ScanResults) {
    println!("host,port,state,service,version,banner,response_time_ms");

    for (addr, result) in results {
        let version = result
            .version
            .as_ref()
            .map(|v| format!("{} {}", v.name, v.version.as_deref().unwrap_or("")))
            .unwrap_or_default();

        println!(
            "{},{},{},{},{},{},{}",
            addr.ip(),
            result.port,
            result.state.as_str(),
            result.service,
            version,
            result.banner.as_deref().unwrap_or("").replace(',', ";"),
            result.response_time_ms
        );
    }
}

/// Export results to file
async fn export_results(results: &ScanResults, path: &str, format: OutputFormat) -> Result<()> {
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    let content = match format {
        OutputFormat::Json => {
            let output: Vec<_> = results
                .iter()
                .map(|(addr, result)| {
                    serde_json::json!({
                        "host": addr.ip().to_string(),
                        "port": result.port,
                        "state": result.state.as_str(),
                        "service": result.service,
                        "banner": result.banner,
                        "version": result.version,
                    })
                })
                .collect();
            serde_json::to_string_pretty(&output)?
        }
        OutputFormat::Csv => {
            let mut csv = String::from("host,port,state,service,version,banner\n");
            for (addr, result) in results {
                let version = result
                    .version
                    .as_ref()
                    .map(|v| v.name.clone())
                    .unwrap_or_default();
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    addr.ip(),
                    result.port,
                    result.state.as_str(),
                    result.service,
                    version,
                    result.banner.as_deref().unwrap_or("").replace(',', ";")
                ));
            }
            csv
        }
        OutputFormat::Text => {
            let mut text = String::new();
            for (addr, result) in results {
                text.push_str(&format!(
                    "{} - {}/tcp {} ({})\n",
                    addr.ip(),
                    result.port,
                    result.state.as_str(),
                    result.service
                ));
            }
            text
        }
    };

    let mut file = File::create(path).await?;
    file.write_all(content.as_bytes()).await?;

    println!("{} Results exported to {}", "[+]".green(), path);
    Ok(())
}

/// Probe specific protocol
async fn probe_protocol(
    target: &str,
    port: u16,
    protocol: Protocol,
    timeout_ms: u64,
) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", target, port).parse()?;
    let timeout_duration = Duration::from_millis(timeout_ms);

    println!(
        "{} Probing {}:{} with {:?} protocol",
        "[*]".blue(),
        target,
        port,
        protocol
    );

    let connect_result = timeout(timeout_duration, TcpStream::connect(addr)).await;

    match connect_result {
        Ok(Ok(mut stream)) => {
            let probe = match protocol {
                Protocol::Http => ProtocolProbe::http(),
                Protocol::Ssh => ProtocolProbe::ssh(),
                Protocol::Ftp => ProtocolProbe::ftp(),
                Protocol::Smtp => ProtocolProbe::smtp(),
                Protocol::Mysql => ProtocolProbe::mysql(),
                Protocol::Redis => ProtocolProbe::redis(),
                _ => ProtocolProbe::http(),
            };

            let mut buffer = vec![0u8; 8192];

            let response = if probe.data.is_empty() {
                timeout(timeout_duration, stream.read(&mut buffer)).await
            } else {
                stream.write_all(&probe.data).await?;
                timeout(timeout_duration, stream.read(&mut buffer)).await
            };

            match response {
                Ok(Ok(n)) if n > 0 => {
                    println!("\n{} Response ({} bytes):", "[+]".green(), n);
                    println!("{}", "─".repeat(60));

                    if buffer[..n].iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
                        println!("{}", String::from_utf8_lossy(&buffer[..n]));
                    } else {
                        // Hex dump for binary data
                        for (i, chunk) in buffer[..n].chunks(16).enumerate() {
                            print!("{:08x}  ", i * 16);
                            for byte in chunk {
                                print!("{:02x} ", byte);
                            }
                            print!(" ");
                            for byte in chunk {
                                let c = if byte.is_ascii_graphic() || *byte == b' ' {
                                    *byte as char
                                } else {
                                    '.'
                                };
                                print!("{}", c);
                            }
                            println!();
                        }
                    }
                }
                _ => {
                    println!("{} No response received", "[!]".yellow());
                }
            }
        }
        Ok(Err(e)) => {
            println!("{} Connection refused: {}", "[!]".red(), e);
        }
        Err(_) => {
            println!("{} Connection timed out", "[!]".yellow());
        }
    }

    Ok(())
}

/// Show service signatures
fn show_signatures(port_filter: Option<u16>, name_filter: Option<String>) {
    println!("\n{}", "═".repeat(60).cyan());
    println!("{}", " SERVICE SIGNATURES ".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    for (service, signatures) in SERVICE_SIGNATURES.iter() {
        if let Some(ref name) = name_filter {
            if !service.contains(name.to_lowercase().as_str()) {
                continue;
            }
        }

        println!("\n{} {}:", "[*]".blue(), service.to_uppercase());

        for sig in signatures {
            println!(
                "    {} - {}",
                sig.name.green(),
                sig.product.unwrap_or("unknown")
            );
        }
    }

    if let Some(port) = port_filter {
        println!("\n{} Port {} default service:", "[*]".blue(), port);
        if let Some(service) = PORT_SERVICES.get(&port) {
            println!("    {}", service);
        } else {
            println!("    Unknown");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            ports,
            timeout,
            concurrency,
            banner,
            version,
            output,
            export,
        } => {
            let targets = parse_targets(&target)?;
            let port_list = parse_ports(&ports)?;

            let scanner = ServiceScanner::new(timeout, concurrency, banner, version);
            let results = scanner.scan(targets, port_list).await;

            display_results(&results, output);

            if let Some(path) = export {
                export_results(&results, &path, output).await?;
            }
        }

        Commands::Probe {
            target,
            port,
            protocol,
            timeout,
        } => {
            probe_protocol(&target, port, protocol, timeout).await?;
        }

        Commands::Signatures { port, name } => {
            show_signatures(port, name);
        }
    }

    Ok(())
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test port parsing
    #[test]
    fn test_parse_ports() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);

        let range = parse_ports("1-5").unwrap();
        assert_eq!(range, vec![1, 2, 3, 4, 5]);

        let mixed = parse_ports("22,80-82,443").unwrap();
        assert_eq!(mixed, vec![22, 80, 81, 82, 443]);
    }

    /// Test target parsing
    #[test]
    fn test_parse_targets() {
        let single = parse_targets("192.168.1.1").unwrap();
        assert_eq!(single.len(), 1);

        let cidr = parse_targets("192.168.1.0/30").unwrap();
        assert_eq!(cidr.len(), 4); // /30 = 4 addresses
    }

    /// Test service signature matching
    #[test]
    fn test_signature_matching() {
        let banner = "SSH-2.0-OpenSSH_8.4p1";
        let result = identify_service(banner, "ssh");

        assert!(result.is_some());
        let matched = result.unwrap();
        assert_eq!(matched.name, "OpenSSH");
        assert_eq!(matched.version, Some("8.4p1".to_string()));
    }

    /// Test port state
    #[test]
    fn test_port_state() {
        assert_eq!(PortState::Open.as_str(), "open");
        assert_eq!(PortState::Closed.as_str(), "closed");
        assert_eq!(PortState::Filtered.as_str(), "filtered");
    }

    /// Test port to service mapping
    #[test]
    fn test_port_services() {
        assert_eq!(PORT_SERVICES.get(&22), Some(&"ssh"));
        assert_eq!(PORT_SERVICES.get(&80), Some(&"http"));
        assert_eq!(PORT_SERVICES.get(&3306), Some(&"mysql"));
    }

    /// Test async scan result type
    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            port: 22,
            state: PortState::Open,
            service: "ssh".to_string(),
            banner: Some("OpenSSH".to_string()),
            version: None,
            response_time_ms: 50,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"port\":22"));
        assert!(json.contains("\"state\":\"Open\""));
    }

    /// Test type alias usage
    #[test]
    fn test_type_alias() {
        let results: ScanResults = vec![(
            "127.0.0.1:22".parse().unwrap(),
            ScanResult {
                port: 22,
                state: PortState::Open,
                service: "ssh".to_string(),
                banner: None,
                version: None,
                response_time_ms: 10,
            },
        )];

        assert_eq!(results.len(), 1);
    }
}
