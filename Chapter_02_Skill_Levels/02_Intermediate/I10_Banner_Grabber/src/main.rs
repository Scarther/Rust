//! # Banner Grabber - Rust Security Bible
//!
//! A comprehensive tool for grabbing service banners from network ports.
//! Banner grabbing is a fundamental reconnaissance technique used to identify
//! services, versions, and potential vulnerabilities on target systems.
//!
//! ## Features
//! - Grab banners from single or multiple ports
//! - Protocol-specific probes (HTTP, SMTP, FTP, SSH, etc.)
//! - SSL/TLS banner grabbing
//! - Service fingerprinting
//! - Concurrent scanning
//! - Custom probes
//!
//! ## Security Applications
//! - Service enumeration
//! - Version detection
//! - Vulnerability assessment
//! - Network mapping

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use futures::future::join_all;
use native_tls::TlsConnector;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tabled::{Table, Tabled};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Custom error types for banner grabbing operations
#[derive(Error, Debug)]
pub enum BannerError {
    #[error("Connection failed to {host}:{port}: {reason}")]
    ConnectionFailed {
        host: String,
        port: u16,
        reason: String,
    },

    #[error("Connection timeout after {0:?}")]
    Timeout(Duration),

    #[error("Read timeout - no banner received")]
    ReadTimeout,

    #[error("TLS handshake failed: {0}")]
    TlsError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("No banner received")]
    NoBanner,
}

pub type BannerResult<T> = Result<T, BannerError>;

// =============================================================================
// CLI INTERFACE
// =============================================================================

/// Banner Grabber - Service reconnaissance tool
#[derive(Parser, Debug)]
#[command(name = "banner_grabber")]
#[command(author = "Security Developer")]
#[command(version = "1.0")]
#[command(about = "Grab service banners from network ports")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Grab banner from a single port
    Single {
        /// Target host
        host: String,

        /// Target port
        port: u16,

        /// Connection timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,

        /// Use SSL/TLS
        #[arg(short, long)]
        ssl: bool,

        /// Protocol hint for sending appropriate probe
        #[arg(short, long)]
        protocol: Option<Protocol>,
    },

    /// Grab banners from multiple ports
    Scan {
        /// Target host
        host: String,

        /// Ports to scan (comma-separated or range like 1-1000)
        #[arg(short, long, default_value = "21,22,23,25,80,110,143,443,3306,5432,8080")]
        ports: String,

        /// Maximum concurrent connections
        #[arg(short, long, default_value = "10")]
        concurrent: usize,

        /// Connection timeout in seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
    },

    /// Grab banners from common service ports
    Quick {
        /// Target host
        host: String,

        /// Connection timeout in seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
    },

    /// Grab HTTP banner with detailed analysis
    Http {
        /// Target URL or host
        host: String,

        /// Port (default 80, or 443 for HTTPS)
        #[arg(short, long, default_value = "80")]
        port: u16,

        /// Use HTTPS
        #[arg(short, long)]
        ssl: bool,

        /// Custom path
        #[arg(long, default_value = "/")]
        path: String,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
enum Protocol {
    Http,
    Https,
    Smtp,
    Ftp,
    Ssh,
    Pop3,
    Imap,
    Mysql,
    Postgres,
    Redis,
    Raw,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Result of a banner grab operation
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct BannerInfo {
    #[tabled(rename = "Host")]
    pub host: String,
    #[tabled(rename = "Port")]
    pub port: u16,
    #[tabled(rename = "Status")]
    pub status: String,
    #[tabled(rename = "Service")]
    pub service: String,
    #[tabled(rename = "Banner")]
    #[tabled(display_with = "truncate_banner")]
    pub banner: String,
    #[tabled(rename = "Time (ms)")]
    pub response_time_ms: u64,
}

fn truncate_banner(banner: &String) -> String {
    if banner.len() > 50 {
        format!("{}...", &banner[..47])
    } else {
        banner.clone()
    }
}

/// Detailed banner analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerAnalysis {
    pub raw_banner: String,
    pub service: String,
    pub version: Option<String>,
    pub os_hint: Option<String>,
    pub security_notes: Vec<String>,
    pub headers: HashMap<String, String>,
}

/// Service fingerprint database entry
#[derive(Debug, Clone)]
struct ServiceFingerprint {
    name: &'static str,
    patterns: Vec<&'static str>,
    version_regex: Option<&'static str>,
}

// =============================================================================
// SERVICE FINGERPRINTING
// =============================================================================

/// Get known service fingerprints
fn get_fingerprints() -> Vec<ServiceFingerprint> {
    vec![
        ServiceFingerprint {
            name: "SSH",
            patterns: vec!["SSH-", "OpenSSH", "dropbear"],
            version_regex: Some(r"SSH-[\d.]+-([\w._-]+)"),
        },
        ServiceFingerprint {
            name: "HTTP",
            patterns: vec!["HTTP/", "Apache", "nginx", "IIS", "LiteSpeed"],
            version_regex: Some(r"(?:Apache|nginx|IIS)/?(\d+\.[\d.]+)"),
        },
        ServiceFingerprint {
            name: "FTP",
            patterns: vec!["220", "FTP", "vsFTPd", "ProFTPD", "Pure-FTPd"],
            version_regex: Some(r"(?:vsFTPd|ProFTPD|Pure-FTPd)\s+([\d.]+)"),
        },
        ServiceFingerprint {
            name: "SMTP",
            patterns: vec!["220", "ESMTP", "Postfix", "Sendmail", "Microsoft ESMTP"],
            version_regex: Some(r"(?:Postfix|Sendmail)\s*/?\s*([\d.]+)?"),
        },
        ServiceFingerprint {
            name: "MySQL",
            patterns: vec!["mysql", "MariaDB", "\x00\x00\x00\x0a"],
            version_regex: Some(r"([\d.]+)(?:-MariaDB)?"),
        },
        ServiceFingerprint {
            name: "PostgreSQL",
            patterns: vec!["PostgreSQL", "FATAL", "SSL required"],
            version_regex: Some(r"PostgreSQL\s+([\d.]+)"),
        },
        ServiceFingerprint {
            name: "Redis",
            patterns: vec!["-ERR", "+PONG", "redis_version"],
            version_regex: Some(r"redis_version:([\d.]+)"),
        },
        ServiceFingerprint {
            name: "MongoDB",
            patterns: vec!["MongoDB", "ismaster"],
            version_regex: None,
        },
        ServiceFingerprint {
            name: "POP3",
            patterns: vec!["+OK", "POP3"],
            version_regex: None,
        },
        ServiceFingerprint {
            name: "IMAP",
            patterns: vec!["* OK", "IMAP", "Dovecot", "Cyrus"],
            version_regex: Some(r"(?:Dovecot|Cyrus)\s+(?:IMAP)?\s*([\d.]+)?"),
        },
        ServiceFingerprint {
            name: "Telnet",
            patterns: vec!["\xff\xfd", "\xff\xfb", "login:"],
            version_regex: None,
        },
    ]
}

/// Fingerprint a service based on its banner
fn fingerprint_service(banner: &str) -> (String, Option<String>) {
    let fingerprints = get_fingerprints();

    for fp in fingerprints {
        for pattern in &fp.patterns {
            if banner.contains(pattern) {
                let version = fp.version_regex.and_then(|regex_str| {
                    Regex::new(regex_str).ok().and_then(|re| {
                        re.captures(banner)
                            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
                    })
                });
                return (fp.name.to_string(), version);
            }
        }
    }

    ("Unknown".to_string(), None)
}

/// Analyze banner for security issues
fn analyze_security(banner: &str, service: &str) -> Vec<String> {
    let mut notes = Vec::new();

    // Check for version disclosure
    if Regex::new(r"\d+\.\d+\.\d+").unwrap().is_match(banner) {
        notes.push("Version information disclosed".to_string());
    }

    // Check for outdated protocols
    if banner.contains("SSLv2") || banner.contains("SSLv3") {
        notes.push("Outdated SSL version detected".to_string());
    }

    // Check for debug mode
    if banner.to_lowercase().contains("debug") {
        notes.push("Debug mode possibly enabled".to_string());
    }

    // Service-specific checks
    match service {
        "SSH" => {
            if banner.contains("SSH-1") {
                notes.push("SSH protocol version 1 (insecure)".to_string());
            }
        }
        "FTP" => {
            if banner.to_lowercase().contains("anonymous") {
                notes.push("Anonymous FTP may be enabled".to_string());
            }
        }
        "HTTP" => {
            if !banner.contains("Strict-Transport-Security") {
                notes.push("HSTS not detected".to_string());
            }
        }
        "Telnet" => {
            notes.push("Telnet is unencrypted - security risk".to_string());
        }
        _ => {}
    }

    notes
}

// =============================================================================
// PROTOCOL PROBES
// =============================================================================

/// Get the appropriate probe for a protocol
fn get_probe(protocol: &Protocol) -> Vec<u8> {
    match protocol {
        Protocol::Http | Protocol::Https => {
            b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: BannerGrabber/1.0\r\nConnection: close\r\n\r\n".to_vec()
        }
        Protocol::Smtp => b"EHLO scanner\r\n".to_vec(),
        Protocol::Ftp => vec![], // FTP sends banner on connect
        Protocol::Ssh => vec![], // SSH sends banner on connect
        Protocol::Pop3 => vec![], // POP3 sends banner on connect
        Protocol::Imap => vec![], // IMAP sends banner on connect
        Protocol::Mysql => vec![], // MySQL sends banner on connect
        Protocol::Postgres => vec![
            // PostgreSQL startup message (simplified)
            0, 0, 0, 8, 4, 210, 22, 47,
        ],
        Protocol::Redis => b"PING\r\n".to_vec(),
        Protocol::Raw => vec![],
    }
}

/// Get default protocol for a port
fn default_protocol(port: u16) -> Protocol {
    match port {
        21 => Protocol::Ftp,
        22 => Protocol::Ssh,
        23 => Protocol::Raw,
        25 | 587 => Protocol::Smtp,
        80 | 8080 | 8000 | 8888 => Protocol::Http,
        110 => Protocol::Pop3,
        143 => Protocol::Imap,
        443 | 8443 => Protocol::Https,
        3306 => Protocol::Mysql,
        5432 => Protocol::Postgres,
        6379 => Protocol::Redis,
        _ => Protocol::Raw,
    }
}

// =============================================================================
// BANNER GRABBING IMPLEMENTATION
// =============================================================================

/// Banner grabber with configurable options
pub struct BannerGrabber {
    timeout: Duration,
    max_banner_size: usize,
}

impl BannerGrabber {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            max_banner_size: 4096,
        }
    }

    /// Grab banner from a TCP connection
    pub async fn grab(
        &self,
        host: &str,
        port: u16,
        use_ssl: bool,
        protocol: Option<Protocol>,
    ) -> BannerResult<BannerInfo> {
        let start = Instant::now();

        // Resolve address
        let addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .or_else(|_| {
                // Try DNS resolution
                use std::net::ToSocketAddrs;
                format!("{}:{}", host, port)
                    .to_socket_addrs()
                    .map_err(|e| BannerError::InvalidAddress(e.to_string()))?
                    .next()
                    .ok_or_else(|| BannerError::InvalidAddress(host.to_string()))
            })?;

        // Connect with timeout
        let stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| BannerError::Timeout(self.timeout))?
            .map_err(|e| BannerError::ConnectionFailed {
                host: host.to_string(),
                port,
                reason: e.to_string(),
            })?;

        let banner = if use_ssl {
            self.grab_ssl_banner(stream, host, &protocol).await?
        } else {
            self.grab_plain_banner(stream, &protocol).await?
        };

        let elapsed = start.elapsed();
        let (service, version) = fingerprint_service(&banner);
        let service_display = match version {
            Some(v) => format!("{} {}", service, v),
            None => service,
        };

        Ok(BannerInfo {
            host: host.to_string(),
            port,
            status: "Open".to_string(),
            service: service_display,
            banner: sanitize_banner(&banner),
            response_time_ms: elapsed.as_millis() as u64,
        })
    }

    /// Grab banner over plain TCP
    async fn grab_plain_banner(
        &self,
        mut stream: TcpStream,
        protocol: &Option<Protocol>,
    ) -> BannerResult<String> {
        let proto = protocol.clone().unwrap_or(Protocol::Raw);
        let probe = get_probe(&proto);

        // Send probe if needed
        if !probe.is_empty() {
            stream.write_all(&probe).await?;
        }

        // Read response
        let mut buffer = vec![0u8; self.max_banner_size];
        let read_timeout = Duration::from_secs(2);

        let n = match timeout(read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(BannerError::IoError(e)),
            Err(_) => return Err(BannerError::ReadTimeout),
        };

        if n == 0 {
            return Err(BannerError::NoBanner);
        }

        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    }

    /// Grab banner over SSL/TLS
    async fn grab_ssl_banner(
        &self,
        stream: TcpStream,
        host: &str,
        protocol: &Option<Protocol>,
    ) -> BannerResult<String> {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true) // For scanning purposes
            .build()
            .map_err(|e| BannerError::TlsError(e.to_string()))?;

        let connector = tokio_native_tls::TlsConnector::from(connector);

        let mut tls_stream = connector
            .connect(host, stream)
            .await
            .map_err(|e| BannerError::TlsError(e.to_string()))?;

        let proto = protocol.clone().unwrap_or(Protocol::Https);
        let probe = get_probe(&proto);

        if !probe.is_empty() {
            tls_stream.write_all(&probe).await?;
        }

        let mut buffer = vec![0u8; self.max_banner_size];
        let read_timeout = Duration::from_secs(2);

        let n = match timeout(read_timeout, tls_stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(BannerError::IoError(e)),
            Err(_) => return Err(BannerError::ReadTimeout),
        };

        if n == 0 {
            return Err(BannerError::NoBanner);
        }

        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    }

    /// Grab banners from multiple ports concurrently
    pub async fn grab_multiple(
        &self,
        host: &str,
        ports: Vec<u16>,
        max_concurrent: usize,
    ) -> Vec<BannerInfo> {
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut handles = Vec::new();

        for port in ports {
            let sem = Arc::clone(&semaphore);
            let host = host.to_string();
            let timeout_secs = self.timeout.as_secs();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("Semaphore closed");
                let grabber = BannerGrabber::new(timeout_secs);

                // Determine if SSL should be used
                let use_ssl = matches!(port, 443 | 8443 | 993 | 995 | 465);
                let protocol = Some(default_protocol(port));

                grabber.grab(&host, port, use_ssl, protocol).await
            });

            handles.push((port, handle));
        }

        let mut results = Vec::new();
        for (port, handle) in handles {
            match handle.await {
                Ok(Ok(info)) => results.push(info),
                Ok(Err(_)) => {
                    results.push(BannerInfo {
                        host: host.to_string(),
                        port,
                        status: "Closed/Filtered".to_string(),
                        service: "-".to_string(),
                        banner: "-".to_string(),
                        response_time_ms: 0,
                    });
                }
                Err(_) => {}
            }
        }

        results.sort_by_key(|r| r.port);
        results
    }

    /// Detailed HTTP banner analysis
    pub async fn grab_http_detailed(
        &self,
        host: &str,
        port: u16,
        use_ssl: bool,
        path: &str,
    ) -> BannerResult<BannerAnalysis> {
        let start = Instant::now();

        // Build HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (compatible; BannerGrabber/1.0)\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\r\n",
            path, host
        );

        // Connect
        let addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .or_else(|_| {
                use std::net::ToSocketAddrs;
                format!("{}:{}", host, port)
                    .to_socket_addrs()
                    .map_err(|e| BannerError::InvalidAddress(e.to_string()))?
                    .next()
                    .ok_or_else(|| BannerError::InvalidAddress(host.to_string()))
            })?;

        let stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| BannerError::Timeout(self.timeout))?
            .map_err(|e| BannerError::ConnectionFailed {
                host: host.to_string(),
                port,
                reason: e.to_string(),
            })?;

        let response = if use_ssl {
            self.http_ssl_request(stream, host, &request).await?
        } else {
            self.http_plain_request(stream, &request).await?
        };

        // Parse response
        let mut headers = HashMap::new();
        let mut service = "HTTP".to_string();
        let mut version = None;
        let mut os_hint = None;

        for line in response.lines() {
            if line.starts_with("HTTP/") {
                service = line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            } else if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                // Extract version info from Server header
                if key == "server" {
                    version = Regex::new(r"([\d.]+)")
                        .ok()
                        .and_then(|re| {
                            re.captures(&value)
                                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                        });

                    // OS hints
                    if value.to_lowercase().contains("ubuntu") {
                        os_hint = Some("Ubuntu Linux".to_string());
                    } else if value.to_lowercase().contains("debian") {
                        os_hint = Some("Debian Linux".to_string());
                    } else if value.to_lowercase().contains("centos") {
                        os_hint = Some("CentOS Linux".to_string());
                    } else if value.contains("Win") {
                        os_hint = Some("Windows".to_string());
                    }
                }

                headers.insert(key, value);
            }
        }

        let security_notes = analyze_security(&response, "HTTP");

        Ok(BannerAnalysis {
            raw_banner: response,
            service,
            version,
            os_hint,
            security_notes,
            headers,
        })
    }

    async fn http_plain_request(
        &self,
        mut stream: TcpStream,
        request: &str,
    ) -> BannerResult<String> {
        stream.write_all(request.as_bytes()).await?;

        let mut buffer = vec![0u8; 8192];
        let mut response = String::new();

        loop {
            match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response.push_str(&String::from_utf8_lossy(&buffer[..n]));
                    if response.len() > 8192 {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(BannerError::IoError(e)),
                Err(_) => break,
            }
        }

        Ok(response)
    }

    async fn http_ssl_request(
        &self,
        stream: TcpStream,
        host: &str,
        request: &str,
    ) -> BannerResult<String> {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| BannerError::TlsError(e.to_string()))?;

        let connector = tokio_native_tls::TlsConnector::from(connector);

        let mut tls_stream = connector
            .connect(host, stream)
            .await
            .map_err(|e| BannerError::TlsError(e.to_string()))?;

        tls_stream.write_all(request.as_bytes()).await?;

        let mut buffer = vec![0u8; 8192];
        let mut response = String::new();

        loop {
            match timeout(Duration::from_secs(2), tls_stream.read(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response.push_str(&String::from_utf8_lossy(&buffer[..n]));
                    if response.len() > 8192 {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(BannerError::IoError(e)),
                Err(_) => break,
            }
        }

        Ok(response)
    }
}

/// Sanitize banner for display (remove control characters)
fn sanitize_banner(banner: &str) -> String {
    banner
        .chars()
        .map(|c| if c.is_control() && c != '\n' && c != '\r' { '.' } else { c })
        .collect::<String>()
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Parse port specification (e.g., "80,443" or "1-1000")
fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    ports.extend(start..=end);
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }

    ports
}

/// Get common service ports
fn common_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
        5432, 5900, 8080, 8443,
    ]
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!(
        "{}",
        "Banner Grabber - Service Reconnaissance Tool"
            .bright_cyan()
            .bold()
    );
    println!("{}", "=".repeat(50));

    match cli.command {
        Commands::Single {
            host,
            port,
            timeout: timeout_secs,
            ssl,
            protocol,
        } => {
            println!(
                "\n{} {}:{} (SSL: {}, Timeout: {}s)\n",
                "Grabbing banner from".cyan(),
                host.green(),
                port.to_string().yellow(),
                ssl,
                timeout_secs
            );

            let grabber = BannerGrabber::new(timeout_secs);
            match grabber.grab(&host, port, ssl, protocol).await {
                Ok(info) => {
                    match cli.format {
                        OutputFormat::Text => {
                            println!("{}: {}", "Status".bold(), info.status.green());
                            println!("{}: {}", "Service".bold(), info.service.yellow());
                            println!("{}: {}ms", "Response Time".bold(), info.response_time_ms);
                            println!("\n{}:", "Banner".bold());
                            println!("{}", info.banner);

                            // Security analysis
                            let (service, _) = fingerprint_service(&info.banner);
                            let notes = analyze_security(&info.banner, &service);
                            if !notes.is_empty() {
                                println!("\n{}:", "Security Notes".bold().red());
                                for note in notes {
                                    println!("  - {}", note.yellow());
                                }
                            }
                        }
                        OutputFormat::Json => {
                            println!("{}", serde_json::to_string_pretty(&info)?);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}: {}", "Error".red(), e);
                }
            }
        }

        Commands::Scan {
            host,
            ports,
            concurrent,
            timeout: timeout_secs,
        } => {
            let port_list = parse_ports(&ports);
            println!(
                "\n{} {} ports on {} (max {} concurrent)\n",
                "Scanning".cyan(),
                port_list.len().to_string().yellow(),
                host.green(),
                concurrent.to_string().yellow()
            );

            let grabber = BannerGrabber::new(timeout_secs);
            let results = grabber.grab_multiple(&host, port_list, concurrent).await;

            let open_ports: Vec<_> = results.iter().filter(|r| r.status == "Open").collect();

            match cli.format {
                OutputFormat::Text => {
                    let table = Table::new(&results);
                    println!("{}", table);
                    println!(
                        "\n{}: {} open, {} closed/filtered",
                        "Summary".bold(),
                        open_ports.len().to_string().green(),
                        (results.len() - open_ports.len()).to_string().yellow()
                    );
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                }
            }
        }

        Commands::Quick {
            host,
            timeout: timeout_secs,
        } => {
            let ports = common_ports();
            println!(
                "\n{} {} common ports on {}\n",
                "Quick scan of".cyan(),
                ports.len().to_string().yellow(),
                host.green()
            );

            let grabber = BannerGrabber::new(timeout_secs);
            let results = grabber.grab_multiple(&host, ports, 20).await;

            let open_ports: Vec<_> = results.iter().filter(|r| r.status == "Open").collect();

            match cli.format {
                OutputFormat::Text => {
                    if open_ports.is_empty() {
                        println!("{}", "No open ports found".yellow());
                    } else {
                        let table = Table::new(open_ports);
                        println!("{}", table);
                    }
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                }
            }
        }

        Commands::Http {
            host,
            port,
            ssl,
            path,
        } => {
            println!(
                "\n{} {}:{}{} (SSL: {})\n",
                "HTTP banner grab from".cyan(),
                host.green(),
                port.to_string().yellow(),
                path.cyan(),
                ssl
            );

            let grabber = BannerGrabber::new(10);
            match grabber.grab_http_detailed(&host, port, ssl, &path).await {
                Ok(analysis) => match cli.format {
                    OutputFormat::Text => {
                        println!("{}: {}", "Service".bold(), analysis.service.green());
                        if let Some(version) = &analysis.version {
                            println!("{}: {}", "Version".bold(), version.yellow());
                        }
                        if let Some(os) = &analysis.os_hint {
                            println!("{}: {}", "OS Hint".bold(), os.cyan());
                        }

                        println!("\n{}:", "Headers".bold());
                        for (key, value) in &analysis.headers {
                            println!("  {}: {}", key.cyan(), value);
                        }

                        if !analysis.security_notes.is_empty() {
                            println!("\n{}:", "Security Notes".bold().red());
                            for note in &analysis.security_notes {
                                println!("  - {}", note.yellow());
                            }
                        }
                    }
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&analysis)?);
                    }
                },
                Err(e) => {
                    eprintln!("{}: {}", "Error".red(), e);
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports("80");
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_ports_multiple() {
        let ports = parse_ports("80,443,8080");
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("80-83");
        assert_eq!(ports, vec![80, 81, 82, 83]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        let ports = parse_ports("22,80-82,443");
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_fingerprint_ssh() {
        let (service, version) = fingerprint_service("SSH-2.0-OpenSSH_8.9");
        assert_eq!(service, "SSH");
        assert!(version.is_some());
    }

    #[test]
    fn test_fingerprint_http() {
        let (service, _) = fingerprint_service("HTTP/1.1 200 OK");
        assert_eq!(service, "HTTP");
    }

    #[test]
    fn test_fingerprint_ftp() {
        let (service, version) = fingerprint_service("220 (vsFTPd 3.0.3)");
        assert_eq!(service, "FTP");
        assert_eq!(version, Some("3.0.3".to_string()));
    }

    #[test]
    fn test_fingerprint_unknown() {
        let (service, version) = fingerprint_service("random data");
        assert_eq!(service, "Unknown");
        assert!(version.is_none());
    }

    #[test]
    fn test_sanitize_banner() {
        let banner = "SSH-2.0-OpenSSH\r\n";
        let sanitized = sanitize_banner(banner);
        assert_eq!(sanitized, "SSH-2.0-OpenSSH");
    }

    #[test]
    fn test_sanitize_banner_control_chars() {
        let banner = "Test\x00\x01\x02Banner";
        let sanitized = sanitize_banner(banner);
        assert!(sanitized.contains("..."));
    }

    #[test]
    fn test_default_protocol() {
        assert!(matches!(default_protocol(22), Protocol::Ssh));
        assert!(matches!(default_protocol(80), Protocol::Http));
        assert!(matches!(default_protocol(443), Protocol::Https));
        assert!(matches!(default_protocol(3306), Protocol::Mysql));
    }

    #[test]
    fn test_common_ports() {
        let ports = common_ports();
        assert!(ports.contains(&22));
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[test]
    fn test_security_analysis_version() {
        let notes = analyze_security("Server: Apache/2.4.41", "HTTP");
        assert!(notes.iter().any(|n| n.contains("Version")));
    }

    #[test]
    fn test_security_analysis_telnet() {
        let notes = analyze_security("login:", "Telnet");
        assert!(notes.iter().any(|n| n.contains("unencrypted")));
    }

    #[test]
    fn test_security_analysis_ssh_v1() {
        let notes = analyze_security("SSH-1.5-Server", "SSH");
        assert!(notes.iter().any(|n| n.contains("version 1")));
    }

    #[test]
    fn test_banner_info_serialization() {
        let info = BannerInfo {
            host: "example.com".to_string(),
            port: 80,
            status: "Open".to_string(),
            service: "HTTP".to_string(),
            banner: "HTTP/1.1 200 OK".to_string(),
            response_time_ms: 100,
        };

        let json = serde_json::to_string(&info);
        assert!(json.is_ok());
    }

    #[tokio::test]
    async fn test_banner_grabber_creation() {
        let grabber = BannerGrabber::new(5);
        assert_eq!(grabber.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_get_probe_http() {
        let probe = get_probe(&Protocol::Http);
        assert!(!probe.is_empty());
        assert!(String::from_utf8_lossy(&probe).contains("GET"));
    }

    #[test]
    fn test_get_probe_raw() {
        let probe = get_probe(&Protocol::Raw);
        assert!(probe.is_empty());
    }
}
