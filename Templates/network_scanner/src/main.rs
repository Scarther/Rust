//! Network Scanner Template
//!
//! A template for building network scanning tools in Rust.
//! Supports TCP connect scans, ping sweeps, and banner grabbing.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::IpNetwork;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

mod output;

/// Network Scanner - A fast, async network scanning tool
#[derive(Parser)]
#[command(name = "netscan")]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Number of concurrent connections
    #[arg(short, long, default_value = "100")]
    concurrency: usize,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value = "3000")]
    timeout: u64,

    /// Output format (text, json, csv)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// TCP port scan
    Ports {
        /// Target IP or hostname
        #[arg(short, long)]
        target: String,

        /// Port range (e.g., "1-1000" or "22,80,443")
        #[arg(short, long, default_value = "1-1000")]
        ports: String,

        /// Grab service banners
        #[arg(short, long)]
        banner: bool,
    },

    /// Host discovery (ping sweep)
    Sweep {
        /// Network in CIDR notation (e.g., "192.168.1.0/24")
        #[arg(short, long)]
        network: String,
    },

    /// Service detection
    Services {
        /// Target IP or hostname
        #[arg(short, long)]
        target: String,

        /// Port to probe
        #[arg(short, long)]
        port: u16,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortResult {
    pub port: u16,
    pub state: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub timestamp: String,
    pub scan_type: String,
    pub duration_ms: u64,
    pub ports: Vec<PortResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: String,
    pub alive: bool,
    pub latency_ms: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();

    let timeout_duration = Duration::from_millis(cli.timeout);
    let semaphore = Arc::new(Semaphore::new(cli.concurrency));

    match cli.command {
        Commands::Ports { target, ports, banner } => {
            let results = port_scan(&target, &ports, banner, timeout_duration, semaphore).await?;
            output::print_port_results(&results, &cli.format)?;
        }
        Commands::Sweep { network } => {
            let results = host_sweep(&network, timeout_duration, semaphore).await?;
            output::print_host_results(&results, &cli.format)?;
        }
        Commands::Services { target, port } => {
            let result = detect_service(&target, port, timeout_duration).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}

/// Perform a TCP port scan
async fn port_scan(
    target: &str,
    port_spec: &str,
    grab_banner: bool,
    timeout_duration: Duration,
    semaphore: Arc<Semaphore>,
) -> Result<ScanResults> {
    let start_time = std::time::Instant::now();

    // Resolve target
    let ip: IpAddr = target.parse().context("Invalid IP address")?;
    info!("Scanning {} with port spec: {}", target, port_spec);

    // Parse port specification
    let ports = parse_ports(port_spec)?;
    let total_ports = ports.len();

    println!(
        "{} Scanning {} ports on {}",
        "[*]".blue(),
        total_ports,
        target
    );

    // Create progress bar
    let pb = ProgressBar::new(total_ports as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Scan ports concurrently
    let mut handles = Vec::new();

    for port in ports {
        let sem = semaphore.clone();
        let pb = pb.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let addr = SocketAddr::new(ip, port);
            let result = scan_port(addr, grab_banner, timeout_duration).await;

            pb.inc(1);
            result
        });

        handles.push(handle);
    }

    // Collect results
    let mut open_ports: Vec<PortResult> = Vec::new();

    for handle in handles {
        if let Ok(Some(result)) = handle.await {
            if result.state == "open" {
                open_ports.push(result);
            }
        }
    }

    pb.finish_with_message("Scan complete");

    // Sort by port number
    open_ports.sort_by_key(|p| p.port);

    let duration = start_time.elapsed().as_millis() as u64;

    println!(
        "\n{} Found {} open ports in {}ms",
        "[+]".green(),
        open_ports.len(),
        duration
    );

    Ok(ScanResults {
        target: target.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        scan_type: "tcp_connect".to_string(),
        duration_ms: duration,
        ports: open_ports,
    })
}

/// Scan a single port
async fn scan_port(
    addr: SocketAddr,
    grab_banner: bool,
    timeout_duration: Duration,
) -> Option<PortResult> {
    let result = timeout(timeout_duration, TcpStream::connect(addr)).await;

    match result {
        Ok(Ok(mut stream)) => {
            debug!("Port {} is open", addr.port());

            let mut banner = None;
            let service = guess_service(addr.port());

            // Try to grab banner if requested
            if grab_banner {
                banner = grab_banner_from_stream(&mut stream, timeout_duration).await;
            }

            Some(PortResult {
                port: addr.port(),
                state: "open".to_string(),
                service,
                banner,
            })
        }
        Ok(Err(_)) => {
            debug!("Port {} is closed", addr.port());
            None
        }
        Err(_) => {
            debug!("Port {} timed out", addr.port());
            None
        }
    }
}

/// Attempt to grab a service banner
async fn grab_banner_from_stream(
    stream: &mut TcpStream,
    timeout_duration: Duration,
) -> Option<String> {
    let mut buffer = vec![0u8; 1024];

    // Some services need a probe
    let _ = stream.write_all(b"\r\n").await;

    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n])
                .trim()
                .to_string();
            if !banner.is_empty() {
                Some(banner)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Perform a host sweep
async fn host_sweep(
    network_spec: &str,
    timeout_duration: Duration,
    semaphore: Arc<Semaphore>,
) -> Result<Vec<HostResult>> {
    let network: IpNetwork = network_spec.parse().context("Invalid network specification")?;

    let hosts: Vec<IpAddr> = network.iter().collect();
    let total_hosts = hosts.len();

    println!(
        "{} Sweeping {} hosts in {}",
        "[*]".blue(),
        total_hosts,
        network_spec
    );

    let pb = ProgressBar::new(total_hosts as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap(),
    );

    let mut handles = Vec::new();

    for ip in hosts {
        let sem = semaphore.clone();
        let pb = pb.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let start = std::time::Instant::now();
            let alive = check_host_alive(ip, timeout_duration).await;
            let latency = if alive {
                Some(start.elapsed().as_millis() as u64)
            } else {
                None
            };

            pb.inc(1);

            HostResult {
                ip: ip.to_string(),
                alive,
                latency_ms: latency,
            }
        });

        handles.push(handle);
    }

    let mut results = Vec::new();

    for handle in handles {
        if let Ok(result) = handle.await {
            if result.alive {
                results.push(result);
            }
        }
    }

    pb.finish_with_message("Sweep complete");

    println!("\n{} Found {} live hosts", "[+]".green(), results.len());

    Ok(results)
}

/// Check if a host is alive by trying common ports
async fn check_host_alive(ip: IpAddr, timeout_duration: Duration) -> bool {
    let common_ports = [80, 443, 22, 445, 139, 21, 23, 25, 53];

    for port in common_ports {
        let addr = SocketAddr::new(ip, port);
        if timeout(timeout_duration, TcpStream::connect(addr))
            .await
            .is_ok()
        {
            return true;
        }
    }

    false
}

/// Detect service on a specific port
async fn detect_service(
    target: &str,
    port: u16,
    timeout_duration: Duration,
) -> Result<PortResult> {
    let ip: IpAddr = target.parse()?;
    let addr = SocketAddr::new(ip, port);

    if let Some(result) = scan_port(addr, true, timeout_duration).await {
        Ok(result)
    } else {
        Ok(PortResult {
            port,
            state: "closed".to_string(),
            service: None,
            banner: None,
        })
    }
}

/// Parse port specification (e.g., "1-1000" or "22,80,443")
fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();

        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].parse()?;
                let end: u16 = range[1].parse()?;
                ports.extend(start..=end);
            }
        } else {
            ports.push(part.parse()?);
        }
    }

    Ok(ports)
}

/// Guess service name based on port number
fn guess_service(port: u16) -> Option<String> {
    match port {
        21 => Some("ftp".to_string()),
        22 => Some("ssh".to_string()),
        23 => Some("telnet".to_string()),
        25 => Some("smtp".to_string()),
        53 => Some("dns".to_string()),
        80 => Some("http".to_string()),
        110 => Some("pop3".to_string()),
        111 => Some("rpcbind".to_string()),
        135 => Some("msrpc".to_string()),
        139 => Some("netbios-ssn".to_string()),
        143 => Some("imap".to_string()),
        443 => Some("https".to_string()),
        445 => Some("microsoft-ds".to_string()),
        993 => Some("imaps".to_string()),
        995 => Some("pop3s".to_string()),
        1433 => Some("mssql".to_string()),
        1521 => Some("oracle".to_string()),
        3306 => Some("mysql".to_string()),
        3389 => Some("rdp".to_string()),
        5432 => Some("postgresql".to_string()),
        5900 => Some("vnc".to_string()),
        6379 => Some("redis".to_string()),
        8080 => Some("http-proxy".to_string()),
        8443 => Some("https-alt".to_string()),
        27017 => Some("mongodb".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range() {
        let ports = parse_ports("1-10").unwrap();
        assert_eq!(ports.len(), 10);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[9], 10);
    }

    #[test]
    fn test_parse_port_list() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_mixed_ports() {
        let ports = parse_ports("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_guess_service() {
        assert_eq!(guess_service(22), Some("ssh".to_string()));
        assert_eq!(guess_service(80), Some("http".to_string()));
        assert_eq!(guess_service(12345), None);
    }
}
