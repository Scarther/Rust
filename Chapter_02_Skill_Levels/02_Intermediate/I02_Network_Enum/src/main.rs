//! # Network Enumeration Tool
//!
//! This tool provides comprehensive network enumeration capabilities including:
//! - ARP scanning for local network host discovery
//! - ICMP ping sweep for host availability
//! - Service detection on discovered hosts
//!
//! ## Rust Concepts Demonstrated:
//! - **Arc<T>**: Atomic Reference Counting for thread-safe shared ownership
//! - **Mutex<T>**: Mutual exclusion for thread-safe interior mutability
//! - **Channels**: mpsc (multi-producer, single-consumer) for thread communication
//! - **Traits**: Custom trait implementations for display and serialization
//! - **Lifetimes**: Explicit lifetime annotations in struct definitions
//! - **Error Handling**: Using Result and the ? operator with anyhow

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::IpNetwork;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Network Enumeration Tool - Discover hosts and services on your network
///
/// # INTERMEDIATE RUST CONCEPTS:
///
/// This tool demonstrates several intermediate Rust patterns:
///
/// 1. **Arc (Atomic Reference Counting)**:
///    Arc<T> enables multiple ownership across threads. Unlike Rc<T>,
///    Arc uses atomic operations for reference counting, making it thread-safe.
///
/// 2. **Mutex (Mutual Exclusion)**:
///    Mutex<T> provides interior mutability with runtime borrowing rules.
///    Combined with Arc, it allows safe mutable access from multiple threads.
///
/// 3. **Channels (mpsc)**:
///    Channels provide a way to send messages between threads.
///    The sender can be cloned for multiple producers.
///
/// 4. **Rayon Parallel Iterators**:
///    Rayon's par_iter() automatically parallelizes iteration across CPU cores.
#[derive(Parser)]
#[command(name = "network_enum")]
#[command(author = "Security Researcher")]
#[command(version = "1.0")]
#[command(about = "Network enumeration with ARP scan, ping sweep, and service detection")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Subcommands for different enumeration methods
#[derive(Subcommand)]
enum Commands {
    /// Perform ARP scan on local network
    Arp {
        /// Network interface to use (e.g., eth0, enp0s3)
        #[arg(short, long)]
        interface: String,

        /// Target network in CIDR notation (e.g., 192.168.1.0/24)
        #[arg(short, long)]
        target: String,

        /// Timeout in milliseconds for each probe
        #[arg(long, default_value = "1000")]
        timeout: u64,
    },

    /// Perform ICMP ping sweep
    Ping {
        /// Target network in CIDR notation
        #[arg(short, long)]
        target: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "50")]
        threads: usize,

        /// Timeout in milliseconds
        #[arg(long, default_value = "1000")]
        timeout: u64,
    },

    /// Detect services on discovered hosts
    Services {
        /// Target host or network
        #[arg(short, long)]
        target: String,

        /// Ports to scan (comma-separated or range like 1-1000)
        #[arg(short, long, default_value = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080")]
        ports: String,

        /// Connection timeout in milliseconds
        #[arg(long, default_value = "500")]
        timeout: u64,
    },

    /// List available network interfaces
    Interfaces,
}

/// Represents a discovered host on the network
///
/// # Lifetime Annotation:
/// This struct owns all its data (String, not &str), so no lifetime needed.
/// If we used `&str` for hostname, we'd need: `struct Host<'a> { hostname: &'a str, ... }`
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscoveredHost {
    /// IP address of the discovered host
    ip_address: IpAddr,
    /// MAC address (if available from ARP)
    mac_address: Option<String>,
    /// Hostname (if reverse DNS succeeded)
    hostname: Option<String>,
    /// Response time in milliseconds
    response_time_ms: u64,
    /// Discovered services
    services: Vec<ServiceInfo>,
}

/// Information about a discovered service
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceInfo {
    port: u16,
    protocol: String,
    service_name: String,
    banner: Option<String>,
}

/// Common service port mappings for service identification
fn get_common_services() -> HashMap<u16, &'static str> {
    // Using a HashMap for O(1) lookups - important for scanning many ports
    let mut services = HashMap::new();
    services.insert(21, "FTP");
    services.insert(22, "SSH");
    services.insert(23, "Telnet");
    services.insert(25, "SMTP");
    services.insert(53, "DNS");
    services.insert(80, "HTTP");
    services.insert(110, "POP3");
    services.insert(111, "RPC");
    services.insert(135, "MSRPC");
    services.insert(139, "NetBIOS");
    services.insert(143, "IMAP");
    services.insert(443, "HTTPS");
    services.insert(445, "SMB");
    services.insert(993, "IMAPS");
    services.insert(995, "POP3S");
    services.insert(1433, "MSSQL");
    services.insert(1521, "Oracle");
    services.insert(3306, "MySQL");
    services.insert(3389, "RDP");
    services.insert(5432, "PostgreSQL");
    services.insert(5900, "VNC");
    services.insert(6379, "Redis");
    services.insert(8080, "HTTP-Proxy");
    services.insert(8443, "HTTPS-Alt");
    services.insert(27017, "MongoDB");
    services
}

/// ARP Scanner implementation
///
/// # OWNERSHIP AND BORROWING:
/// The scanner takes ownership of the interface name (String)
/// but borrows the network configuration (&IpNetwork) since we don't need to modify it.
struct ArpScanner {
    interface: NetworkInterface,
    timeout: Duration,
}

impl ArpScanner {
    /// Create a new ARP scanner
    ///
    /// # Arguments
    /// * `interface_name` - Name of the network interface (ownership transferred)
    /// * `timeout` - Timeout duration (Copy type, so no ownership concerns)
    fn new(interface_name: &str, timeout: Duration) -> Result<Self> {
        // Find the specified interface
        // `into_iter()` takes ownership of the Vec, consuming it
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .context(format!("Interface '{}' not found", interface_name))?;

        Ok(Self { interface, timeout })
    }

    /// Perform ARP scan on the network
    ///
    /// # RUST CONCEPT - Arc<Mutex<T>>:
    /// We use Arc<Mutex<Vec<...>>> to share results across threads safely:
    /// - Arc: Allows multiple threads to own the same data
    /// - Mutex: Ensures only one thread modifies the Vec at a time
    fn scan(&self, network: &IpNetwork) -> Result<Vec<DiscoveredHost>> {
        println!(
            "{} Starting ARP scan on {} via {}",
            "[*]".blue(),
            network,
            self.interface.name
        );

        // Get our source IP and MAC
        let source_ip = self
            .interface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                IpAddr::V4(ipv4) => Some(ipv4),
                _ => None,
            })
            .context("No IPv4 address found on interface")?;

        let source_mac = self
            .interface
            .mac
            .context("No MAC address found on interface")?;

        // Arc<Mutex<Vec>> pattern for thread-safe result collection
        // Arc = Atomic Reference Count - thread-safe reference counting
        // Mutex = Mutual Exclusion - ensures only one thread accesses data at a time
        let results: Arc<Mutex<Vec<DiscoveredHost>>> = Arc::new(Mutex::new(Vec::new()));

        // Collect target IPs
        let targets: Vec<Ipv4Addr> = network
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(ipv4) => Some(ipv4),
                _ => None,
            })
            .collect();

        let progress = ProgressBar::new(targets.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Using Rayon's parallel iterator for concurrent scanning
        // par_iter() automatically distributes work across CPU cores
        targets.par_iter().for_each(|&target_ip| {
            if let Ok(Some(mac)) = self.send_arp_probe(source_ip, source_mac, target_ip) {
                // Clone Arc to get another reference for this thread
                // Arc::clone() is cheap - just increments atomic counter
                let results_clone = Arc::clone(&results);

                // Lock the mutex to safely push to the vector
                // MutexGuard implements DerefMut, so we can use it like &mut Vec
                let mut hosts = results_clone.lock().unwrap();
                hosts.push(DiscoveredHost {
                    ip_address: IpAddr::V4(target_ip),
                    mac_address: Some(mac.to_string()),
                    hostname: None, // Could add reverse DNS lookup
                    response_time_ms: 0,
                    services: Vec::new(),
                });
            }
            progress.inc(1);
        });

        progress.finish_with_message("Scan complete");

        // Extract results from Arc<Mutex<>>
        // into_inner() consumes the Mutex, returning the inner value
        // This works because Arc::try_unwrap succeeds when refcount is 1
        let hosts = Arc::try_unwrap(results)
            .map_err(|_| anyhow::anyhow!("Failed to unwrap Arc"))?
            .into_inner()
            .unwrap();

        Ok(hosts)
    }

    /// Send a single ARP probe and wait for response
    ///
    /// # BORROWING:
    /// - `&self`: Immutable borrow of scanner (we don't modify scanner state)
    /// - The IP addresses are Copy types, so they're copied not moved
    fn send_arp_probe(
        &self,
        source_ip: Ipv4Addr,
        source_mac: MacAddr,
        target_ip: Ipv4Addr,
    ) -> Result<Option<MacAddr>> {
        // Create channel for sending/receiving packets
        let (mut tx, mut rx) = match datalink::channel(&self.interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Unknown channel type")),
        };

        // Build ARP request packet
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
            .context("Failed to create ethernet packet")?;

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet =
            MutableArpPacket::new(&mut arp_buffer).context("Failed to create ARP packet")?;

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet());

        // Send the packet
        tx.send_to(ethernet_packet.packet(), None);

        // Wait for response with timeout
        let start = Instant::now();
        while start.elapsed() < self.timeout {
            if let Ok(packet) = rx.next() {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                            if arp.get_operation() == ArpOperations::Reply
                                && arp.get_sender_proto_addr() == target_ip
                            {
                                return Ok(Some(arp.get_sender_hw_addr()));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Ping sweep implementation using channels for result collection
///
/// # CHANNEL PATTERN:
/// We use mpsc (multi-producer, single-consumer) channels to collect results:
/// - Multiple worker threads send results through cloned Senders
/// - Main thread receives results through single Receiver
struct PingSweeper {
    timeout: Duration,
    thread_count: usize,
}

impl PingSweeper {
    fn new(timeout: Duration, thread_count: usize) -> Self {
        Self {
            timeout,
            thread_count,
        }
    }

    /// Perform ping sweep using TCP connect as fallback (no raw sockets needed)
    ///
    /// # CHANNEL USAGE:
    /// ```
    /// let (tx, rx) = channel();  // Create channel
    /// let tx_clone = tx.clone(); // Clone sender for another thread
    /// tx.send(data);             // Send data to channel
    /// rx.recv();                 // Receive data from channel
    /// ```
    fn sweep(&self, network: &IpNetwork) -> Result<Vec<DiscoveredHost>> {
        println!(
            "{} Starting ping sweep on {} with {} threads",
            "[*]".blue(),
            network,
            self.thread_count
        );

        // Collect all target IPs
        let targets: Vec<IpAddr> = network.iter().collect();
        let total = targets.len();

        // Create channel for collecting results
        // mpsc = Multi-Producer, Single-Consumer
        // tx (transmitter) can be cloned, rx (receiver) cannot
        let (tx, rx): (Sender<DiscoveredHost>, _) = channel();

        // Create progress bar
        let progress = Arc::new(Mutex::new(ProgressBar::new(total as u64)));
        {
            let pb = progress.lock().unwrap();
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
        }

        // Split targets into chunks for parallel processing
        let chunk_size = (total + self.thread_count - 1) / self.thread_count;
        let target_chunks: Vec<Vec<IpAddr>> =
            targets.chunks(chunk_size).map(|c| c.to_vec()).collect();

        let timeout = self.timeout;

        // Spawn worker threads
        let mut handles = Vec::new();

        for chunk in target_chunks {
            // Clone sender for this thread - this is the "multi-producer" part
            let tx_clone = tx.clone();
            let progress_clone = Arc::clone(&progress);

            // Move chunk ownership into thread
            // `move` keyword transfers ownership of captured variables
            let handle = thread::spawn(move || {
                for target in chunk {
                    let start = Instant::now();

                    // Try TCP connect to common ports as ping alternative
                    // (Raw ICMP requires root privileges)
                    let is_alive = Self::tcp_ping(&target, timeout);
                    let elapsed = start.elapsed().as_millis() as u64;

                    if is_alive {
                        // Send result through channel
                        let _ = tx_clone.send(DiscoveredHost {
                            ip_address: target,
                            mac_address: None,
                            hostname: None,
                            response_time_ms: elapsed,
                            services: Vec::new(),
                        });
                    }

                    progress_clone.lock().unwrap().inc(1);
                }
            });

            handles.push(handle);
        }

        // Drop original sender so channel closes when all threads finish
        // This is important! The channel won't close until all senders are dropped
        drop(tx);

        // Collect results from channel
        let mut results = Vec::new();
        while let Ok(host) = rx.recv() {
            results.push(host);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        progress.lock().unwrap().finish_with_message("Sweep complete");

        Ok(results)
    }

    /// TCP-based ping (SYN probe to common ports)
    fn tcp_ping(target: &IpAddr, timeout: Duration) -> bool {
        // Try connecting to common ports
        let common_ports = [80, 443, 22, 445, 139];

        for port in common_ports {
            let socket_addr = SocketAddr::new(*target, port);
            if TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
                return true;
            }
        }

        false
    }
}

/// Service detection scanner
///
/// # INTERMEDIATE PATTERN - Builder Pattern:
/// While not fully implemented here, service scanning could use
/// the builder pattern for configuration:
/// ```
/// ServiceScanner::new()
///     .with_timeout(Duration::from_secs(1))
///     .with_banner_grab(true)
///     .build()
/// ```
struct ServiceScanner {
    timeout: Duration,
    services_db: HashMap<u16, &'static str>,
}

impl ServiceScanner {
    fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            services_db: get_common_services(),
        }
    }

    /// Scan ports on a target host
    ///
    /// # PARALLEL SCANNING WITH RAYON:
    /// Rayon's par_iter() handles thread pool management automatically.
    /// It's much simpler than manual thread spawning for CPU-bound tasks.
    fn scan_host(&self, target: IpAddr, ports: &[u16]) -> Vec<ServiceInfo> {
        println!(
            "{} Scanning {} ports on {}",
            "[*]".blue(),
            ports.len(),
            target
        );

        let progress = ProgressBar::new(ports.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Thread-safe results collection
        let results: Arc<Mutex<Vec<ServiceInfo>>> = Arc::new(Mutex::new(Vec::new()));
        let timeout = self.timeout;
        let services_db = &self.services_db;

        // Parallel port scanning
        ports.par_iter().for_each(|&port| {
            let socket_addr = SocketAddr::new(target, port);

            if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
                // Port is open - try to identify service
                let service_name = services_db.get(&port).unwrap_or(&"Unknown").to_string();

                // Attempt banner grab with timeout
                let banner = Self::grab_banner(&mut stream, timeout);

                let results_clone = Arc::clone(&results);
                let mut services = results_clone.lock().unwrap();
                services.push(ServiceInfo {
                    port,
                    protocol: "TCP".to_string(),
                    service_name,
                    banner,
                });
            }
            progress.inc(1);
        });

        progress.finish_with_message("Scan complete");

        Arc::try_unwrap(results)
            .unwrap()
            .into_inner()
            .unwrap()
    }

    /// Attempt to grab service banner
    ///
    /// # BORROWING MUTABLE REFERENCE:
    /// `&mut TcpStream` - We need mutable access to read from the stream
    fn grab_banner(stream: &mut TcpStream, timeout: Duration) -> Option<String> {
        use std::io::{Read, Write};

        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        let mut buffer = [0u8; 1024];

        // Try reading immediately (some services send banner on connect)
        if let Ok(n) = stream.read(&mut buffer) {
            if n > 0 {
                return Some(
                    String::from_utf8_lossy(&buffer[..n])
                        .trim()
                        .chars()
                        .take(100)
                        .collect(),
                );
            }
        }

        // Try sending HTTP request for web services
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n");
        if let Ok(n) = stream.read(&mut buffer) {
            if n > 0 {
                return Some(
                    String::from_utf8_lossy(&buffer[..n])
                        .trim()
                        .lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(100)
                        .collect(),
                );
            }
        }

        None
    }
}

/// Parse port specification (comma-separated or range)
fn parse_ports(port_spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in port_spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // Range specification
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() == 2 {
                let start: u16 = range_parts[0].parse().context("Invalid port range start")?;
                let end: u16 = range_parts[1].parse().context("Invalid port range end")?;
                ports.extend(start..=end);
            }
        } else {
            // Single port
            let port: u16 = part.parse().context("Invalid port number")?;
            ports.push(port);
        }
    }

    Ok(ports)
}

/// Display discovered hosts in a formatted table
fn display_results(hosts: &[DiscoveredHost]) {
    if hosts.is_empty() {
        println!("{} No hosts discovered", "[!]".yellow());
        return;
    }

    println!("\n{}", "═".repeat(80).cyan());
    println!("{}", " DISCOVERED HOSTS ".cyan().bold());
    println!("{}\n", "═".repeat(80).cyan());

    for host in hosts {
        println!(
            "{} {} ({})",
            "[+]".green(),
            host.ip_address.to_string().white().bold(),
            host.mac_address.as_deref().unwrap_or("N/A").dimmed()
        );

        if let Some(ref hostname) = host.hostname {
            println!("    Hostname: {}", hostname);
        }

        if host.response_time_ms > 0 {
            println!("    Response: {}ms", host.response_time_ms);
        }

        if !host.services.is_empty() {
            println!("    Services:");
            for service in &host.services {
                println!(
                    "      - {}/{} ({})",
                    service.port, service.protocol, service.service_name
                );
                if let Some(ref banner) = service.banner {
                    println!("        Banner: {}", banner.dimmed());
                }
            }
        }
        println!();
    }

    println!("{}", "═".repeat(80).cyan());
    println!("Total hosts discovered: {}", hosts.len());
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Arp {
            interface,
            target,
            timeout,
        } => {
            let network: IpNetwork = target.parse().context("Invalid network specification")?;
            let scanner = ArpScanner::new(&interface, Duration::from_millis(timeout))?;
            let hosts = scanner.scan(&network)?;
            display_results(&hosts);

            // Output as JSON for scripting
            println!("\n{} JSON Output:", "[*]".blue());
            println!("{}", serde_json::to_string_pretty(&hosts)?);
        }

        Commands::Ping {
            target,
            threads,
            timeout,
        } => {
            let network: IpNetwork = target.parse().context("Invalid network specification")?;
            let sweeper = PingSweeper::new(Duration::from_millis(timeout), threads);
            let hosts = sweeper.sweep(&network)?;
            display_results(&hosts);
        }

        Commands::Services {
            target,
            ports,
            timeout,
        } => {
            let target_ip: IpAddr = target.parse().context("Invalid target IP")?;
            let port_list = parse_ports(&ports)?;
            let scanner = ServiceScanner::new(Duration::from_millis(timeout));
            let services = scanner.scan_host(target_ip, &port_list);

            if services.is_empty() {
                println!("{} No open ports found", "[!]".yellow());
            } else {
                println!("\n{}", "═".repeat(60).cyan());
                println!("{}", " DISCOVERED SERVICES ".cyan().bold());
                println!("{}\n", "═".repeat(60).cyan());

                for service in &services {
                    let status = "[OPEN]".green();
                    println!(
                        "{} {:<6} {:<15} {}",
                        status,
                        format!("{}/tcp", service.port),
                        service.service_name,
                        service.banner.as_deref().unwrap_or("").dimmed()
                    );
                }
            }
        }

        Commands::Interfaces => {
            println!("\n{}", "═".repeat(60).cyan());
            println!("{}", " NETWORK INTERFACES ".cyan().bold());
            println!("{}\n", "═".repeat(60).cyan());

            for interface in datalink::interfaces() {
                let status = if interface.is_up() {
                    "[UP]".green()
                } else {
                    "[DOWN]".red()
                };

                println!(
                    "{} {} ({})",
                    status,
                    interface.name.white().bold(),
                    interface
                        .mac
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "N/A".to_string())
                        .dimmed()
                );

                for ip in &interface.ips {
                    println!("    IP: {}", ip);
                }
                println!();
            }
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

    /// Test port parsing with comma-separated values
    #[test]
    fn test_parse_ports_comma_separated() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    /// Test port parsing with range
    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    /// Test port parsing with mixed format
    #[test]
    fn test_parse_ports_mixed() {
        let ports = parse_ports("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    /// Test common services database
    #[test]
    fn test_common_services() {
        let services = get_common_services();
        assert_eq!(services.get(&22), Some(&"SSH"));
        assert_eq!(services.get(&80), Some(&"HTTP"));
        assert_eq!(services.get(&443), Some(&"HTTPS"));
    }

    /// Test DiscoveredHost serialization
    #[test]
    fn test_host_serialization() {
        let host = DiscoveredHost {
            ip_address: "192.168.1.1".parse().unwrap(),
            mac_address: Some("00:11:22:33:44:55".to_string()),
            hostname: Some("router.local".to_string()),
            response_time_ms: 5,
            services: vec![],
        };

        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("00:11:22:33:44:55"));
    }

    /// Test Arc<Mutex<>> pattern
    #[test]
    fn test_arc_mutex_pattern() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let counter = Arc::new(Mutex::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            let handle = thread::spawn(move || {
                let mut num = counter_clone.lock().unwrap();
                *num += 1;
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(*counter.lock().unwrap(), 10);
    }

    /// Test channel communication
    #[test]
    fn test_channel_pattern() {
        use std::sync::mpsc::channel;
        use std::thread;

        let (tx, rx) = channel();

        thread::spawn(move || {
            tx.send("Hello from thread").unwrap();
        });

        let received = rx.recv().unwrap();
        assert_eq!(received, "Hello from thread");
    }

    /// Test ServiceInfo creation
    #[test]
    fn test_service_info() {
        let service = ServiceInfo {
            port: 22,
            protocol: "TCP".to_string(),
            service_name: "SSH".to_string(),
            banner: Some("OpenSSH 8.4".to_string()),
        };

        assert_eq!(service.port, 22);
        assert!(service.banner.is_some());
    }
}
