# IDS01: Packet Capture Engine

## Overview

| Property | Value |
|----------|-------|
| **ID** | IDS01 |
| **Difficulty** | Advanced |
| **Skills** | Network programming, libpcap, async I/O |
| **Prerequisites** | I01-I10, Linux networking basics |
| **Crates** | pcap, pnet, etherparse |

## What You'll Learn

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PACKET CAPTURE CONCEPTS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐       │
│  │   INTERFACE     │     │    CAPTURE      │     │    DECODE       │       │
│  │  ───────────    │     │  ───────────    │     │  ───────────    │       │
│  │  • libpcap      │────▶│  • BPF filter   │────▶│  • Ethernet     │       │
│  │  • AF_PACKET    │     │  • Promiscuous  │     │  • IP           │       │
│  │  • Raw socket   │     │  • Ring buffer  │     │  • TCP/UDP      │       │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘       │
│                                                                              │
│  Capture Methods:                                                            │
│  ─────────────────                                                          │
│  1. libpcap     - Portable, widely used, kernel bypass support              │
│  2. AF_PACKET   - Linux native, lower overhead                              │
│  3. DPDK        - User-space, 10+ Gbps (not covered here)                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## The Code

```rust
//! Packet Capture Engine for IDS
//!
//! Captures network traffic using libpcap and decodes packets
//! for analysis by the detection engine.
//!
//! # Requirements
//! - libpcap-dev installed
//! - CAP_NET_RAW capability or root access

use clap::Parser;
use pcap::{Capture, Device, Active};
use pnet::packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    icmp::IcmpPacket,
    Packet,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════
// COMMAND LINE INTERFACE
// ═══════════════════════════════════════════════════════════════════════════

/// Packet Capture Engine - Network traffic capture for IDS
#[derive(Parser, Debug)]
#[command(name = "packet-capture")]
#[command(about = "Capture and decode network packets")]
struct Args {
    /// Network interface to capture on (e.g., eth0, wlan0)
    #[arg(short, long)]
    interface: Option<String>,

    /// BPF filter expression (e.g., "tcp port 80")
    #[arg(short, long, default_value = "")]
    filter: String,

    /// Enable promiscuous mode
    #[arg(short, long)]
    promiscuous: bool,

    /// Capture buffer size in MB
    #[arg(short, long, default_value = "16")]
    buffer: i32,

    /// Snapshot length (max bytes per packet)
    #[arg(short, long, default_value = "65535")]
    snaplen: i32,

    /// Number of packets to capture (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    count: u64,

    /// Print packet details
    #[arg(short = 'v', long)]
    verbose: bool,

    /// List available interfaces and exit
    #[arg(short, long)]
    list: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

/// Decoded network packet
///
/// # Design Rationale
/// We decode packets into this struct for several reasons:
/// 1. Type safety - Can't accidentally access wrong fields
/// 2. Performance - Decode once, use many times
/// 3. Flexibility - Easy to add new fields later
/// 4. Separation - Decoding logic separate from analysis
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    /// Capture timestamp (microseconds since epoch)
    pub timestamp: u64,

    /// Ethernet source MAC
    pub eth_src: [u8; 6],

    /// Ethernet destination MAC
    pub eth_dst: [u8; 6],

    /// Ethernet type
    pub eth_type: u16,

    /// IP version (4 or 6)
    pub ip_version: u8,

    /// Source IP address
    pub src_ip: IpAddr,

    /// Destination IP address
    pub dst_ip: IpAddr,

    /// IP protocol (6=TCP, 17=UDP, 1=ICMP)
    pub protocol: u8,

    /// Time to live
    pub ttl: u8,

    /// Source port (0 if not TCP/UDP)
    pub src_port: u16,

    /// Destination port
    pub dst_port: u16,

    /// TCP flags (if TCP)
    pub tcp_flags: Option<TcpFlags>,

    /// Payload data
    pub payload: Vec<u8>,

    /// Total packet length
    pub length: usize,
}

/// TCP flag bits
///
/// # Flag Meanings
/// - FIN: Connection termination
/// - SYN: Connection initiation
/// - RST: Connection reset
/// - PSH: Push data immediately
/// - ACK: Acknowledgment
/// - URG: Urgent pointer valid
#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    /// Creates TcpFlags from raw flags byte
    ///
    /// # Bit Layout
    /// ```text
    /// Bit: 7  6  5  4  3  2  1  0
    ///      CWR ECE URG ACK PSH RST SYN FIN
    /// ```
    pub fn from_raw(flags: u8) -> Self {
        TcpFlags {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
        }
    }

    /// Returns string representation (e.g., "SYN,ACK")
    pub fn to_string(&self) -> String {
        let mut flags = Vec::new();
        if self.syn { flags.push("SYN"); }
        if self.ack { flags.push("ACK"); }
        if self.psh { flags.push("PSH"); }
        if self.rst { flags.push("RST"); }
        if self.fin { flags.push("FIN"); }
        if self.urg { flags.push("URG"); }
        flags.join(",")
    }
}

/// Capture statistics
///
/// # Why Atomic?
/// These counters are updated from the capture thread and read
/// from other threads (e.g., status display). AtomicU64 provides
/// lock-free thread-safe access.
#[derive(Debug)]
pub struct CaptureStats {
    /// Total packets received
    pub packets_received: AtomicU64,
    /// Packets dropped by kernel
    pub packets_dropped: AtomicU64,
    /// Packets dropped by interface
    pub packets_if_dropped: AtomicU64,
    /// Total bytes captured
    pub bytes_captured: AtomicU64,
}

impl CaptureStats {
    pub fn new() -> Self {
        CaptureStats {
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_if_dropped: AtomicU64::new(0),
            bytes_captured: AtomicU64::new(0),
        }
    }

    pub fn record_packet(&self, size: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_captured.fetch_add(size as u64, Ordering::Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PACKET CAPTURE ENGINE
// ═══════════════════════════════════════════════════════════════════════════

/// The main packet capture engine
///
/// # Architecture
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                    CaptureEngine                             │
/// │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
/// │  │   Config    │ │    Stats    │ │       Capture          ││
/// │  │             │ │  Arc<Stats> │ │   Option<Capture>      ││
/// │  └─────────────┘ └─────────────┘ └─────────────────────────┘│
/// │                                                              │
/// │  ┌───────────────────────────────────────────────────────┐  │
/// │  │                    Decoder                             │  │
/// │  │  parse_ethernet -> parse_ipv4/6 -> parse_tcp/udp       │  │
/// │  └───────────────────────────────────────────────────────┘  │
/// └─────────────────────────────────────────────────────────────┘
/// ```
pub struct CaptureEngine {
    /// Interface name
    interface: String,

    /// BPF filter
    filter: String,

    /// Promiscuous mode
    promiscuous: bool,

    /// Buffer size (MB)
    buffer_size: i32,

    /// Snapshot length
    snaplen: i32,

    /// Capture statistics (shared)
    stats: Arc<CaptureStats>,

    /// Running flag (for graceful shutdown)
    running: Arc<AtomicBool>,
}

impl CaptureEngine {
    /// Creates a new capture engine
    ///
    /// # Parameters
    /// - `interface`: Network interface name (e.g., "eth0")
    /// - `filter`: BPF filter expression
    /// - `promiscuous`: Enable promiscuous mode
    /// - `buffer_size`: Kernel buffer size in MB
    /// - `snaplen`: Maximum bytes to capture per packet
    pub fn new(
        interface: &str,
        filter: &str,
        promiscuous: bool,
        buffer_size: i32,
        snaplen: i32,
    ) -> Self {
        CaptureEngine {
            interface: interface.to_string(),
            filter: filter.to_string(),
            promiscuous,
            buffer_size,
            snaplen,
            stats: Arc::new(CaptureStats::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Lists available network interfaces
    ///
    /// # Return Value
    /// Vector of (name, description) tuples
    pub fn list_interfaces() -> Vec<(String, String)> {
        Device::list()
            .unwrap_or_default()
            .into_iter()
            .map(|d| {
                let desc = d.desc.clone().unwrap_or_default();
                (d.name, desc)
            })
            .collect()
    }

    /// Gets the default interface
    pub fn default_interface() -> Option<String> {
        Device::lookup()
            .ok()
            .flatten()
            .map(|d| d.name)
    }

    /// Opens the capture handle
    ///
    /// # BPF Filters
    /// Berkeley Packet Filter expressions let the kernel filter packets
    /// before they reach userspace. Examples:
    /// - `tcp port 80` - Only HTTP traffic
    /// - `host 192.168.1.1` - Traffic to/from specific host
    /// - `tcp[tcpflags] & tcp-syn != 0` - SYN packets
    ///
    /// # Error Handling
    /// Uses the `?` operator for clean error propagation
    fn open_capture(&self) -> Result<Capture<Active>, String> {
        let mut cap = Capture::from_device(self.interface.as_str())
            .map_err(|e| format!("Failed to open device: {}", e))?
            .promisc(self.promiscuous)
            .snaplen(self.snaplen)
            .buffer_size(self.buffer_size * 1024 * 1024) // Convert MB to bytes
            .timeout(1000) // 1 second timeout for non-blocking reads
            .open()
            .map_err(|e| format!("Failed to activate capture: {}", e))?;

        // Apply BPF filter if specified
        if !self.filter.is_empty() {
            cap.filter(&self.filter, true)
                .map_err(|e| format!("Failed to apply filter: {}", e))?;
            println!("[*] BPF filter applied: {}", self.filter);
        }

        Ok(cap)
    }

    /// Starts capturing packets
    ///
    /// # Callback Pattern
    /// We use a callback function to process each packet. This allows
    /// flexible handling without coupling the capture to specific logic.
    ///
    /// # Graceful Shutdown
    /// The `running` flag allows external code to stop the capture loop.
    pub fn start<F>(&self, mut callback: F) -> Result<(), String>
    where
        F: FnMut(DecodedPacket),
    {
        let mut cap = self.open_capture()?;

        self.running.store(true, Ordering::SeqCst);

        println!("[*] Capturing on interface: {}", self.interface);
        println!("[*] Press Ctrl+C to stop\n");

        while self.running.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    // Record stats
                    self.stats.record_packet(packet.len());

                    // Decode packet
                    if let Some(decoded) = self.decode_packet(packet.data) {
                        callback(decoded);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue
                    continue;
                }
                Err(e) => {
                    eprintln!("[-] Capture error: {}", e);
                    break;
                }
            }
        }

        // Get final stats from pcap
        if let Ok(pcap_stats) = cap.stats() {
            self.stats.packets_dropped.store(pcap_stats.dropped as u64, Ordering::Relaxed);
            self.stats.packets_if_dropped.store(pcap_stats.if_dropped as u64, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Stops the capture loop
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Gets current statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.packets_received.load(Ordering::Relaxed),
            self.stats.packets_dropped.load(Ordering::Relaxed),
            self.stats.packets_if_dropped.load(Ordering::Relaxed),
            self.stats.bytes_captured.load(Ordering::Relaxed),
        )
    }

    /// Decodes a raw packet into a DecodedPacket
    ///
    /// # Packet Structure
    /// ```text
    /// ┌──────────────────────────────────────────────────────────┐
    /// │                   Ethernet Frame                          │
    /// ├────────────────┬────────────────┬────────────────────────┤
    /// │ Dst MAC (6B)   │ Src MAC (6B)   │ EtherType (2B)         │
    /// ├────────────────┴────────────────┴────────────────────────┤
    /// │                     Payload                               │
    /// │  ┌─────────────────────────────────────────────────────┐ │
    /// │  │              IP Header (20+ bytes)                   │ │
    /// │  ├─────────────────────────────────────────────────────┤ │
    /// │  │           TCP/UDP Header (8-20 bytes)                │ │
    /// │  ├─────────────────────────────────────────────────────┤ │
    /// │  │                Application Data                      │ │
    /// │  └─────────────────────────────────────────────────────┘ │
    /// └──────────────────────────────────────────────────────────┘
    /// ```
    fn decode_packet(&self, data: &[u8]) -> Option<DecodedPacket> {
        // Parse Ethernet frame
        let eth_packet = EthernetPacket::new(data)?;

        // Get timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        // Extract MAC addresses
        let eth_src = eth_packet.get_source().octets();
        let eth_dst = eth_packet.get_destination().octets();
        let eth_type = eth_packet.get_ethertype().0;

        // Parse based on EtherType
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.decode_ipv4(eth_packet.payload(), timestamp, eth_src, eth_dst, eth_type)
            }
            EtherTypes::Ipv6 => {
                self.decode_ipv6(eth_packet.payload(), timestamp, eth_src, eth_dst, eth_type)
            }
            _ => None, // Skip non-IP traffic
        }
    }

    /// Decodes IPv4 packet
    fn decode_ipv4(
        &self,
        data: &[u8],
        timestamp: u64,
        eth_src: [u8; 6],
        eth_dst: [u8; 6],
        eth_type: u16,
    ) -> Option<DecodedPacket> {
        let ip_packet = Ipv4Packet::new(data)?;

        let src_ip = IpAddr::V4(ip_packet.get_source());
        let dst_ip = IpAddr::V4(ip_packet.get_destination());
        let protocol = ip_packet.get_next_level_protocol().0;
        let ttl = ip_packet.get_ttl();

        // Parse transport layer
        let (src_port, dst_port, tcp_flags, payload) = match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                self.decode_tcp(ip_packet.payload())
            }
            IpNextHeaderProtocols::Udp => {
                self.decode_udp(ip_packet.payload())
            }
            IpNextHeaderProtocols::Icmp => {
                (0, 0, None, ip_packet.payload().to_vec())
            }
            _ => (0, 0, None, ip_packet.payload().to_vec()),
        };

        Some(DecodedPacket {
            timestamp,
            eth_src,
            eth_dst,
            eth_type,
            ip_version: 4,
            src_ip,
            dst_ip,
            protocol,
            ttl,
            src_port,
            dst_port,
            tcp_flags,
            payload,
            length: data.len() + 14, // Add Ethernet header
        })
    }

    /// Decodes IPv6 packet
    fn decode_ipv6(
        &self,
        data: &[u8],
        timestamp: u64,
        eth_src: [u8; 6],
        eth_dst: [u8; 6],
        eth_type: u16,
    ) -> Option<DecodedPacket> {
        let ip_packet = Ipv6Packet::new(data)?;

        let src_ip = IpAddr::V6(ip_packet.get_source());
        let dst_ip = IpAddr::V6(ip_packet.get_destination());
        let protocol = ip_packet.get_next_header().0;
        let ttl = ip_packet.get_hop_limit();

        // Parse transport layer
        let (src_port, dst_port, tcp_flags, payload) = match ip_packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                self.decode_tcp(ip_packet.payload())
            }
            IpNextHeaderProtocols::Udp => {
                self.decode_udp(ip_packet.payload())
            }
            _ => (0, 0, None, ip_packet.payload().to_vec()),
        };

        Some(DecodedPacket {
            timestamp,
            eth_src,
            eth_dst,
            eth_type,
            ip_version: 6,
            src_ip,
            dst_ip,
            protocol,
            ttl,
            src_port,
            dst_port,
            tcp_flags,
            payload,
            length: data.len() + 14,
        })
    }

    /// Decodes TCP segment
    fn decode_tcp(&self, data: &[u8]) -> (u16, u16, Option<TcpFlags>, Vec<u8>) {
        if let Some(tcp) = TcpPacket::new(data) {
            let flags = TcpFlags::from_raw(tcp.get_flags());
            let data_offset = (tcp.get_data_offset() * 4) as usize;
            let payload = if data.len() > data_offset {
                data[data_offset..].to_vec()
            } else {
                Vec::new()
            };

            (tcp.get_source(), tcp.get_destination(), Some(flags), payload)
        } else {
            (0, 0, None, Vec::new())
        }
    }

    /// Decodes UDP datagram
    fn decode_udp(&self, data: &[u8]) -> (u16, u16, Option<TcpFlags>, Vec<u8>) {
        if let Some(udp) = UdpPacket::new(data) {
            let payload = if data.len() > 8 {
                data[8..].to_vec() // UDP header is 8 bytes
            } else {
                Vec::new()
            };

            (udp.get_source(), udp.get_destination(), None, payload)
        } else {
            (0, 0, None, Vec::new())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Formats MAC address as string
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Formats bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Gets protocol name from number
fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        _ => "OTHER",
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

fn main() {
    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║             PACKET CAPTURE ENGINE                               ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // List interfaces if requested
    if args.list {
        println!("[*] Available interfaces:");
        for (name, desc) in CaptureEngine::list_interfaces() {
            if desc.is_empty() {
                println!("    {}", name);
            } else {
                println!("    {} - {}", name, desc);
            }
        }
        return;
    }

    // Determine interface
    let interface = args.interface.unwrap_or_else(|| {
        CaptureEngine::default_interface()
            .expect("No default interface found. Specify one with --interface")
    });

    // Create capture engine
    let engine = CaptureEngine::new(
        &interface,
        &args.filter,
        args.promiscuous,
        args.buffer,
        args.snaplen,
    );

    // Set up Ctrl+C handler
    let running = engine.running.clone();
    ctrlc::set_handler(move || {
        println!("\n[*] Shutting down...");
        running.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    // Packet counter for --count option
    let mut packet_count: u64 = 0;

    // Start capture
    let result = engine.start(|packet| {
        packet_count += 1;

        if args.verbose {
            // Verbose output
            println!("[{}] {} {}:{} -> {}:{} ({}) len={}",
                packet_count,
                protocol_name(packet.protocol),
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port,
                packet.tcp_flags.map(|f| f.to_string()).unwrap_or_default(),
                packet.length,
            );
        } else {
            // Brief output
            println!("{} -> {} ({} bytes)",
                packet.src_ip,
                packet.dst_ip,
                packet.length,
            );
        }

        // Check packet count limit
        if args.count > 0 && packet_count >= args.count {
            engine.stop();
        }
    });

    // Print results
    match result {
        Ok(()) => {
            let (received, dropped, if_dropped, bytes) = engine.get_stats();
            println!("\n[*] Capture Statistics:");
            println!("    Packets received:  {}", received);
            println!("    Packets dropped:   {}", dropped);
            println!("    IF dropped:        {}", if_dropped);
            println!("    Bytes captured:    {}", format_bytes(bytes));
        }
        Err(e) => {
            eprintln!("[-] Error: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        // SYN flag only
        let flags = TcpFlags::from_raw(0x02);
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);

        // SYN+ACK
        let flags = TcpFlags::from_raw(0x12);
        assert!(flags.syn);
        assert!(flags.ack);

        // FIN+ACK
        let flags = TcpFlags::from_raw(0x11);
        assert!(flags.fin);
        assert!(flags.ack);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }
}
```

## Line-by-Line Breakdown

### Opening Capture Handle

```rust
let mut cap = Capture::from_device(self.interface.as_str())
    .map_err(|e| format!("Failed to open device: {}", e))?
    .promisc(self.promiscuous)
    .snaplen(self.snaplen)
    .buffer_size(self.buffer_size * 1024 * 1024)
    .timeout(1000)
    .open()
    .map_err(|e| format!("Failed to activate capture: {}", e))?;
```

**Line-by-Line:**
1. `Capture::from_device()` - Creates a capture builder for the interface
2. `.map_err()` - Converts pcap errors to our error type
3. `?` - Propagates errors up to caller
4. `.promisc()` - Sets promiscuous mode (capture all packets, not just ours)
5. `.snaplen()` - Maximum bytes to capture per packet
6. `.buffer_size()` - Kernel ring buffer size
7. `.timeout()` - Read timeout in milliseconds
8. `.open()` - Activates the capture

### BPF Filter

```rust
cap.filter(&self.filter, true)
    .map_err(|e| format!("Failed to apply filter: {}", e))?;
```

The second parameter (`true`) means optimize the filter. BPF filters are compiled to bytecode that runs in the kernel, filtering packets before they're copied to userspace.

### Decoding Ethernet

```rust
let eth_packet = EthernetPacket::new(data)?;
let eth_src = eth_packet.get_source().octets();
let eth_dst = eth_packet.get_destination().octets();
```

`EthernetPacket::new(data)` creates a zero-copy view of the packet data. The `?` uses Rust's `Option` for error handling - returns `None` if parsing fails.

## Red Team Perspective

### Evading Packet Capture
```
1. Fragmentation
   └─► Split packets across fragments to evade pattern matching

2. Encryption
   └─► TLS/SSL prevents content inspection (but not metadata)

3. Protocol tunneling
   └─► Hide traffic inside allowed protocols (DNS, HTTPS)

4. Traffic blending
   └─► Match normal traffic patterns to avoid anomaly detection

5. MAC spoofing
   └─► Change MAC address to avoid MAC-based filtering
```

### Testing Your Evasion
- Use Wireshark to verify packet structure
- Test against Snort/Suricata rules
- Capture your own traffic to analyze patterns

## Blue Team Perspective

### Improving Capture
```
1. Full packet capture
   └─► Store complete packets for forensics

2. Multi-interface capture
   └─► Monitor all network segments

3. Hardware timestamping
   └─► Precise timing for correlation

4. Traffic mirroring
   └─► Use SPAN ports for passive capture

5. Out-of-band management
   └─► Don't capture on production interfaces
```

### Integration Points
- Feed packets to Suricata/Snort
- Store in Elasticsearch for analysis
- Integrate with SIEM systems
- Build network baselines

## Exercises

### Exercise 1: Add VLAN Support
Extend the decoder to handle 802.1Q VLAN-tagged frames. The VLAN tag adds 4 bytes after the source MAC.

### Exercise 2: Protocol Statistics
Add per-protocol packet and byte counters. Display a summary at the end.

### Exercise 3: Live Rate Calculation
Calculate and display packets-per-second and bytes-per-second in real-time.

### Exercise 4: PCAP File Writing
Add the ability to write captured packets to a PCAP file for later analysis.

### Exercise 5: Multi-Interface Capture
Modify the engine to capture from multiple interfaces simultaneously using threads.

---

**← Previous:** [Chapter 9 Overview](../README.md) | **Next →** [IDS02: Rule Engine](../02_Rule_Engine/README.md)
