//! # Packet Builder - Rust Security Bible
//!
//! A comprehensive tool for building and analyzing custom network packets.
//! Understanding packet structure is fundamental for security research,
//! network analysis, and penetration testing.
//!
//! ## Features
//! - Build Ethernet, IPv4, TCP, UDP, ICMP packets
//! - Analyze packet hex dumps
//! - Calculate checksums
//! - Generate test packets for fuzzing
//! - Parse pcap-style hex data
//!
//! ## Security Applications
//! - Protocol analysis
//! - Packet crafting for testing
//! - Network fuzzing
//! - IDS/IPS testing
//!
//! ## Note
//! Sending raw packets typically requires root/admin privileges.
//! This tool focuses on packet construction and analysis.

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use thiserror::Error;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Custom error types for packet operations
#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Invalid packet size: expected {expected}, got {actual}")]
    InvalidSize { expected: usize, actual: usize },

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Invalid MAC address: {0}")]
    InvalidMac(String),

    #[error("Invalid port: {0}")]
    InvalidPort(String),

    #[error("Invalid hex data: {0}")]
    InvalidHex(String),

    #[error("Packet construction failed: {0}")]
    ConstructionFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

pub type PacketResult<T> = Result<T, PacketError>;

// =============================================================================
// CLI INTERFACE
// =============================================================================

/// Packet Builder - Network packet construction tool
#[derive(Parser, Debug)]
#[command(name = "packet_builder")]
#[command(author = "Security Developer")]
#[command(version = "1.0")]
#[command(about = "Build and analyze custom network packets")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build an Ethernet frame
    Ethernet {
        /// Source MAC address
        #[arg(short, long, default_value = "00:00:00:00:00:01")]
        src: String,

        /// Destination MAC address
        #[arg(short, long, default_value = "ff:ff:ff:ff:ff:ff")]
        dst: String,

        /// EtherType (ipv4, ipv6, arp)
        #[arg(short, long, default_value = "ipv4")]
        ether_type: EtherTypeArg,

        /// Payload as hex string
        #[arg(short, long)]
        payload: Option<String>,
    },

    /// Build an IPv4 packet
    Ipv4 {
        /// Source IP address
        #[arg(short, long, default_value = "192.168.1.1")]
        src: String,

        /// Destination IP address
        #[arg(short, long, default_value = "192.168.1.2")]
        dst: String,

        /// Protocol (tcp, udp, icmp)
        #[arg(short, long, default_value = "tcp")]
        protocol: IpProtocolArg,

        /// TTL value
        #[arg(long, default_value = "64")]
        ttl: u8,

        /// Payload as hex string
        #[arg(long)]
        payload: Option<String>,
    },

    /// Build a TCP segment
    Tcp {
        /// Source port
        #[arg(short, long, default_value = "12345")]
        src_port: u16,

        /// Destination port
        #[arg(short, long, default_value = "80")]
        dst_port: u16,

        /// TCP flags (syn, ack, fin, rst, psh, urg, comma-separated)
        #[arg(short, long, default_value = "syn")]
        flags: String,

        /// Sequence number
        #[arg(long)]
        seq: Option<u32>,

        /// Acknowledgment number
        #[arg(long)]
        ack: Option<u32>,

        /// Window size
        #[arg(short, long, default_value = "65535")]
        window: u16,

        /// Payload as hex or string
        #[arg(long)]
        payload: Option<String>,
    },

    /// Build a UDP datagram
    Udp {
        /// Source port
        #[arg(short, long, default_value = "12345")]
        src_port: u16,

        /// Destination port
        #[arg(short, long, default_value = "53")]
        dst_port: u16,

        /// Payload as hex or string
        #[arg(long)]
        payload: Option<String>,
    },

    /// Build an ICMP packet
    Icmp {
        /// ICMP type (echo-request, echo-reply, dest-unreachable)
        #[arg(short, long, default_value = "echo-request")]
        icmp_type: IcmpTypeArg,

        /// ICMP code
        #[arg(short, long, default_value = "0")]
        code: u8,

        /// Identifier (for echo)
        #[arg(long, default_value = "1")]
        id: u16,

        /// Sequence number (for echo)
        #[arg(long, default_value = "1")]
        seq: u16,

        /// Payload
        #[arg(long)]
        payload: Option<String>,
    },

    /// Build a complete TCP/IP packet
    Full {
        /// Source IP
        #[arg(long, default_value = "192.168.1.1")]
        src_ip: String,

        /// Destination IP
        #[arg(long, default_value = "192.168.1.2")]
        dst_ip: String,

        /// Source port
        #[arg(long, default_value = "12345")]
        src_port: u16,

        /// Destination port
        #[arg(long, default_value = "80")]
        dst_port: u16,

        /// TCP flags
        #[arg(long, default_value = "syn")]
        flags: String,

        /// Payload
        #[arg(long)]
        payload: Option<String>,
    },

    /// Analyze a packet from hex dump
    Analyze {
        /// Hex dump of the packet
        hex_data: String,

        /// Packet type (ethernet, ipv4, tcp, udp)
        #[arg(short, long, default_value = "ethernet")]
        packet_type: PacketTypeArg,
    },

    /// Generate random test packets for fuzzing
    Fuzz {
        /// Packet type to fuzz
        #[arg(short, long, default_value = "tcp")]
        packet_type: PacketTypeArg,

        /// Number of packets to generate
        #[arg(short, long, default_value = "5")]
        count: usize,
    },

    /// Calculate checksum for data
    Checksum {
        /// Hex data to checksum
        data: String,

        /// Checksum type
        #[arg(short, long, default_value = "ip")]
        checksum_type: ChecksumType,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum EtherTypeArg {
    Ipv4,
    Ipv6,
    Arp,
}

#[derive(Debug, Clone, ValueEnum)]
enum IpProtocolArg {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, ValueEnum)]
enum IcmpTypeArg {
    EchoRequest,
    EchoReply,
    DestUnreachable,
    TimeExceeded,
}

#[derive(Debug, Clone, ValueEnum)]
enum PacketTypeArg {
    Ethernet,
    Ipv4,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, ValueEnum)]
enum ChecksumType {
    Ip,
    Tcp,
    Udp,
    Icmp,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Ethernet frame representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetFrame {
    pub src_mac: String,
    pub dst_mac: String,
    pub ether_type: u16,
    pub payload: Vec<u8>,
}

/// IPv4 packet representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: String,
    pub dst_ip: String,
}

/// TCP segment representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: Vec<String>,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

/// UDP datagram representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// ICMP packet representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub data: Vec<u8>,
}

// =============================================================================
// PACKET BUILDER IMPLEMENTATION
// =============================================================================

/// Packet builder for constructing network packets
pub struct PacketBuilder;

impl PacketBuilder {
    /// Build an Ethernet frame
    pub fn build_ethernet(
        src: &str,
        dst: &str,
        ether_type: EtherType,
        payload: &[u8],
    ) -> PacketResult<Vec<u8>> {
        let src_mac: MacAddr = src
            .parse()
            .map_err(|_| PacketError::InvalidMac(src.to_string()))?;
        let dst_mac: MacAddr = dst
            .parse()
            .map_err(|_| PacketError::InvalidMac(dst.to_string()))?;

        // Ethernet header is 14 bytes
        let total_len = 14 + payload.len();
        let mut buffer = vec![0u8; total_len];

        let mut ethernet = MutableEthernetPacket::new(&mut buffer)
            .ok_or_else(|| PacketError::ConstructionFailed("Ethernet packet creation failed".to_string()))?;

        ethernet.set_source(src_mac);
        ethernet.set_destination(dst_mac);
        ethernet.set_ethertype(ether_type);
        ethernet.set_payload(payload);

        Ok(buffer)
    }

    /// Build an IPv4 packet
    pub fn build_ipv4(
        src: &str,
        dst: &str,
        protocol: u8,
        ttl: u8,
        payload: &[u8],
    ) -> PacketResult<Vec<u8>> {
        let src_ip: Ipv4Addr = src
            .parse()
            .map_err(|_| PacketError::InvalidIp(src.to_string()))?;
        let dst_ip: Ipv4Addr = dst
            .parse()
            .map_err(|_| PacketError::InvalidIp(dst.to_string()))?;

        // IPv4 header (20 bytes minimum) + payload
        let total_len = 20 + payload.len();
        let mut buffer = vec![0u8; total_len];

        let mut ipv4 = MutableIpv4Packet::new(&mut buffer)
            .ok_or_else(|| PacketError::ConstructionFailed("IPv4 packet creation failed".to_string()))?;

        ipv4.set_version(4);
        ipv4.set_header_length(5); // 20 bytes / 4 = 5
        ipv4.set_dscp(0);
        ipv4.set_ecn(0);
        ipv4.set_total_length(total_len as u16);
        ipv4.set_identification(rand::thread_rng().gen());
        ipv4.set_flags(Ipv4Flags::DontFragment);
        ipv4.set_fragment_offset(0);
        ipv4.set_ttl(ttl);
        ipv4.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocol(protocol));
        ipv4.set_source(src_ip);
        ipv4.set_destination(dst_ip);
        ipv4.set_payload(payload);

        // Calculate checksum
        let checksum = pnet::packet::ipv4::checksum(&ipv4.to_immutable());
        ipv4.set_checksum(checksum);

        Ok(buffer)
    }

    /// Build a TCP segment
    pub fn build_tcp(
        src_port: u16,
        dst_port: u16,
        flags: u16,
        seq: u32,
        ack: u32,
        window: u16,
        payload: &[u8],
    ) -> PacketResult<Vec<u8>> {
        // TCP header (20 bytes minimum) + payload
        let total_len = 20 + payload.len();
        let mut buffer = vec![0u8; total_len];

        let mut tcp = MutableTcpPacket::new(&mut buffer)
            .ok_or_else(|| PacketError::ConstructionFailed("TCP packet creation failed".to_string()))?;

        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5); // 20 bytes / 4 = 5
        tcp.set_flags(flags);
        tcp.set_window(window);
        tcp.set_urgent_ptr(0);
        tcp.set_payload(payload);

        // Note: TCP checksum requires pseudo-header with IP addresses
        // Setting to 0 for now - would need IP context for proper calculation
        tcp.set_checksum(0);

        Ok(buffer)
    }

    /// Build a UDP datagram
    pub fn build_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> PacketResult<Vec<u8>> {
        // UDP header is 8 bytes + payload
        let total_len = 8 + payload.len();
        let mut buffer = vec![0u8; total_len];

        let mut udp = MutableUdpPacket::new(&mut buffer)
            .ok_or_else(|| PacketError::ConstructionFailed("UDP packet creation failed".to_string()))?;

        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(total_len as u16);
        udp.set_payload(payload);

        // Note: UDP checksum requires pseudo-header
        udp.set_checksum(0);

        Ok(buffer)
    }

    /// Build an ICMP packet
    pub fn build_icmp(
        icmp_type: u8,
        code: u8,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> PacketResult<Vec<u8>> {
        // ICMP header is 8 bytes + payload
        let total_len = 8 + payload.len();
        let mut buffer = vec![0u8; total_len];

        let mut icmp = MutableIcmpPacket::new(&mut buffer)
            .ok_or_else(|| PacketError::ConstructionFailed("ICMP packet creation failed".to_string()))?;

        icmp.set_icmp_type(pnet::packet::icmp::IcmpType(icmp_type));
        icmp.set_icmp_code(IcmpCode(code));

        // Set identifier and sequence in payload area for echo packets
        if icmp_type == 8 || icmp_type == 0 {
            // Echo request/reply
            let mut icmp_payload = vec![0u8; 4 + payload.len()];
            icmp_payload[0] = (id >> 8) as u8;
            icmp_payload[1] = (id & 0xff) as u8;
            icmp_payload[2] = (seq >> 8) as u8;
            icmp_payload[3] = (seq & 0xff) as u8;
            icmp_payload[4..].copy_from_slice(payload);
            icmp.set_payload(&icmp_payload);
        } else {
            icmp.set_payload(payload);
        }

        // Calculate checksum
        let checksum = pnet::packet::icmp::checksum(&icmp.to_immutable());
        icmp.set_checksum(checksum);

        Ok(buffer)
    }

    /// Build a complete TCP/IP packet
    pub fn build_full_tcp(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        flags: u16,
        payload: &[u8],
    ) -> PacketResult<Vec<u8>> {
        // Build TCP segment
        let tcp_packet = Self::build_tcp(
            src_port,
            dst_port,
            flags,
            rand::thread_rng().gen(),
            0,
            65535,
            payload,
        )?;

        // Build IPv4 packet with TCP as payload
        Self::build_ipv4(src_ip, dst_ip, 6, 64, &tcp_packet) // 6 = TCP
    }

    /// Parse TCP flags from string
    pub fn parse_tcp_flags(flags_str: &str) -> u16 {
        let mut flags: u16 = 0;

        for flag in flags_str.to_lowercase().split(',') {
            match flag.trim() {
                "fin" => flags |= TcpFlags::FIN,
                "syn" => flags |= TcpFlags::SYN,
                "rst" => flags |= TcpFlags::RST,
                "psh" => flags |= TcpFlags::PSH,
                "ack" => flags |= TcpFlags::ACK,
                "urg" => flags |= TcpFlags::URG,
                "ece" => flags |= TcpFlags::ECE,
                "cwr" => flags |= TcpFlags::CWR,
                _ => {}
            }
        }

        flags
    }

    /// Convert TCP flags to string representation
    pub fn flags_to_string(flags: u16) -> Vec<String> {
        let mut result = Vec::new();

        if flags & TcpFlags::FIN != 0 {
            result.push("FIN".to_string());
        }
        if flags & TcpFlags::SYN != 0 {
            result.push("SYN".to_string());
        }
        if flags & TcpFlags::RST != 0 {
            result.push("RST".to_string());
        }
        if flags & TcpFlags::PSH != 0 {
            result.push("PSH".to_string());
        }
        if flags & TcpFlags::ACK != 0 {
            result.push("ACK".to_string());
        }
        if flags & TcpFlags::URG != 0 {
            result.push("URG".to_string());
        }

        result
    }
}

// =============================================================================
// PACKET ANALYZER
// =============================================================================

/// Packet analyzer for parsing raw packet data
pub struct PacketAnalyzer;

impl PacketAnalyzer {
    /// Analyze an Ethernet frame
    pub fn analyze_ethernet(data: &[u8]) -> PacketResult<EthernetFrame> {
        let ethernet = EthernetPacket::new(data)
            .ok_or_else(|| PacketError::ParseError("Invalid Ethernet frame".to_string()))?;

        Ok(EthernetFrame {
            src_mac: ethernet.get_source().to_string(),
            dst_mac: ethernet.get_destination().to_string(),
            ether_type: ethernet.get_ethertype().0,
            payload: ethernet.payload().to_vec(),
        })
    }

    /// Analyze an IPv4 packet
    pub fn analyze_ipv4(data: &[u8]) -> PacketResult<Ipv4Header> {
        let ipv4 = Ipv4Packet::new(data)
            .ok_or_else(|| PacketError::ParseError("Invalid IPv4 packet".to_string()))?;

        Ok(Ipv4Header {
            version: ipv4.get_version(),
            ihl: ipv4.get_header_length(),
            dscp: ipv4.get_dscp(),
            ecn: ipv4.get_ecn(),
            total_length: ipv4.get_total_length(),
            identification: ipv4.get_identification(),
            flags: ipv4.get_flags(),
            fragment_offset: ipv4.get_fragment_offset(),
            ttl: ipv4.get_ttl(),
            protocol: ipv4.get_next_level_protocol().0,
            checksum: ipv4.get_checksum(),
            src_ip: ipv4.get_source().to_string(),
            dst_ip: ipv4.get_destination().to_string(),
        })
    }

    /// Analyze a TCP segment
    pub fn analyze_tcp(data: &[u8]) -> PacketResult<TcpHeader> {
        let tcp = TcpPacket::new(data)
            .ok_or_else(|| PacketError::ParseError("Invalid TCP segment".to_string()))?;

        Ok(TcpHeader {
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
            seq_num: tcp.get_sequence(),
            ack_num: tcp.get_acknowledgement(),
            data_offset: tcp.get_data_offset(),
            flags: PacketBuilder::flags_to_string(tcp.get_flags()),
            window: tcp.get_window(),
            checksum: tcp.get_checksum(),
            urgent_ptr: tcp.get_urgent_ptr(),
        })
    }

    /// Analyze a UDP datagram
    pub fn analyze_udp(data: &[u8]) -> PacketResult<UdpHeader> {
        let udp = UdpPacket::new(data)
            .ok_or_else(|| PacketError::ParseError("Invalid UDP datagram".to_string()))?;

        Ok(UdpHeader {
            src_port: udp.get_source(),
            dst_port: udp.get_destination(),
            length: udp.get_length(),
            checksum: udp.get_checksum(),
        })
    }

    /// Analyze an ICMP packet
    pub fn analyze_icmp(data: &[u8]) -> PacketResult<IcmpHeader> {
        let icmp = IcmpPacket::new(data)
            .ok_or_else(|| PacketError::ParseError("Invalid ICMP packet".to_string()))?;

        Ok(IcmpHeader {
            icmp_type: icmp.get_icmp_type().0,
            code: icmp.get_icmp_code().0,
            checksum: icmp.get_checksum(),
            data: icmp.payload().to_vec(),
        })
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Calculate Internet checksum
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() - 1 {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

/// Generate random packet for fuzzing
pub fn generate_fuzz_packet(packet_type: &PacketTypeArg) -> PacketResult<Vec<u8>> {
    let mut rng = rand::thread_rng();

    match packet_type {
        PacketTypeArg::Tcp => {
            let payload_len = rng.gen_range(0..100);
            let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();
            PacketBuilder::build_tcp(
                rng.gen(),
                rng.gen(),
                rng.gen::<u16>() & 0x3f, // Valid flag bits
                rng.gen(),
                rng.gen(),
                rng.gen(),
                &payload,
            )
        }
        PacketTypeArg::Udp => {
            let payload_len = rng.gen_range(0..100);
            let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();
            PacketBuilder::build_udp(rng.gen(), rng.gen(), &payload)
        }
        PacketTypeArg::Icmp => {
            let payload_len = rng.gen_range(0..56);
            let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();
            PacketBuilder::build_icmp(rng.gen_range(0..19), rng.gen(), rng.gen(), rng.gen(), &payload)
        }
        PacketTypeArg::Ipv4 => {
            let payload_len = rng.gen_range(0..100);
            let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();
            let src = format!(
                "{}.{}.{}.{}",
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>()
            );
            let dst = format!(
                "{}.{}.{}.{}",
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>()
            );
            PacketBuilder::build_ipv4(&src, &dst, rng.gen(), rng.gen(), &payload)
        }
        PacketTypeArg::Ethernet => {
            let payload_len = rng.gen_range(46..100);
            let payload: Vec<u8> = (0..payload_len).map(|_| rng.gen()).collect();
            let src = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>()
            );
            let dst = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>()
            );
            PacketBuilder::build_ethernet(&src, &dst, EtherTypes::Ipv4, &payload)
        }
    }
}

/// Parse hex string to bytes
fn parse_hex(hex_str: &str) -> PacketResult<Vec<u8>> {
    let clean = hex_str.replace(' ', "").replace('\n', "").replace("0x", "");
    hex::decode(&clean).map_err(|e| PacketError::InvalidHex(e.to_string()))
}

/// Format bytes as hex dump
fn hex_dump(data: &[u8]) -> String {
    let mut output = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        output.push_str(&format!("{:04x}  ", i * 16));

        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        // Pad if less than 16 bytes
        for j in chunk.len()..16 {
            output.push_str("   ");
            if j == 7 {
                output.push(' ');
            }
        }

        output.push_str(" |");
        for byte in chunk {
            if *byte >= 32 && *byte < 127 {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }

    output
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!(
        "{}",
        "Packet Builder - Network Packet Construction Tool"
            .bright_cyan()
            .bold()
    );
    println!("{}", "=".repeat(50));

    match cli.command {
        Commands::Ethernet {
            src,
            dst,
            ether_type,
            payload,
        } => {
            let ether = match ether_type {
                EtherTypeArg::Ipv4 => EtherTypes::Ipv4,
                EtherTypeArg::Ipv6 => EtherTypes::Ipv6,
                EtherTypeArg::Arp => EtherTypes::Arp,
            };

            let payload_bytes = payload
                .as_ref()
                .map(|p| parse_hex(p))
                .transpose()?
                .unwrap_or_default();

            println!("\n{}", "Building Ethernet Frame".cyan());
            println!("Source MAC: {}", src.green());
            println!("Dest MAC: {}", dst.green());
            println!("EtherType: {:?}", ether_type);

            let packet = PacketBuilder::build_ethernet(&src, &dst, ether, &payload_bytes)?;

            println!("\n{}:", "Packet Hex Dump".bold());
            print!("{}", hex_dump(&packet));
            println!("\n{}: {}", "Raw Hex".bold(), hex::encode(&packet));
        }

        Commands::Ipv4 {
            src,
            dst,
            protocol,
            ttl,
            payload,
        } => {
            let proto = match protocol {
                IpProtocolArg::Tcp => 6,
                IpProtocolArg::Udp => 17,
                IpProtocolArg::Icmp => 1,
            };

            let payload_bytes = payload
                .as_ref()
                .map(|p| parse_hex(p))
                .transpose()?
                .unwrap_or_default();

            println!("\n{}", "Building IPv4 Packet".cyan());
            println!("Source IP: {}", src.green());
            println!("Dest IP: {}", dst.green());
            println!("Protocol: {:?}", protocol);
            println!("TTL: {}", ttl);

            let packet = PacketBuilder::build_ipv4(&src, &dst, proto, ttl, &payload_bytes)?;

            println!("\n{}:", "Packet Hex Dump".bold());
            print!("{}", hex_dump(&packet));
            println!("\n{}: {}", "Raw Hex".bold(), hex::encode(&packet));
        }

        Commands::Tcp {
            src_port,
            dst_port,
            flags,
            seq,
            ack,
            window,
            payload,
        } => {
            let flag_bits = PacketBuilder::parse_tcp_flags(&flags);
            let seq_num = seq.unwrap_or_else(|| rand::thread_rng().gen());
            let ack_num = ack.unwrap_or(0);

            let payload_bytes = payload
                .as_ref()
                .map(|p| {
                    if p.chars().all(|c| c.is_ascii_hexdigit() || c == ' ') {
                        parse_hex(p)
                    } else {
                        Ok(p.as_bytes().to_vec())
                    }
                })
                .transpose()?
                .unwrap_or_default();

            println!("\n{}", "Building TCP Segment".cyan());
            println!("Source Port: {}", src_port.to_string().green());
            println!("Dest Port: {}", dst_port.to_string().green());
            println!("Flags: {}", flags.yellow());
            println!("Seq: {}", seq_num);
            println!("Ack: {}", ack_num);
            println!("Window: {}", window);

            let packet = PacketBuilder::build_tcp(
                src_port,
                dst_port,
                flag_bits,
                seq_num,
                ack_num,
                window,
                &payload_bytes,
            )?;

            println!("\n{}:", "Packet Hex Dump".bold());
            print!("{}", hex_dump(&packet));
            println!("\n{}: {}", "Raw Hex".bold(), hex::encode(&packet));
        }

        Commands::Udp {
            src_port,
            dst_port,
            payload,
        } => {
            let payload_bytes = payload
                .as_ref()
                .map(|p| {
                    if p.chars().all(|c| c.is_ascii_hexdigit() || c == ' ') {
                        parse_hex(p)
                    } else {
                        Ok(p.as_bytes().to_vec())
                    }
                })
                .transpose()?
                .unwrap_or_default();

            println!("\n{}", "Building UDP Datagram".cyan());
            println!("Source Port: {}", src_port.to_string().green());
            println!("Dest Port: {}", dst_port.to_string().green());

            let packet = PacketBuilder::build_udp(src_port, dst_port, &payload_bytes)?;

            println!("\n{}:", "Packet Hex Dump".bold());
            print!("{}", hex_dump(&packet));
            println!("\n{}: {}", "Raw Hex".bold(), hex::encode(&packet));
        }

        Commands::Icmp {
            icmp_type,
            code,
            id,
            seq,
            payload,
        } => {
            let type_num = match icmp_type {
                IcmpTypeArg::EchoRequest => 8,
                IcmpTypeArg::EchoReply => 0,
                IcmpTypeArg::DestUnreachable => 3,
                IcmpTypeArg::TimeExceeded => 11,
            };

            let payload_bytes = payload
                .as_ref()
                .map(|p| parse_hex(p))
                .transpose()?
                .unwrap_or_else(|| b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec());

            println!("\n{}", "Building ICMP Packet".cyan());
            println!("Type: {:?}", icmp_type);
            println!("Code: {}", code);
            println!("ID: {}", id);
            println!("Seq: {}", seq);

            let packet = PacketBuilder::build_icmp(type_num, code, id, seq, &payload_bytes)?;

            println!("\n{}:", "Packet Hex Dump".bold());
            print!("{}", hex_dump(&packet));
            println!("\n{}: {}", "Raw Hex".bold(), hex::encode(&packet));
        }

        Commands::Full {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flags,
            payload,
        } => {
            let flag_bits = PacketBuilder::parse_tcp_flags(&flags);
            let payload_bytes = payload
                .as_ref()
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_default();

            println!("\n{}", "Building Complete TCP/IP Packet".cyan());
            println!("Source: {}:{}", src_ip.green(), src_port);
            println!("Dest: {}:{}", dst_ip.green(), dst_port);
            println!("Flags: {}", flags.yellow());

            let packet = PacketBuilder::build_full_tcp(
                &src_ip,
                &dst_ip,
                src_port,
                dst_port,
                flag_bits,
                &payload_bytes,
            )?;

            println!("\n{}:", "Packet Hex Dump".bold());
            print!("{}", hex_dump(&packet));
            println!("\n{}: {}", "Raw Hex".bold(), hex::encode(&packet));
        }

        Commands::Analyze { hex_data, packet_type } => {
            let data = parse_hex(&hex_data)?;

            println!("\n{}", "Analyzing Packet".cyan());
            println!("Data length: {} bytes", data.len());

            match packet_type {
                PacketTypeArg::Ethernet => {
                    let frame = PacketAnalyzer::analyze_ethernet(&data)?;
                    println!("\n{}", serde_json::to_string_pretty(&frame)?);
                }
                PacketTypeArg::Ipv4 => {
                    let header = PacketAnalyzer::analyze_ipv4(&data)?;
                    println!("\n{}", serde_json::to_string_pretty(&header)?);
                }
                PacketTypeArg::Tcp => {
                    let header = PacketAnalyzer::analyze_tcp(&data)?;
                    println!("\n{}", serde_json::to_string_pretty(&header)?);
                }
                PacketTypeArg::Udp => {
                    let header = PacketAnalyzer::analyze_udp(&data)?;
                    println!("\n{}", serde_json::to_string_pretty(&header)?);
                }
                PacketTypeArg::Icmp => {
                    let header = PacketAnalyzer::analyze_icmp(&data)?;
                    println!("\n{}", serde_json::to_string_pretty(&header)?);
                }
            }
        }

        Commands::Fuzz { packet_type, count } => {
            println!(
                "\n{} {} {:?} packets",
                "Generating".cyan(),
                count,
                packet_type
            );

            for i in 0..count {
                let packet = generate_fuzz_packet(&packet_type)?;
                println!(
                    "\n{} {}:\n{}",
                    "Packet".bold(),
                    i + 1,
                    hex::encode(&packet)
                );
            }
        }

        Commands::Checksum { data, checksum_type } => {
            let bytes = parse_hex(&data)?;

            println!("\n{}", "Calculating Checksum".cyan());
            println!("Data: {} bytes", bytes.len());

            let checksum = calculate_checksum(&bytes);
            println!(
                "{} {:?} checksum: {:#06x} ({})",
                "Calculated".green(),
                checksum_type,
                checksum,
                checksum
            );
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
    fn test_build_ethernet() {
        let result = PacketBuilder::build_ethernet(
            "00:11:22:33:44:55",
            "ff:ff:ff:ff:ff:ff",
            EtherTypes::Ipv4,
            &[0x45, 0x00],
        );
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert_eq!(packet.len(), 16); // 14 header + 2 payload
    }

    #[test]
    fn test_build_ipv4() {
        let result = PacketBuilder::build_ipv4("192.168.1.1", "192.168.1.2", 6, 64, &[]);
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert_eq!(packet.len(), 20); // Minimum IPv4 header
    }

    #[test]
    fn test_build_tcp() {
        let result = PacketBuilder::build_tcp(12345, 80, TcpFlags::SYN, 1000, 0, 65535, &[]);
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert_eq!(packet.len(), 20); // Minimum TCP header
    }

    #[test]
    fn test_build_udp() {
        let result = PacketBuilder::build_udp(12345, 53, b"test");
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert_eq!(packet.len(), 12); // 8 header + 4 payload
    }

    #[test]
    fn test_build_icmp() {
        let result = PacketBuilder::build_icmp(8, 0, 1, 1, b"test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_tcp_flags() {
        let flags = PacketBuilder::parse_tcp_flags("syn,ack");
        assert!(flags & TcpFlags::SYN != 0);
        assert!(flags & TcpFlags::ACK != 0);
        assert!(flags & TcpFlags::FIN == 0);
    }

    #[test]
    fn test_flags_to_string() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        let result = PacketBuilder::flags_to_string(flags);
        assert!(result.contains(&"SYN".to_string()));
        assert!(result.contains(&"ACK".to_string()));
    }

    #[test]
    fn test_analyze_tcp() {
        let packet = PacketBuilder::build_tcp(12345, 80, TcpFlags::SYN, 1000, 0, 65535, &[]).unwrap();
        let result = PacketAnalyzer::analyze_tcp(&packet);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert_eq!(header.src_port, 12345);
        assert_eq!(header.dst_port, 80);
    }

    #[test]
    fn test_analyze_udp() {
        let packet = PacketBuilder::build_udp(12345, 53, &[]).unwrap();
        let result = PacketAnalyzer::analyze_udp(&packet);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert_eq!(header.src_port, 12345);
        assert_eq!(header.dst_port, 53);
    }

    #[test]
    fn test_checksum() {
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00];
        let checksum = calculate_checksum(&data);
        assert!(checksum > 0);
    }

    #[test]
    fn test_parse_hex() {
        let result = parse_hex("48 65 6c 6c 6f");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_parse_hex_no_spaces() {
        let result = parse_hex("48656c6c6f");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_invalid_mac() {
        let result = PacketBuilder::build_ethernet(
            "invalid",
            "ff:ff:ff:ff:ff:ff",
            EtherTypes::Ipv4,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ip() {
        let result = PacketBuilder::build_ipv4("invalid", "192.168.1.2", 6, 64, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fuzz_tcp() {
        let result = generate_fuzz_packet(&PacketTypeArg::Tcp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fuzz_udp() {
        let result = generate_fuzz_packet(&PacketTypeArg::Udp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_dump() {
        let data = b"Hello, World!";
        let dump = hex_dump(data);
        assert!(dump.contains("48 65 6c 6c"));
        assert!(dump.contains("|Hello"));
    }
}
