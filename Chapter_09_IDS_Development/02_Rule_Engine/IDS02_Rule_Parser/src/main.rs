//! IDS02_Rule_Parser - Parse Snort/Suricata-like IDS Rules
//!
//! This module implements a parser for intrusion detection system rules
//! following the Snort/Suricata rule format. These rules define patterns
//! that match malicious network traffic.
//!
//! # Rule Format
//! ```text
//! action protocol src_ip src_port -> dst_ip dst_port (options)
//! ```
//!
//! # Example Rules
//! ```text
//! alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001;)
//! drop udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"DNS Query"; dns_query; sid:1000002;)
//! ```
//!
//! # IDS Concepts
//! - **Action**: What to do when rule matches (alert, drop, pass, log)
//! - **Protocol**: Network protocol (tcp, udp, icmp, ip)
//! - **Flow**: Connection direction and state
//! - **Content**: Byte patterns to match in payload
//! - **PCRE**: Perl-compatible regular expressions for complex patterns

use clap::{Parser, Subcommand};
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during rule parsing
#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Invalid rule action: {0}")]
    InvalidAction(String),

    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid port specification: {0}")]
    InvalidPort(String),

    #[error("Invalid direction operator: {0}")]
    InvalidDirection(String),

    #[error("Missing rule options")]
    MissingOptions,

    #[error("Invalid option format: {0}")]
    InvalidOption(String),

    #[error("Missing required option: {0}")]
    MissingRequiredOption(String),

    #[error("Duplicate SID: {0}")]
    DuplicateSid(u32),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

// =============================================================================
// Rule Components
// =============================================================================

/// Rule action - what to do when traffic matches
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Action {
    /// Generate an alert
    Alert,
    /// Log the packet
    Log,
    /// Allow the packet (whitelist)
    Pass,
    /// Drop the packet (IPS mode)
    Drop,
    /// Reject with RST/ICMP unreachable
    Reject,
    /// Silent drop
    Sdrop,
}

impl Action {
    fn parse(s: &str) -> Result<Self, RuleError> {
        match s.to_lowercase().as_str() {
            "alert" => Ok(Action::Alert),
            "log" => Ok(Action::Log),
            "pass" => Ok(Action::Pass),
            "drop" => Ok(Action::Drop),
            "reject" => Ok(Action::Reject),
            "sdrop" => Ok(Action::Sdrop),
            _ => Err(RuleError::InvalidAction(s.to_string())),
        }
    }
}

/// Network protocol
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,  // Any IP protocol
    Http,
    Dns,
    Tls,
    Ssh,
    Ftp,
    Smtp,
}

impl Protocol {
    fn parse(s: &str) -> Result<Self, RuleError> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "ip" => Ok(Protocol::Ip),
            "http" => Ok(Protocol::Http),
            "dns" => Ok(Protocol::Dns),
            "tls" | "ssl" => Ok(Protocol::Tls),
            "ssh" => Ok(Protocol::Ssh),
            "ftp" => Ok(Protocol::Ftp),
            "smtp" => Ok(Protocol::Smtp),
            _ => Err(RuleError::InvalidProtocol(s.to_string())),
        }
    }
}

/// IP address specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpSpec {
    /// Any IP address
    Any,
    /// Single IP address
    Single(IpAddr),
    /// CIDR notation (e.g., 192.168.1.0/24)
    Cidr(IpAddr, u8),
    /// Variable reference (e.g., $HOME_NET)
    Variable(String),
    /// Negated specification
    Negated(Box<IpSpec>),
    /// Group of IP specs
    Group(Vec<IpSpec>),
}

impl IpSpec {
    fn parse(s: &str) -> Result<Self, RuleError> {
        let s = s.trim();

        // Handle negation
        if let Some(rest) = s.strip_prefix('!') {
            return Ok(IpSpec::Negated(Box::new(IpSpec::parse(rest)?)));
        }

        // Handle "any"
        if s.to_lowercase() == "any" {
            return Ok(IpSpec::Any);
        }

        // Handle variable
        if s.starts_with('$') {
            return Ok(IpSpec::Variable(s.to_string()));
        }

        // Handle group [ip1,ip2,ip3]
        if s.starts_with('[') && s.ends_with(']') {
            let inner = &s[1..s.len()-1];
            let specs: Result<Vec<_>, _> = inner
                .split(',')
                .map(|part| IpSpec::parse(part.trim()))
                .collect();
            return Ok(IpSpec::Group(specs?));
        }

        // Handle CIDR
        if s.contains('/') {
            let parts: Vec<&str> = s.split('/').collect();
            if parts.len() == 2 {
                let ip: IpAddr = parts[0].parse()
                    .map_err(|_| RuleError::InvalidIpAddress(s.to_string()))?;
                let prefix: u8 = parts[1].parse()
                    .map_err(|_| RuleError::InvalidIpAddress(s.to_string()))?;
                return Ok(IpSpec::Cidr(ip, prefix));
            }
        }

        // Handle single IP
        s.parse::<IpAddr>()
            .map(IpSpec::Single)
            .map_err(|_| RuleError::InvalidIpAddress(s.to_string()))
    }

    /// Check if an IP matches this specification
    pub fn matches(&self, ip: IpAddr, variables: &HashMap<String, Vec<IpAddr>>) -> bool {
        match self {
            IpSpec::Any => true,
            IpSpec::Single(spec_ip) => ip == *spec_ip,
            IpSpec::Cidr(net_ip, prefix) => {
                // Simple CIDR matching
                match (ip, net_ip) {
                    (IpAddr::V4(ip), IpAddr::V4(net)) => {
                        let mask = if *prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
                        (u32::from(ip) & mask) == (u32::from(*net) & mask)
                    }
                    _ => false,
                }
            }
            IpSpec::Variable(var) => {
                if let Some(ips) = variables.get(var) {
                    ips.contains(&ip)
                } else {
                    false
                }
            }
            IpSpec::Negated(inner) => !inner.matches(ip, variables),
            IpSpec::Group(specs) => specs.iter().any(|s| s.matches(ip, variables)),
        }
    }
}

/// Port specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortSpec {
    /// Any port
    Any,
    /// Single port
    Single(u16),
    /// Port range (start:end)
    Range(u16, u16),
    /// Variable reference
    Variable(String),
    /// Negated specification
    Negated(Box<PortSpec>),
    /// Group of port specs
    Group(Vec<PortSpec>),
}

impl PortSpec {
    fn parse(s: &str) -> Result<Self, RuleError> {
        let s = s.trim();

        // Handle negation
        if let Some(rest) = s.strip_prefix('!') {
            return Ok(PortSpec::Negated(Box::new(PortSpec::parse(rest)?)));
        }

        // Handle "any"
        if s.to_lowercase() == "any" {
            return Ok(PortSpec::Any);
        }

        // Handle variable
        if s.starts_with('$') {
            return Ok(PortSpec::Variable(s.to_string()));
        }

        // Handle group [port1,port2,port3]
        if s.starts_with('[') && s.ends_with(']') {
            let inner = &s[1..s.len()-1];
            let specs: Result<Vec<_>, _> = inner
                .split(',')
                .map(|part| PortSpec::parse(part.trim()))
                .collect();
            return Ok(PortSpec::Group(specs?));
        }

        // Handle range (start:end or :end or start:)
        if s.contains(':') {
            let parts: Vec<&str> = s.split(':').collect();
            let start = if parts[0].is_empty() { 0 } else {
                parts[0].parse().map_err(|_| RuleError::InvalidPort(s.to_string()))?
            };
            let end = if parts.len() < 2 || parts[1].is_empty() { 65535 } else {
                parts[1].parse().map_err(|_| RuleError::InvalidPort(s.to_string()))?
            };
            return Ok(PortSpec::Range(start, end));
        }

        // Handle single port
        s.parse::<u16>()
            .map(PortSpec::Single)
            .map_err(|_| RuleError::InvalidPort(s.to_string()))
    }

    /// Check if a port matches this specification
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Single(p) => port == *p,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
            PortSpec::Variable(_) => true, // Variables need runtime resolution
            PortSpec::Negated(inner) => !inner.matches(port),
            PortSpec::Group(specs) => specs.iter().any(|s| s.matches(port)),
        }
    }
}

/// Direction of the rule
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Direction {
    /// Unidirectional (source -> destination)
    Unidirectional,
    /// Bidirectional (source <> destination)
    Bidirectional,
}

impl Direction {
    fn parse(s: &str) -> Result<Self, RuleError> {
        match s {
            "->" => Ok(Direction::Unidirectional),
            "<>" => Ok(Direction::Bidirectional),
            _ => Err(RuleError::InvalidDirection(s.to_string())),
        }
    }
}

// =============================================================================
// Rule Options
// =============================================================================

/// Content match modifiers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentModifiers {
    /// Case-insensitive matching
    pub nocase: bool,
    /// Offset from start of payload
    pub offset: Option<u32>,
    /// Search depth limit
    pub depth: Option<u32>,
    /// Distance from previous match
    pub distance: Option<i32>,
    /// Within N bytes of previous match
    pub within: Option<u32>,
    /// Match at start of payload
    pub startswith: bool,
    /// Match at end of payload
    pub endswith: bool,
    /// Fast pattern (use for prefilter)
    pub fast_pattern: bool,
}

/// Content pattern to match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMatch {
    /// The pattern bytes
    pub pattern: Vec<u8>,
    /// Original string representation
    pub original: String,
    /// Whether this is a negated match
    pub negated: bool,
    /// Modifiers for this content
    pub modifiers: ContentModifiers,
}

/// PCRE pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcreMatch {
    /// The regex pattern
    pub pattern: String,
    /// PCRE modifiers (i, s, m, etc.)
    pub modifiers: String,
    /// Whether this is negated
    pub negated: bool,
}

/// Flow direction and state options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowOptions {
    /// Match on client to server traffic
    pub to_server: bool,
    /// Match on server to client traffic
    pub to_client: bool,
    /// Match on established connections
    pub established: bool,
    /// Match on stateless traffic
    pub stateless: bool,
    /// Only match on stream (reassembled) data
    pub only_stream: bool,
    /// No stream matching
    pub no_stream: bool,
}

/// Threshold options for rate limiting alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdOptions {
    /// Type: limit, threshold, or both
    pub threshold_type: String,
    /// Track by source or destination
    pub track: String,
    /// Count threshold
    pub count: u32,
    /// Time window in seconds
    pub seconds: u32,
}

/// HTTP-specific options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpOptions {
    pub http_method: bool,
    pub http_uri: bool,
    pub http_raw_uri: bool,
    pub http_header: bool,
    pub http_raw_header: bool,
    pub http_cookie: bool,
    pub http_user_agent: bool,
    pub http_host: bool,
    pub http_content_type: bool,
    pub http_content_len: bool,
    pub http_start: bool,
    pub http_protocol: bool,
    pub http_stat_code: bool,
    pub http_stat_msg: bool,
    pub http_request_body: bool,
    pub http_response_body: bool,
    pub http_server: bool,
}

/// All parsed rule options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleOptions {
    /// Message describing the rule
    pub msg: Option<String>,
    /// Signature ID (unique identifier)
    pub sid: Option<u32>,
    /// Rule revision
    pub rev: Option<u32>,
    /// Classification type
    pub classtype: Option<String>,
    /// Priority (1-4, 1 is highest)
    pub priority: Option<u8>,
    /// Reference URLs/CVEs
    pub references: Vec<String>,
    /// Content patterns to match
    pub content: Vec<ContentMatch>,
    /// PCRE patterns
    pub pcre: Vec<PcreMatch>,
    /// Flow options
    pub flow: FlowOptions,
    /// Threshold/rate limiting
    pub threshold: Option<ThresholdOptions>,
    /// HTTP-specific options
    pub http: HttpOptions,
    /// Byte test operations
    pub byte_tests: Vec<String>,
    /// Byte jump operations
    pub byte_jumps: Vec<String>,
    /// IP type of service
    pub tos: Option<u8>,
    /// IP TTL
    pub ttl: Option<String>,
    /// IP ID
    pub id: Option<u16>,
    /// Fragment offset
    pub fragoffset: Option<String>,
    /// Fragment bits
    pub fragbits: Option<String>,
    /// IP options
    pub ipopts: Option<String>,
    /// Payload size check
    pub dsize: Option<String>,
    /// TCP flags
    pub flags: Option<String>,
    /// TCP window size
    pub window: Option<String>,
    /// TCP sequence number
    pub seq: Option<u32>,
    /// TCP acknowledgment number
    pub ack: Option<u32>,
    /// ICMP type
    pub itype: Option<u8>,
    /// ICMP code
    pub icode: Option<u8>,
    /// ICMP ID
    pub icmp_id: Option<u16>,
    /// ICMP sequence
    pub icmp_seq: Option<u16>,
    /// Detection filter
    pub detection_filter: Option<String>,
    /// Metadata tags
    pub metadata: Vec<String>,
    /// Target of attack
    pub target: Option<String>,
    /// GeoIP matching
    pub geoip: Option<String>,
    /// File data matching
    pub filedata: bool,
    /// File name matching
    pub filename: Option<String>,
    /// File extension matching
    pub fileext: Option<String>,
    /// File magic matching
    pub filemagic: Option<String>,
    /// File MD5 matching
    pub filemd5: Option<String>,
    /// File SHA256 matching
    pub filesha256: Option<String>,
    /// File size matching
    pub filesize: Option<String>,
}

// =============================================================================
// Complete Rule Structure
// =============================================================================

/// A complete parsed IDS rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Original rule text
    pub raw: String,
    /// Rule action
    pub action: Action,
    /// Protocol
    pub protocol: Protocol,
    /// Source IP specification
    pub src_ip: IpSpec,
    /// Source port specification
    pub src_port: PortSpec,
    /// Direction
    pub direction: Direction,
    /// Destination IP specification
    pub dst_ip: IpSpec,
    /// Destination port specification
    pub dst_port: PortSpec,
    /// Rule options
    pub options: RuleOptions,
    /// Whether rule is enabled
    pub enabled: bool,
}

// =============================================================================
// Rule Parser
// =============================================================================

/// Parser for IDS rules
pub struct RuleParser {
    /// Variable definitions (e.g., $HOME_NET)
    variables: HashMap<String, String>,
    /// Compiled regex for content hex patterns
    hex_pattern: Regex,
    /// Rules indexed by SID
    rules_by_sid: HashMap<u32, usize>,
}

impl RuleParser {
    /// Create a new rule parser
    pub fn new() -> Self {
        RuleParser {
            variables: HashMap::new(),
            hex_pattern: Regex::new(r"\|([0-9A-Fa-f\s]+)\|").unwrap(),
            rules_by_sid: HashMap::new(),
        }
    }

    /// Set a variable
    pub fn set_variable(&mut self, name: &str, value: &str) {
        self.variables.insert(name.to_string(), value.to_string());
    }

    /// Load default variables
    pub fn load_default_variables(&mut self) {
        self.set_variable("$HOME_NET", "any");
        self.set_variable("$EXTERNAL_NET", "any");
        self.set_variable("$HTTP_PORTS", "80,443,8080");
        self.set_variable("$SSH_PORTS", "22");
        self.set_variable("$DNS_PORTS", "53");
        self.set_variable("$SMTP_PORTS", "25,465,587");
        self.set_variable("$SQL_PORTS", "1433,3306,5432");
    }

    /// Parse a single rule
    pub fn parse_rule(&mut self, line: &str) -> Result<Rule, RuleError> {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            return Err(RuleError::ParseError("Empty or comment line".to_string()));
        }

        // Handle disabled rules (starting with #)
        let (enabled, line) = if line.starts_with('#') {
            (false, line[1..].trim())
        } else {
            (true, line)
        };

        debug!("Parsing rule: {}", line);

        // Find the options section (everything in parentheses)
        let options_start = line.find('(')
            .ok_or(RuleError::MissingOptions)?;
        let options_end = line.rfind(')')
            .ok_or(RuleError::MissingOptions)?;

        let header = &line[..options_start].trim();
        let options_str = &line[options_start + 1..options_end];

        // Parse header: action protocol src_ip src_port direction dst_ip dst_port
        let header_parts: Vec<&str> = header.split_whitespace().collect();

        if header_parts.len() < 7 {
            return Err(RuleError::ParseError(
                format!("Invalid header: expected 7 parts, got {}", header_parts.len())
            ));
        }

        let action = Action::parse(header_parts[0])?;
        let protocol = Protocol::parse(header_parts[1])?;
        let src_ip = IpSpec::parse(header_parts[2])?;
        let src_port = PortSpec::parse(header_parts[3])?;
        let direction = Direction::parse(header_parts[4])?;
        let dst_ip = IpSpec::parse(header_parts[5])?;
        let dst_port = PortSpec::parse(header_parts[6])?;

        // Parse options
        let options = self.parse_options(options_str)?;

        // Check for duplicate SID
        if let Some(sid) = options.sid {
            if self.rules_by_sid.contains_key(&sid) {
                warn!("Duplicate SID: {}", sid);
            }
        }

        Ok(Rule {
            raw: line.to_string(),
            action,
            protocol,
            src_ip,
            src_port,
            direction,
            dst_ip,
            dst_port,
            options,
            enabled,
        })
    }

    /// Parse rule options
    fn parse_options(&self, options_str: &str) -> Result<RuleOptions, RuleError> {
        let mut options = RuleOptions::default();
        let mut current_content: Option<ContentMatch> = None;

        // Split options by semicolon, handling quoted strings
        let option_parts = self.split_options(options_str);

        for part in option_parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            // Split option into keyword and value
            let (keyword, value) = if let Some(colon_pos) = part.find(':') {
                let k = part[..colon_pos].trim();
                let v = part[colon_pos + 1..].trim();
                // Remove surrounding quotes if present
                let v = v.trim_matches('"').trim_matches('\'');
                (k, Some(v))
            } else {
                (part, None)
            };

            // Process each option keyword
            match keyword.to_lowercase().as_str() {
                "msg" => {
                    options.msg = value.map(|s| s.to_string());
                }
                "sid" => {
                    options.sid = value.and_then(|s| s.parse().ok());
                }
                "rev" => {
                    options.rev = value.and_then(|s| s.parse().ok());
                }
                "classtype" => {
                    options.classtype = value.map(|s| s.to_string());
                }
                "priority" => {
                    options.priority = value.and_then(|s| s.parse().ok());
                }
                "reference" => {
                    if let Some(v) = value {
                        options.references.push(v.to_string());
                    }
                }
                "content" => {
                    // Save previous content if exists
                    if let Some(content) = current_content.take() {
                        options.content.push(content);
                    }

                    // Parse new content
                    if let Some(v) = value {
                        let (pattern, negated) = if v.starts_with('!') {
                            (&v[1..], true)
                        } else {
                            (v, false)
                        };

                        let pattern = pattern.trim_matches('"');
                        let bytes = self.parse_content_pattern(pattern)?;

                        current_content = Some(ContentMatch {
                            pattern: bytes,
                            original: pattern.to_string(),
                            negated,
                            modifiers: ContentModifiers::default(),
                        });
                    }
                }
                "nocase" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.nocase = true;
                    }
                }
                "offset" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.offset = value.and_then(|s| s.parse().ok());
                    }
                }
                "depth" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.depth = value.and_then(|s| s.parse().ok());
                    }
                }
                "distance" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.distance = value.and_then(|s| s.parse().ok());
                    }
                }
                "within" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.within = value.and_then(|s| s.parse().ok());
                    }
                }
                "startswith" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.startswith = true;
                    }
                }
                "endswith" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.endswith = true;
                    }
                }
                "fast_pattern" => {
                    if let Some(ref mut content) = current_content {
                        content.modifiers.fast_pattern = true;
                    }
                }
                "pcre" => {
                    if let Some(v) = value {
                        let pcre = self.parse_pcre(v)?;
                        options.pcre.push(pcre);
                    }
                }
                "flow" => {
                    if let Some(v) = value {
                        options.flow = self.parse_flow(v);
                    }
                }
                "threshold" | "detection_filter" => {
                    if let Some(v) = value {
                        options.threshold = self.parse_threshold(v);
                    }
                }
                // HTTP options
                "http_method" => options.http.http_method = true,
                "http_uri" | "http.uri" => options.http.http_uri = true,
                "http_raw_uri" => options.http.http_raw_uri = true,
                "http_header" | "http.header" => options.http.http_header = true,
                "http_raw_header" => options.http.http_raw_header = true,
                "http_cookie" | "http.cookie" => options.http.http_cookie = true,
                "http_user_agent" | "http.user_agent" => options.http.http_user_agent = true,
                "http_host" | "http.host" => options.http.http_host = true,
                "http_content_type" => options.http.http_content_type = true,
                "http_content_len" => options.http.http_content_len = true,
                "http_start" => options.http.http_start = true,
                "http_protocol" => options.http.http_protocol = true,
                "http_stat_code" | "http.stat_code" => options.http.http_stat_code = true,
                "http_stat_msg" => options.http.http_stat_msg = true,
                "http_request_body" | "http.request_body" => options.http.http_request_body = true,
                "http_response_body" | "http.response_body" => options.http.http_response_body = true,
                "http_server" => options.http.http_server = true,
                // TCP options
                "flags" => options.flags = value.map(|s| s.to_string()),
                "window" => options.window = value.map(|s| s.to_string()),
                "seq" => options.seq = value.and_then(|s| s.parse().ok()),
                "ack" => options.ack = value.and_then(|s| s.parse().ok()),
                // ICMP options
                "itype" => options.itype = value.and_then(|s| s.parse().ok()),
                "icode" => options.icode = value.and_then(|s| s.parse().ok()),
                "icmp_id" => options.icmp_id = value.and_then(|s| s.parse().ok()),
                "icmp_seq" => options.icmp_seq = value.and_then(|s| s.parse().ok()),
                // IP options
                "tos" => options.tos = value.and_then(|s| s.parse().ok()),
                "ttl" => options.ttl = value.map(|s| s.to_string()),
                "id" => options.id = value.and_then(|s| s.parse().ok()),
                "fragoffset" => options.fragoffset = value.map(|s| s.to_string()),
                "fragbits" => options.fragbits = value.map(|s| s.to_string()),
                "ipopts" => options.ipopts = value.map(|s| s.to_string()),
                "dsize" => options.dsize = value.map(|s| s.to_string()),
                // Byte operations
                "byte_test" => {
                    if let Some(v) = value {
                        options.byte_tests.push(v.to_string());
                    }
                }
                "byte_jump" => {
                    if let Some(v) = value {
                        options.byte_jumps.push(v.to_string());
                    }
                }
                // Metadata and misc
                "metadata" => {
                    if let Some(v) = value {
                        options.metadata.push(v.to_string());
                    }
                }
                "target" => options.target = value.map(|s| s.to_string()),
                "geoip" => options.geoip = value.map(|s| s.to_string()),
                // File options
                "filedata" => options.filedata = true,
                "filename" => options.filename = value.map(|s| s.to_string()),
                "fileext" => options.fileext = value.map(|s| s.to_string()),
                "filemagic" => options.filemagic = value.map(|s| s.to_string()),
                "filemd5" => options.filemd5 = value.map(|s| s.to_string()),
                "filesha256" => options.filesha256 = value.map(|s| s.to_string()),
                "filesize" => options.filesize = value.map(|s| s.to_string()),
                _ => {
                    debug!("Unknown option: {}", keyword);
                }
            }
        }

        // Save final content if exists
        if let Some(content) = current_content {
            options.content.push(content);
        }

        Ok(options)
    }

    /// Split options by semicolon, respecting quoted strings
    fn split_options(&self, s: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut quote_char = '"';
        let mut escape_next = false;

        for c in s.chars() {
            if escape_next {
                current.push(c);
                escape_next = false;
                continue;
            }

            if c == '\\' {
                escape_next = true;
                current.push(c);
                continue;
            }

            if c == '"' || c == '\'' {
                if !in_quotes {
                    in_quotes = true;
                    quote_char = c;
                } else if c == quote_char {
                    in_quotes = false;
                }
                current.push(c);
            } else if c == ';' && !in_quotes {
                if !current.trim().is_empty() {
                    result.push(current.trim().to_string());
                }
                current = String::new();
            } else {
                current.push(c);
            }
        }

        if !current.trim().is_empty() {
            result.push(current.trim().to_string());
        }

        result
    }

    /// Parse content pattern with hex sequences
    fn parse_content_pattern(&self, pattern: &str) -> Result<Vec<u8>, RuleError> {
        let mut result = Vec::new();
        let mut remaining = pattern;

        while let Some(start) = remaining.find('|') {
            // Add bytes before the hex sequence
            result.extend(remaining[..start].as_bytes());

            // Find end of hex sequence
            if let Some(end) = remaining[start + 1..].find('|') {
                let hex_str: String = remaining[start + 1..start + 1 + end]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();

                let bytes = hex::decode(&hex_str)
                    .map_err(|e| RuleError::ParseError(format!("Invalid hex: {}", e)))?;
                result.extend(bytes);

                remaining = &remaining[start + end + 2..];
            } else {
                return Err(RuleError::ParseError("Unclosed hex sequence".to_string()));
            }
        }

        // Add remaining bytes
        result.extend(remaining.as_bytes());

        Ok(result)
    }

    /// Parse PCRE pattern
    fn parse_pcre(&self, s: &str) -> Result<PcreMatch, RuleError> {
        let s = s.trim();
        let negated = s.starts_with('!');
        let s = if negated { &s[1..] } else { s };

        // PCRE format: /pattern/modifiers or "pattern"modifiers
        if s.starts_with('/') {
            if let Some(last_slash) = s[1..].rfind('/') {
                let pattern = s[1..last_slash + 1].to_string();
                let modifiers = s[last_slash + 2..].to_string();
                return Ok(PcreMatch { pattern, modifiers, negated });
            }
        }

        // Fallback: treat whole thing as pattern
        Ok(PcreMatch {
            pattern: s.to_string(),
            modifiers: String::new(),
            negated,
        })
    }

    /// Parse flow options
    fn parse_flow(&self, s: &str) -> FlowOptions {
        let mut flow = FlowOptions::default();

        for part in s.split(',') {
            match part.trim() {
                "to_server" | "from_client" => flow.to_server = true,
                "to_client" | "from_server" => flow.to_client = true,
                "established" => flow.established = true,
                "stateless" => flow.stateless = true,
                "only_stream" => flow.only_stream = true,
                "no_stream" => flow.no_stream = true,
                _ => {}
            }
        }

        flow
    }

    /// Parse threshold options
    fn parse_threshold(&self, s: &str) -> Option<ThresholdOptions> {
        let mut threshold_type = String::new();
        let mut track = String::new();
        let mut count = 0u32;
        let mut seconds = 0u32;

        for part in s.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once(' ') {
                match key.trim() {
                    "type" => threshold_type = value.trim().to_string(),
                    "track" => track = value.trim().to_string(),
                    "count" => count = value.trim().parse().unwrap_or(0),
                    "seconds" => seconds = value.trim().parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        if !threshold_type.is_empty() {
            Some(ThresholdOptions {
                threshold_type,
                track,
                count,
                seconds,
            })
        } else {
            None
        }
    }

    /// Parse a rule file
    pub fn parse_file(&mut self, path: &PathBuf) -> Result<Vec<Rule>, RuleError> {
        let content = fs::read_to_string(path)?;
        self.parse_rules(&content)
    }

    /// Parse multiple rules from string
    pub fn parse_rules(&mut self, content: &str) -> Result<Vec<Rule>, RuleError> {
        let mut rules = Vec::new();
        let mut multiline = String::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle line continuation
            if line.ends_with('\\') {
                multiline.push_str(&line[..line.len() - 1]);
                multiline.push(' ');
                continue;
            }

            let full_line = if multiline.is_empty() {
                line.to_string()
            } else {
                let result = format!("{}{}", multiline, line);
                multiline.clear();
                result
            };

            match self.parse_rule(&full_line) {
                Ok(rule) => {
                    if let Some(sid) = rule.options.sid {
                        self.rules_by_sid.insert(sid, rules.len());
                    }
                    rules.push(rule);
                }
                Err(e) => {
                    warn!("Failed to parse rule: {} - {}", e, full_line);
                }
            }
        }

        info!("Parsed {} rules", rules.len());
        Ok(rules)
    }
}

impl Default for RuleParser {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Rule Validator
// =============================================================================

/// Validates parsed rules for correctness and best practices
pub struct RuleValidator;

impl RuleValidator {
    /// Validate a rule and return warnings/errors
    pub fn validate(rule: &Rule) -> Vec<String> {
        let mut issues = Vec::new();

        // Check for required options
        if rule.options.sid.is_none() {
            issues.push("Missing SID - every rule should have a unique signature ID".to_string());
        }

        if rule.options.msg.is_none() {
            issues.push("Missing msg - rule should have a descriptive message".to_string());
        }

        // Check for performance issues
        if rule.options.content.is_empty() && rule.options.pcre.is_empty() {
            issues.push("No content or pcre - rule may match too broadly".to_string());
        }

        // Check for fast_pattern
        if rule.options.content.len() > 1 {
            let has_fast_pattern = rule.options.content.iter()
                .any(|c| c.modifiers.fast_pattern);
            if !has_fast_pattern {
                issues.push("Consider adding fast_pattern to one content for better performance".to_string());
            }
        }

        // Check for small content patterns
        for content in &rule.options.content {
            if content.pattern.len() < 4 && !content.modifiers.fast_pattern {
                issues.push(format!(
                    "Short content pattern '{}' may cause performance issues",
                    content.original
                ));
            }
        }

        // Check flow for TCP rules
        if matches!(rule.protocol, Protocol::Tcp) {
            if !rule.options.flow.established && !rule.options.flow.stateless {
                issues.push("TCP rule without flow:established may match invalid packets".to_string());
            }
        }

        issues
    }
}

// =============================================================================
// CLI Interface
// =============================================================================

#[derive(Parser)]
#[command(name = "ids02_rule_parser")]
#[command(about = "Parse and validate Snort/Suricata-like IDS rules")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse a single rule
    Parse {
        /// The rule to parse
        rule: String,
    },
    /// Parse rules from a file
    File {
        /// Path to the rules file
        path: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Validate rules
    Validate {
        /// Path to the rules file
        path: PathBuf,
    },
    /// Show example rules
    Examples,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    let cli = Cli::parse();
    let mut parser = RuleParser::new();
    parser.load_default_variables();

    match cli.command {
        Commands::Parse { rule } => {
            println!("{}", "Parsing Rule".cyan().bold());
            println!("{}", "=".repeat(60));

            match parser.parse_rule(&rule) {
                Ok(parsed) => {
                    print_rule(&parsed);
                }
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::File { path, json } => {
            println!("{}", format!("Parsing rules from: {}", path.display()).cyan().bold());
            println!("{}", "=".repeat(60));

            match parser.parse_file(&path) {
                Ok(rules) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&rules)?);
                    } else {
                        for (i, rule) in rules.iter().enumerate() {
                            println!("\n{} {}", "Rule".green().bold(), i + 1);
                            print_rule(rule);
                        }
                        println!("\n{}: {} rules parsed", "Summary".cyan().bold(), rules.len());
                    }
                }
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Validate { path } => {
            println!("{}", format!("Validating rules from: {}", path.display()).cyan().bold());
            println!("{}", "=".repeat(60));

            match parser.parse_file(&path) {
                Ok(rules) => {
                    let mut total_issues = 0;

                    for rule in &rules {
                        let issues = RuleValidator::validate(rule);
                        if !issues.is_empty() {
                            let sid = rule.options.sid
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "unknown".to_string());

                            println!("\n{} SID {}", "Issues for".yellow().bold(), sid);
                            for issue in &issues {
                                println!("  {} {}", "-".yellow(), issue);
                                total_issues += 1;
                            }
                        }
                    }

                    println!("\n{}", "Summary".cyan().bold());
                    println!("  Rules: {}", rules.len());
                    println!("  Issues: {}", total_issues);
                }
                Err(e) => {
                    eprintln!("{}: {}", "Error".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Examples => {
            print_examples();
        }
    }

    Ok(())
}

fn print_rule(rule: &Rule) {
    println!("  {}: {:?}", "Action".yellow(), rule.action);
    println!("  {}: {:?}", "Protocol".yellow(), rule.protocol);
    println!("  {}: {:?} : {:?}", "Source".yellow(), rule.src_ip, rule.src_port);
    println!("  {}: {:?}", "Direction".yellow(), rule.direction);
    println!("  {}: {:?} : {:?}", "Destination".yellow(), rule.dst_ip, rule.dst_port);

    if let Some(msg) = &rule.options.msg {
        println!("  {}: {}", "Message".green(), msg);
    }
    if let Some(sid) = rule.options.sid {
        println!("  {}: {}", "SID".green(), sid);
    }
    if !rule.options.content.is_empty() {
        println!("  {}:", "Content Patterns".green());
        for content in &rule.options.content {
            println!("    - {} (negated: {}, nocase: {})",
                content.original, content.negated, content.modifiers.nocase);
        }
    }
    if !rule.options.pcre.is_empty() {
        println!("  {}:", "PCRE Patterns".green());
        for pcre in &rule.options.pcre {
            println!("    - /{}/{}", pcre.pattern, pcre.modifiers);
        }
    }
}

fn print_examples() {
    println!("{}", "Example IDS Rules".cyan().bold());
    println!("{}", "=".repeat(60));

    let examples = vec![
        (
            "Basic HTTP GET Detection",
            r#"alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; http_method; sid:1000001; rev:1;)"#
        ),
        (
            "SQL Injection Attempt",
            r#"alert http any any -> any any (msg:"SQL Injection Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:20; flow:to_server,established; classtype:web-application-attack; sid:1000002; rev:1;)"#
        ),
        (
            "SSH Brute Force",
            r#"alert tcp any any -> any 22 (msg:"Possible SSH Brute Force"; flow:to_server,established; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000003; rev:1;)"#
        ),
        (
            "Malware Beacon Detection",
            r#"alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Malware Beacon"; content:"|89 50 4e 47|"; depth:4; content:"data"; distance:0; pcre:"/beacon\d+/i"; sid:1000004; rev:1;)"#
        ),
        (
            "DNS Tunnel Detection",
            r#"alert udp any any -> any 53 (msg:"Possible DNS Tunnel"; content:"|00 00 01 00 01|"; offset:2; depth:5; dsize:>100; sid:1000005; rev:1;)"#
        ),
    ];

    let mut parser = RuleParser::new();
    parser.load_default_variables();

    for (name, rule) in examples {
        println!("\n{}", name.green().bold());
        println!("{}", rule.dimmed());

        match parser.parse_rule(rule) {
            Ok(parsed) => {
                print_rule(&parsed);
            }
            Err(e) => {
                println!("  {}: {}", "Parse Error".red(), e);
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_parse() {
        assert!(matches!(Action::parse("alert"), Ok(Action::Alert)));
        assert!(matches!(Action::parse("DROP"), Ok(Action::Drop)));
        assert!(matches!(Action::parse("pass"), Ok(Action::Pass)));
        assert!(Action::parse("invalid").is_err());
    }

    #[test]
    fn test_protocol_parse() {
        assert!(matches!(Protocol::parse("tcp"), Ok(Protocol::Tcp)));
        assert!(matches!(Protocol::parse("UDP"), Ok(Protocol::Udp)));
        assert!(matches!(Protocol::parse("http"), Ok(Protocol::Http)));
        assert!(Protocol::parse("invalid").is_err());
    }

    #[test]
    fn test_ip_spec_parse() {
        assert!(matches!(IpSpec::parse("any"), Ok(IpSpec::Any)));
        assert!(matches!(IpSpec::parse("$HOME_NET"), Ok(IpSpec::Variable(_))));
        assert!(matches!(IpSpec::parse("192.168.1.1"), Ok(IpSpec::Single(_))));
        assert!(matches!(IpSpec::parse("192.168.1.0/24"), Ok(IpSpec::Cidr(_, 24))));
        assert!(matches!(IpSpec::parse("!192.168.1.1"), Ok(IpSpec::Negated(_))));
    }

    #[test]
    fn test_port_spec_parse() {
        assert!(matches!(PortSpec::parse("any"), Ok(PortSpec::Any)));
        assert!(matches!(PortSpec::parse("80"), Ok(PortSpec::Single(80))));
        assert!(matches!(PortSpec::parse("1:1024"), Ok(PortSpec::Range(1, 1024))));
        assert!(matches!(PortSpec::parse("!22"), Ok(PortSpec::Negated(_))));
    }

    #[test]
    fn test_basic_rule_parse() {
        let mut parser = RuleParser::new();
        let rule = r#"alert tcp any any -> any 80 (msg:"Test"; sid:1;)"#;

        let parsed = parser.parse_rule(rule).unwrap();
        assert!(matches!(parsed.action, Action::Alert));
        assert!(matches!(parsed.protocol, Protocol::Tcp));
        assert_eq!(parsed.options.msg, Some("Test".to_string()));
        assert_eq!(parsed.options.sid, Some(1));
    }

    #[test]
    fn test_content_hex_parse() {
        let parser = RuleParser::new();
        let pattern = "GET |20| HTTP";
        let bytes = parser.parse_content_pattern(pattern).unwrap();

        assert_eq!(bytes, b"GET \x20 HTTP");
    }

    #[test]
    fn test_complex_rule_parse() {
        let mut parser = RuleParser::new();
        parser.load_default_variables();

        let rule = r#"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SQL Injection"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:20; flow:to_server,established; classtype:web-application-attack; sid:1000002; rev:1;)"#;

        let parsed = parser.parse_rule(rule).unwrap();
        assert!(matches!(parsed.protocol, Protocol::Http));
        assert_eq!(parsed.options.content.len(), 2);
        assert!(parsed.options.content[0].modifiers.nocase);
        assert!(parsed.options.flow.to_server);
        assert!(parsed.options.flow.established);
    }

    #[test]
    fn test_rule_validator() {
        let mut parser = RuleParser::new();
        let rule = r#"alert tcp any any -> any any ()"#;

        // This should fail or produce warnings
        let result = parser.parse_rule(rule);
        if let Ok(parsed) = result {
            let issues = RuleValidator::validate(&parsed);
            assert!(!issues.is_empty());
        }
    }

    #[test]
    fn test_ip_cidr_matching() {
        let spec = IpSpec::Cidr("192.168.1.0".parse().unwrap(), 24);
        let variables = HashMap::new();

        assert!(spec.matches("192.168.1.100".parse().unwrap(), &variables));
        assert!(!spec.matches("192.168.2.100".parse().unwrap(), &variables));
    }

    #[test]
    fn test_port_range_matching() {
        let spec = PortSpec::Range(80, 443);

        assert!(spec.matches(80));
        assert!(spec.matches(100));
        assert!(spec.matches(443));
        assert!(!spec.matches(22));
        assert!(!spec.matches(8080));
    }
}
