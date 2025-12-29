//! # Shellcode Analyzer - Advanced Security Tool
//!
//! This tool analyzes shellcode patterns to identify potentially malicious behavior.
//! It examines binary code sequences for known patterns like:
//! - System call invocations (syscalls)
//! - Common shellcode techniques (egg hunters, decoders)
//! - Suspicious instruction sequences
//! - Anti-debugging techniques
//!
//! ## What is Shellcode?
//!
//! Shellcode is machine code designed to be injected into a running process.
//! It typically:
//! 1. Is position-independent (can run from any memory address)
//! 2. Avoids null bytes (0x00) which terminate strings
//! 3. Uses relative addressing and self-modifying techniques
//! 4. Often spawns a shell (hence the name) or performs other actions
//!
//! ## Educational Purpose
//!
//! This tool is for security research and education only.
//! Understanding shellcode patterns helps:
//! - Malware analysts identify threats
//! - Security researchers develop better defenses
//! - Penetration testers understand exploitation techniques

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

// ============================================================================
// ERROR HANDLING
// ============================================================================

/// Custom error types for shellcode analysis
#[derive(Error, Debug)]
pub enum ShellcodeError {
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    #[error("File read error: {0}")]
    FileError(String),

    #[error("Empty shellcode provided")]
    EmptyShellcode,

    #[error("Disassembly error: {0}")]
    DisassemblyError(String),
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

/// Shellcode Analyzer - Detect patterns in shellcode samples
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input shellcode (hex string or file path)
    #[arg(short, long)]
    input: String,

    /// Input format
    #[arg(short, long, value_enum, default_value = "hex")]
    format: InputFormat,

    /// Target architecture
    #[arg(short, long, value_enum, default_value = "x86-64")]
    arch: Architecture,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    output: OutputFormat,

    /// Verbose output with detailed explanations
    #[arg(short, long)]
    verbose: bool,

    /// Show disassembly
    #[arg(short, long)]
    disasm: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum InputFormat {
    /// Hexadecimal string (e.g., "90909090")
    Hex,
    /// Raw binary file
    Raw,
    /// C-style array (e.g., "\x90\x90")
    CStyle,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Architecture {
    /// 32-bit x86
    X86,
    /// 64-bit x86
    X86_64,
    /// 32-bit ARM
    Arm,
    /// 64-bit ARM
    Arm64,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    /// Human-readable text
    Text,
    /// JSON output
    Json,
}

// ============================================================================
// PATTERN DEFINITIONS
// ============================================================================

/// Represents a detected pattern in the shellcode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Name of the pattern
    pub name: String,
    /// Category of the pattern
    pub category: PatternCategory,
    /// Offset where pattern was found
    pub offset: usize,
    /// Length of the matched pattern
    pub length: usize,
    /// Risk level (1-10)
    pub risk_level: u8,
    /// Detailed description
    pub description: String,
    /// The matched bytes as hex
    pub matched_bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternCategory {
    /// System call invocations
    Syscall,
    /// Anti-debugging techniques
    AntiDebug,
    /// Decoder/encoder stubs
    Decoder,
    /// Network operations
    Network,
    /// File system operations
    FileSystem,
    /// Process manipulation
    Process,
    /// Memory operations
    Memory,
    /// Egg hunter patterns
    EggHunter,
    /// NOP sleds and padding
    NopSled,
    /// Suspicious instructions
    Suspicious,
}

/// Defines a pattern to search for
#[derive(Debug, Clone)]
pub struct PatternDefinition {
    pub name: &'static str,
    pub category: PatternCategory,
    pub pattern: &'static str,
    pub risk_level: u8,
    pub description: &'static str,
}

// ============================================================================
// PATTERN DATABASE
// ============================================================================

/// Get all known shellcode patterns
///
/// ## Pattern Types Explained:
///
/// ### Syscall Patterns
/// System calls are how shellcode interacts with the operating system.
/// - Linux x86: `int 0x80` (CD 80)
/// - Linux x64: `syscall` (0F 05)
/// - Windows: Various interrupt and API call patterns
///
/// ### NOP Sleds
/// NOP (No Operation) sleds are padding used to increase the chance
/// of hitting shellcode when the exact jump address is unknown.
/// - Classic: 0x90 (xchg eax, eax on x86)
/// - Alternatives: Any instruction that doesn't change state
///
/// ### Egg Hunters
/// Small code sequences that search memory for a larger payload
/// marked with a unique "egg" signature (usually 4-8 bytes).
fn get_pattern_database() -> Vec<PatternDefinition> {
    vec![
        // ====================================================================
        // SYSCALL PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "Linux x86 syscall (int 0x80)",
            category: PatternCategory::Syscall,
            // CD 80 = int 0x80 instruction
            pattern: r"\xcd\x80",
            risk_level: 8,
            description: "Linux 32-bit system call interrupt. Used to invoke kernel functions \
                         like execve(), read(), write(), etc. Common in Linux shellcode.",
        },
        PatternDefinition {
            name: "Linux x64 syscall",
            category: PatternCategory::Syscall,
            // 0F 05 = syscall instruction
            pattern: r"\x0f\x05",
            risk_level: 8,
            description: "Linux 64-bit system call instruction. More efficient than int 0x80 \
                         and used in modern Linux shellcode.",
        },
        PatternDefinition {
            name: "Windows syscall (sysenter)",
            category: PatternCategory::Syscall,
            // 0F 34 = sysenter instruction
            pattern: r"\x0f\x34",
            risk_level: 7,
            description: "Fast system call entry on Windows. May indicate direct syscall \
                         invocation bypassing user-mode hooks.",
        },

        // ====================================================================
        // NOP SLED PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "Classic NOP sled",
            category: PatternCategory::NopSled,
            // 4+ consecutive NOPs
            pattern: r"(\x90){4,}",
            risk_level: 3,
            description: "Sequence of NOP (0x90) instructions. NOP sleds increase the \
                         landing zone for jump instructions in buffer overflow exploits.",
        },
        PatternDefinition {
            name: "Alternative NOP sled (xchg)",
            category: PatternCategory::NopSled,
            // Multiple xchg eax, eax or similar
            pattern: r"(\x87[\xc0\xc9\xd2\xdb]){3,}",
            risk_level: 4,
            description: "Alternative NOP sled using xchg instructions. Used to evade \
                         simple NOP sled detection that only looks for 0x90.",
        },

        // ====================================================================
        // DECODER PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "XOR decoder loop",
            category: PatternCategory::Decoder,
            // Common XOR decoder pattern: xor [reg+offset], key
            pattern: r"\x80[\x30-\x37].{0,4}\x(e2|75)",
            risk_level: 7,
            description: "XOR-based decoder stub. Shellcode often encodes itself to avoid \
                         bad characters and uses a decoder stub to restore the original code.",
        },
        PatternDefinition {
            name: "GetPC technique (call $+5)",
            category: PatternCategory::Decoder,
            // E8 00 00 00 00 = call $+5 (call next instruction)
            pattern: r"\xe8\x00\x00\x00\x00",
            risk_level: 6,
            description: "Get Program Counter technique. Pushes the current address onto \
                         the stack, used for position-independent code to find its location.",
        },
        PatternDefinition {
            name: "FPU GetPC technique",
            category: PatternCategory::Decoder,
            // D9 EE D9 74 24 F4 = fldz; fnstenv [esp-0xc]
            pattern: r"\xd9\xee\xd9\x74\x24\xf4",
            risk_level: 6,
            description: "FPU-based GetPC technique. Uses floating-point instructions to \
                         get the current instruction pointer. Often used in egg hunters.",
        },

        // ====================================================================
        // ANTI-DEBUGGING PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "IsDebuggerPresent check",
            category: PatternCategory::AntiDebug,
            // 64 A1 30 00 00 00 = mov eax, fs:[0x30] (PEB access)
            pattern: r"\x64\xa1\x30\x00\x00\x00",
            risk_level: 5,
            description: "Access to Process Environment Block (PEB) via FS segment. \
                         Often used to check IsDebuggerPresent flag at PEB+0x02.",
        },
        PatternDefinition {
            name: "INT 3 breakpoint",
            category: PatternCategory::AntiDebug,
            // CC = int 3 (software breakpoint)
            pattern: r"\xcc",
            risk_level: 3,
            description: "Software breakpoint instruction. Can be used for anti-debugging \
                         or to trigger exceptions as part of shellcode flow control.",
        },
        PatternDefinition {
            name: "RDTSC timing check",
            category: PatternCategory::AntiDebug,
            // 0F 31 = rdtsc (read timestamp counter)
            pattern: r"\x0f\x31",
            risk_level: 5,
            description: "Read Time Stamp Counter instruction. Used for timing-based \
                         anti-debugging to detect single-stepping or breakpoints.",
        },

        // ====================================================================
        // NETWORK PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "Socket creation pattern",
            category: PatternCategory::Network,
            // push 6, push 1, push 2 (common socket() args)
            pattern: r"\x6a\x06\x6a\x01\x6a\x02",
            risk_level: 7,
            description: "Socket creation arguments (AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6). \
                         Indicates network-capable shellcode, likely a reverse or bind shell.",
        },
        PatternDefinition {
            name: "Bind shell port setup",
            category: PatternCategory::Network,
            // Common port in network byte order with sin_family
            pattern: r"\x02\x00[\x00-\xff]{2}",
            risk_level: 6,
            description: "sockaddr_in structure setup with AF_INET (0x0002). The following \
                         two bytes typically contain the port number in network byte order.",
        },

        // ====================================================================
        // PROCESS PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "Fork/execve pattern",
            category: PatternCategory::Process,
            // Common setup for execve: push 0, push string, mov ebx, esp
            pattern: r"\x6a\x00.{0,20}\x89\xe3",
            risk_level: 7,
            description: "Setup for execve() system call. Pushes NULL terminator and \
                         sets up argument pointers for program execution.",
        },
        PatternDefinition {
            name: "/bin/sh string push",
            category: PatternCategory::Process,
            // "//bin/sh" or "/bin//sh" pushed as integers
            pattern: r"\x68.{4}\x68.{4}.{0,10}(\xcd\x80|\x0f\x05)",
            risk_level: 9,
            description: "Shell string construction followed by syscall. Classic pattern \
                         for spawning a shell in Linux shellcode.",
        },

        // ====================================================================
        // EGG HUNTER PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "Egg hunter (access syscall)",
            category: PatternCategory::EggHunter,
            // mov eax, 0x21 (access syscall) pattern
            pattern: r"\xb8\x21\x00\x00\x00",
            risk_level: 6,
            description: "Access syscall setup in egg hunter. Uses access() to safely \
                         probe memory pages for the egg signature.",
        },
        PatternDefinition {
            name: "Egg signature check (scasd)",
            category: PatternCategory::EggHunter,
            // AF AF = scasd scasd (scan for 4-byte egg twice)
            pattern: r"\xaf\xaf",
            risk_level: 5,
            description: "Double scasd instruction for egg hunting. Searches for an 8-byte \
                         egg (4-byte signature repeated) to find the main payload.",
        },

        // ====================================================================
        // SUSPICIOUS PATTERNS
        // ====================================================================
        PatternDefinition {
            name: "Stack pivot",
            category: PatternCategory::Suspicious,
            // xchg eax, esp or similar stack manipulation
            pattern: r"\x94|\x87\xe4",
            risk_level: 8,
            description: "Stack pivot instruction. Changes the stack pointer to a \
                         controlled location, often used in ROP chains.",
        },
        PatternDefinition {
            name: "Return-oriented gadget chain",
            category: PatternCategory::Suspicious,
            // Multiple returns close together
            pattern: r"(\xc3.{0,8}){3,}",
            risk_level: 7,
            description: "Multiple RET instructions in close proximity. May indicate \
                         Return-Oriented Programming (ROP) gadget chain.",
        },
    ]
}

// ============================================================================
// ANALYSIS ENGINE
// ============================================================================

/// Shellcode analyzer engine
pub struct ShellcodeAnalyzer {
    /// Raw shellcode bytes
    shellcode: Vec<u8>,
    /// Target architecture
    architecture: Architecture,
    /// Pattern database
    patterns: Vec<PatternDefinition>,
    /// Analysis results
    matches: Vec<PatternMatch>,
    /// Statistics
    stats: AnalysisStats,
}

/// Statistics from analysis
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AnalysisStats {
    /// Total shellcode length
    pub total_length: usize,
    /// Number of patterns checked
    pub patterns_checked: usize,
    /// Number of matches found
    pub matches_found: usize,
    /// Highest risk level found
    pub max_risk_level: u8,
    /// Category breakdown
    pub category_counts: HashMap<String, usize>,
    /// Entropy of shellcode (0.0 - 8.0)
    pub entropy: f64,
    /// Percentage of printable characters
    pub printable_ratio: f64,
    /// Null byte count
    pub null_bytes: usize,
}

impl ShellcodeAnalyzer {
    /// Create a new analyzer instance
    pub fn new(shellcode: Vec<u8>, architecture: Architecture) -> Result<Self, ShellcodeError> {
        if shellcode.is_empty() {
            return Err(ShellcodeError::EmptyShellcode);
        }

        Ok(Self {
            shellcode,
            architecture,
            patterns: get_pattern_database(),
            matches: Vec::new(),
            stats: AnalysisStats::default(),
        })
    }

    /// Run full analysis on the shellcode
    pub fn analyze(&mut self) -> Result<()> {
        // Calculate statistics first
        self.calculate_stats();

        // Search for all patterns
        self.search_patterns()?;

        // Sort matches by offset
        self.matches.sort_by_key(|m| m.offset);

        Ok(())
    }

    /// Calculate statistical properties of the shellcode
    ///
    /// ## Entropy Analysis
    ///
    /// Shannon entropy measures the randomness of data:
    /// - Low entropy (< 4.0): Repetitive data, possibly NOP sleds or padding
    /// - Medium entropy (4.0-6.0): Normal code
    /// - High entropy (> 6.0): Encrypted or compressed data
    ///
    /// Encoded shellcode typically has higher entropy than plaintext shellcode.
    fn calculate_stats(&mut self) {
        let len = self.shellcode.len();
        self.stats.total_length = len;

        // Count byte frequencies for entropy calculation
        let mut byte_counts = [0u64; 256];
        let mut null_count = 0usize;
        let mut printable_count = 0usize;

        for &byte in &self.shellcode {
            byte_counts[byte as usize] += 1;
            if byte == 0 {
                null_count += 1;
            }
            if byte >= 0x20 && byte <= 0x7e {
                printable_count += 1;
            }
        }

        self.stats.null_bytes = null_count;
        self.stats.printable_ratio = printable_count as f64 / len as f64;

        // Calculate Shannon entropy
        // Formula: H = -Σ(p * log2(p)) where p is probability of each byte
        let mut entropy = 0.0f64;
        for &count in &byte_counts {
            if count > 0 {
                let probability = count as f64 / len as f64;
                entropy -= probability * probability.log2();
            }
        }
        self.stats.entropy = entropy;
    }

    /// Search for all known patterns in the shellcode
    fn search_patterns(&mut self) -> Result<()> {
        self.stats.patterns_checked = self.patterns.len();

        for pattern_def in &self.patterns.clone() {
            // Convert pattern string to regex
            let regex_pattern = pattern_def.pattern
                .replace(r"\x", r"\\x")
                .replace(".", r"[\x00-\xff]");

            // Build regex with proper escaping for hex bytes
            let pattern_bytes: Vec<u8> = parse_pattern_to_bytes(pattern_def.pattern);

            // Search for pattern in shellcode
            self.search_byte_pattern(pattern_def, &pattern_bytes);
        }

        self.stats.matches_found = self.matches.len();
        if let Some(max) = self.matches.iter().map(|m| m.risk_level).max() {
            self.stats.max_risk_level = max;
        }

        // Count categories
        for m in &self.matches {
            let category_name = format!("{:?}", m.category);
            *self.stats.category_counts.entry(category_name).or_insert(0) += 1;
        }

        Ok(())
    }

    /// Search for a specific byte pattern
    fn search_byte_pattern(&mut self, pattern_def: &PatternDefinition, pattern_bytes: &[u8]) {
        if pattern_bytes.is_empty() {
            return;
        }

        // Handle regex patterns differently
        if pattern_def.pattern.contains('{') || pattern_def.pattern.contains('|')
           || pattern_def.pattern.contains('(') {
            self.search_regex_pattern(pattern_def);
            return;
        }

        // Simple byte sequence search
        for (offset, window) in self.shellcode.windows(pattern_bytes.len()).enumerate() {
            if window == pattern_bytes {
                self.matches.push(PatternMatch {
                    name: pattern_def.name.to_string(),
                    category: pattern_def.category.clone(),
                    offset,
                    length: pattern_bytes.len(),
                    risk_level: pattern_def.risk_level,
                    description: pattern_def.description.to_string(),
                    matched_bytes: hex::encode(window),
                });
            }
        }
    }

    /// Search using regex for complex patterns
    fn search_regex_pattern(&mut self, pattern_def: &PatternDefinition) {
        // Convert pattern to proper regex syntax
        let regex_str = convert_to_regex(pattern_def.pattern);

        if let Ok(regex) = Regex::new(&regex_str) {
            for mat in regex.find_iter(&self.shellcode) {
                self.matches.push(PatternMatch {
                    name: pattern_def.name.to_string(),
                    category: pattern_def.category.clone(),
                    offset: mat.start(),
                    length: mat.len(),
                    risk_level: pattern_def.risk_level,
                    description: pattern_def.description.to_string(),
                    matched_bytes: hex::encode(mat.as_bytes()),
                });
            }
        }
    }

    /// Get analysis results
    pub fn get_matches(&self) -> &[PatternMatch] {
        &self.matches
    }

    /// Get statistics
    pub fn get_stats(&self) -> &AnalysisStats {
        &self.stats
    }

    /// Get shellcode bytes
    pub fn get_shellcode(&self) -> &[u8] {
        &self.shellcode
    }

    /// Calculate overall threat score
    pub fn calculate_threat_score(&self) -> u32 {
        let mut score: u32 = 0;

        // Base score from matches
        for m in &self.matches {
            score += m.risk_level as u32 * 10;
        }

        // Bonus for high entropy (possible encoding)
        if self.stats.entropy > 6.5 {
            score += 20;
        }

        // Bonus for no null bytes (shellcode characteristic)
        if self.stats.null_bytes == 0 {
            score += 15;
        }

        // Cap at 100
        score.min(100)
    }

    /// Attempt basic disassembly
    #[cfg(feature = "disasm")]
    pub fn disassemble(&self) -> Result<Vec<String>, ShellcodeError> {
        use capstone::prelude::*;

        let cs = match self.architecture {
            Architecture::X86 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build(),
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build(),
            _ => return Err(ShellcodeError::DisassemblyError(
                "Unsupported architecture for disassembly".to_string()
            )),
        }.map_err(|e| ShellcodeError::DisassemblyError(e.to_string()))?;

        let instructions = cs.disasm_all(&self.shellcode, 0x0)
            .map_err(|e| ShellcodeError::DisassemblyError(e.to_string()))?;

        let mut result = Vec::new();
        for insn in instructions.iter() {
            result.push(format!(
                "0x{:04x}:  {:16}  {} {}",
                insn.address(),
                insn.bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or("")
            ));
        }

        Ok(result)
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Parse a pattern string containing \x escapes to bytes
fn parse_pattern_to_bytes(pattern: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&'x') = chars.peek() {
                chars.next(); // consume 'x'
                let mut hex_str = String::new();
                if let Some(&h1) = chars.peek() {
                    if h1.is_ascii_hexdigit() {
                        hex_str.push(chars.next().unwrap());
                    }
                }
                if let Some(&h2) = chars.peek() {
                    if h2.is_ascii_hexdigit() {
                        hex_str.push(chars.next().unwrap());
                    }
                }
                if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                    bytes.push(byte);
                }
            }
        }
    }

    bytes
}

/// Convert pattern to proper regex syntax for bytes crate
fn convert_to_regex(pattern: &str) -> String {
    let mut result = String::new();
    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == 'x' {
                    chars.next();
                    let mut hex_str = String::new();
                    for _ in 0..2 {
                        if let Some(&h) = chars.peek() {
                            if h.is_ascii_hexdigit() {
                                hex_str.push(chars.next().unwrap());
                            }
                        }
                    }
                    result.push_str(&format!("\\x{}", hex_str));
                } else {
                    result.push(c);
                    result.push(chars.next().unwrap());
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Parse input based on format
fn parse_input(input: &str, format: InputFormat) -> Result<Vec<u8>, ShellcodeError> {
    match format {
        InputFormat::Hex => {
            // Try as file first
            if let Ok(content) = fs::read_to_string(input) {
                let clean: String = content
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect();
                hex::decode(&clean)
                    .map_err(|e| ShellcodeError::InvalidHex(e.to_string()))
            } else {
                // Parse as hex string
                let clean: String = input
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect();
                hex::decode(&clean)
                    .map_err(|e| ShellcodeError::InvalidHex(e.to_string()))
            }
        }
        InputFormat::Raw => {
            fs::read(input)
                .map_err(|e| ShellcodeError::FileError(e.to_string()))
        }
        InputFormat::CStyle => {
            // Parse C-style \xNN format
            let content = if PathBuf::from(input).exists() {
                fs::read_to_string(input)
                    .map_err(|e| ShellcodeError::FileError(e.to_string()))?
            } else {
                input.to_string()
            };

            Ok(parse_pattern_to_bytes(&content))
        }
    }
}

/// Print colored risk level
fn format_risk_level(level: u8) -> ColoredString {
    match level {
        1..=3 => format!("{}/10", level).green(),
        4..=6 => format!("{}/10", level).yellow(),
        7..=8 => format!("{}/10", level).truecolor(255, 165, 0), // Orange
        9..=10 => format!("{}/10", level).red().bold(),
        _ => format!("{}/10", level).white(),
    }
}

/// Print analysis results in text format
fn print_text_output(analyzer: &ShellcodeAnalyzer, verbose: bool) {
    let stats = analyzer.get_stats();
    let matches = analyzer.get_matches();
    let threat_score = analyzer.calculate_threat_score();

    println!("\n{}", "=".repeat(70).blue());
    println!("{}", "           SHELLCODE ANALYSIS REPORT".blue().bold());
    println!("{}", "=".repeat(70).blue());

    // Statistics section
    println!("\n{}", "[ STATISTICS ]".cyan().bold());
    println!("  Shellcode Length:    {} bytes", stats.total_length);
    println!("  Shannon Entropy:     {:.2} / 8.00", stats.entropy);
    println!("  Null Bytes:          {} ({:.1}%)",
             stats.null_bytes,
             (stats.null_bytes as f64 / stats.total_length as f64) * 100.0);
    println!("  Printable Chars:     {:.1}%", stats.printable_ratio * 100.0);
    println!("  Patterns Checked:    {}", stats.patterns_checked);
    println!("  Matches Found:       {}", stats.matches_found);

    // Entropy interpretation
    let entropy_note = if stats.entropy < 4.0 {
        "Low - possibly contains NOP sled or padding".yellow()
    } else if stats.entropy < 6.0 {
        "Normal - typical code entropy".green()
    } else if stats.entropy < 7.0 {
        "Elevated - may be partially encoded".truecolor(255, 165, 0)
    } else {
        "High - likely encrypted or compressed".red()
    };
    println!("  Entropy Assessment:  {}", entropy_note);

    // Null byte analysis
    if stats.null_bytes == 0 {
        println!("  {}", "* No null bytes - characteristic of functional shellcode".yellow());
    }

    // Threat score
    println!("\n{}", "[ THREAT ASSESSMENT ]".cyan().bold());
    let score_color = if threat_score < 30 {
        format!("{}/100", threat_score).green()
    } else if threat_score < 60 {
        format!("{}/100", threat_score).yellow()
    } else if threat_score < 80 {
        format!("{}/100", threat_score).truecolor(255, 165, 0)
    } else {
        format!("{}/100", threat_score).red().bold()
    };
    println!("  Overall Threat Score: {}", score_color);

    // Category breakdown
    if !stats.category_counts.is_empty() {
        println!("\n{}", "[ CATEGORY BREAKDOWN ]".cyan().bold());
        for (category, count) in &stats.category_counts {
            println!("  {:20} {}", category, count);
        }
    }

    // Pattern matches
    if !matches.is_empty() {
        println!("\n{}", "[ DETECTED PATTERNS ]".cyan().bold());
        println!("{}", "-".repeat(70));

        for (i, m) in matches.iter().enumerate() {
            println!("\n  {}. {} {}",
                     i + 1,
                     m.name.white().bold(),
                     format!("[{:?}]", m.category).cyan());
            println!("     Offset:     0x{:04x} ({} bytes)", m.offset, m.offset);
            println!("     Length:     {} bytes", m.length);
            println!("     Risk Level: {}", format_risk_level(m.risk_level));
            println!("     Bytes:      {}", m.matched_bytes.yellow());

            if verbose {
                println!("     {}", "-".repeat(50));
                // Word wrap description
                for line in textwrap(&m.description, 55) {
                    println!("     {}", line.dimmed());
                }
            }
        }
    } else {
        println!("\n{}", "[ NO PATTERNS DETECTED ]".green());
        println!("  The shellcode did not match any known patterns.");
        println!("  This could mean:");
        println!("    - Novel or custom shellcode");
        println!("    - Heavily obfuscated code");
        println!("    - Not actually shellcode");
    }

    // Hex dump preview
    println!("\n{}", "[ HEX DUMP (first 128 bytes) ]".cyan().bold());
    let shellcode = analyzer.get_shellcode();
    let preview_len = shellcode.len().min(128);
    for (i, chunk) in shellcode[..preview_len].chunks(16).enumerate() {
        let hex_part: String = chunk.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii_part: String = chunk.iter()
            .map(|&b| if b >= 0x20 && b <= 0x7e { b as char } else { '.' })
            .collect();
        println!("  {:04x}:  {:48}  {}", i * 16, hex_part, ascii_part.dimmed());
    }
    if shellcode.len() > 128 {
        println!("  ... ({} more bytes)", shellcode.len() - 128);
    }

    println!("\n{}", "=".repeat(70).blue());
}

/// Simple text wrapping
fn textwrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > width {
            if !current_line.is_empty() {
                lines.push(current_line);
                current_line = String::new();
            }
        }
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

/// Print analysis results in JSON format
fn print_json_output(analyzer: &ShellcodeAnalyzer) -> Result<()> {
    #[derive(Serialize)]
    struct FullReport<'a> {
        stats: &'a AnalysisStats,
        threat_score: u32,
        matches: &'a [PatternMatch],
        shellcode_hex: String,
    }

    let report = FullReport {
        stats: analyzer.get_stats(),
        threat_score: analyzer.calculate_threat_score(),
        matches: analyzer.get_matches(),
        shellcode_hex: hex::encode(analyzer.get_shellcode()),
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse input shellcode
    let shellcode = parse_input(&args.input, args.format)
        .context("Failed to parse shellcode input")?;

    // Create and run analyzer
    let mut analyzer = ShellcodeAnalyzer::new(shellcode, args.arch)
        .context("Failed to create analyzer")?;

    analyzer.analyze()
        .context("Analysis failed")?;

    // Output results
    match args.output {
        OutputFormat::Text => print_text_output(&analyzer, args.verbose),
        OutputFormat::Json => print_json_output(&analyzer)?,
    }

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test NOP sled detection
    #[test]
    fn test_nop_sled_detection() {
        // Classic NOP sled followed by shellcode-like bytes
        let shellcode = vec![
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // NOP sled
            0x31, 0xc0,                         // xor eax, eax
            0xcd, 0x80,                         // int 0x80
        ];

        let mut analyzer = ShellcodeAnalyzer::new(shellcode, Architecture::X86).unwrap();
        analyzer.analyze().unwrap();

        let matches = analyzer.get_matches();
        assert!(matches.iter().any(|m| m.category == PatternCategory::NopSled));
        assert!(matches.iter().any(|m| m.category == PatternCategory::Syscall));
    }

    /// Test syscall detection
    #[test]
    fn test_syscall_detection() {
        // Linux x64 shellcode with syscall
        let shellcode = vec![
            0x48, 0x31, 0xc0, // xor rax, rax
            0x0f, 0x05,       // syscall
        ];

        let mut analyzer = ShellcodeAnalyzer::new(shellcode, Architecture::X86_64).unwrap();
        analyzer.analyze().unwrap();

        assert!(analyzer.get_matches().iter().any(|m| m.name.contains("x64 syscall")));
    }

    /// Test entropy calculation
    #[test]
    fn test_entropy_calculation() {
        // All zeros - minimum entropy
        let low_entropy = vec![0u8; 100];
        let mut analyzer = ShellcodeAnalyzer::new(low_entropy, Architecture::X86).unwrap();
        analyzer.analyze().unwrap();
        assert!(analyzer.get_stats().entropy < 1.0);

        // Random-ish bytes - higher entropy
        let high_entropy: Vec<u8> = (0..=255).collect();
        let mut analyzer = ShellcodeAnalyzer::new(high_entropy, Architecture::X86).unwrap();
        analyzer.analyze().unwrap();
        assert!(analyzer.get_stats().entropy > 7.0);
    }

    /// Test GetPC detection
    #[test]
    fn test_getpc_detection() {
        let shellcode = vec![
            0xe8, 0x00, 0x00, 0x00, 0x00, // call $+5
            0x5b,                         // pop ebx (get EIP)
        ];

        let mut analyzer = ShellcodeAnalyzer::new(shellcode, Architecture::X86).unwrap();
        analyzer.analyze().unwrap();

        assert!(analyzer.get_matches().iter().any(|m| m.name.contains("GetPC")));
    }

    /// Test empty shellcode error
    #[test]
    fn test_empty_shellcode_error() {
        let result = ShellcodeAnalyzer::new(vec![], Architecture::X86);
        assert!(result.is_err());
    }

    /// Test hex parsing
    #[test]
    fn test_hex_parsing() {
        let result = parse_input("90909090cd80", InputFormat::Hex).unwrap();
        assert_eq!(result, vec![0x90, 0x90, 0x90, 0x90, 0xcd, 0x80]);
    }

    /// Test C-style parsing
    #[test]
    fn test_cstyle_parsing() {
        let result = parse_input(r"\x90\x90\xcd\x80", InputFormat::CStyle).unwrap();
        assert_eq!(result, vec![0x90, 0x90, 0xcd, 0x80]);
    }

    /// Test threat score calculation
    #[test]
    fn test_threat_score() {
        // High-risk shellcode with multiple dangerous patterns
        let shellcode = vec![
            0x90, 0x90, 0x90, 0x90, // NOP sled
            0xcd, 0x80,             // int 0x80
            0x0f, 0x05,             // syscall
        ];

        let mut analyzer = ShellcodeAnalyzer::new(shellcode, Architecture::X86).unwrap();
        analyzer.analyze().unwrap();

        let score = analyzer.calculate_threat_score();
        assert!(score > 0);
    }

    /// Test pattern bytes parsing
    #[test]
    fn test_pattern_parsing() {
        let bytes = parse_pattern_to_bytes(r"\xcd\x80");
        assert_eq!(bytes, vec![0xcd, 0x80]);
    }
}
