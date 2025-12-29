//! # Base64 Encoding/Decoding Security Tool
//!
//! This module demonstrates Base64 encoding and decoding in Rust with
//! security considerations, including:
//! - Standard Base64 encoding/decoding
//! - URL-safe Base64 variants
//! - Detecting encoded content in strings
//! - Analyzing encoded data for sensitive information
//! - Multi-layer decoding (for obfuscated payloads)
//!
//! ## Security Use Cases
//! - Decoding obfuscated malware payloads
//! - Analyzing encoded credentials
//! - Detecting Base64 in log files
//! - Encoding data for safe transmission

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use thiserror::Error;

// ============================================================================
// CUSTOM ERROR TYPES
// ============================================================================

/// Custom error types for Base64 operations
#[derive(Error, Debug)]
pub enum Base64Error {
    /// Error when decoding fails
    #[error("Base64 decode error: {0}")]
    DecodeError(String),

    /// Error when input is not valid Base64
    #[error("Invalid Base64 input: {0}")]
    InvalidInput(String),

    /// Error when decoded data is not valid UTF-8
    #[error("Decoded data is not valid UTF-8")]
    NotUtf8,
}

// ============================================================================
// ENCODING TYPES
// ============================================================================

/// Available encoding types
#[derive(Debug, Clone, ValueEnum)]
pub enum EncodingType {
    /// Standard Base64 (RFC 4648)
    Standard,
    /// URL-safe Base64 (RFC 4648 URL and Filename safe)
    UrlSafe,
    /// Standard without padding
    NoPad,
    /// URL-safe without padding
    UrlSafeNoPad,
}

/// Output format options
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Plain text output
    Text,
    /// Hexadecimal output
    Hex,
    /// Binary file output
    Binary,
}

// ============================================================================
// CLI ARGUMENT STRUCTURES
// ============================================================================

/// Base64 Tool - Security-focused encoding/decoding utility
///
/// This tool provides Base64 operations with security analysis capabilities.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The subcommand to execute
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output for debugging
    #[arg(short, long, global = true)]
    verbose: bool,
}

/// Available subcommands for Base64 operations
#[derive(Subcommand, Debug)]
enum Commands {
    /// Encode data to Base64
    Encode {
        /// Data to encode (or use stdin)
        data: Option<String>,

        /// Read from file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Encoding type
        #[arg(short, long, default_value = "standard")]
        encoding: EncodingType,

        /// Output to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Wrap output at N characters (0 = no wrap)
        #[arg(short, long, default_value = "0")]
        wrap: usize,
    },

    /// Decode Base64 data
    Decode {
        /// Base64 data to decode (or use stdin)
        data: Option<String>,

        /// Read from file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Encoding type
        #[arg(short, long, default_value = "standard")]
        encoding: EncodingType,

        /// Output format
        #[arg(short = 'O', long, default_value = "text")]
        output_format: OutputFormat,

        /// Output to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Attempt to decode recursively (for nested encoding)
        #[arg(short, long)]
        recursive: bool,

        /// Maximum recursion depth
        #[arg(long, default_value = "10")]
        max_depth: usize,
    },

    /// Detect Base64 encoded strings in input
    Detect {
        /// Input data (or use stdin)
        data: Option<String>,

        /// Read from file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Minimum length for detection
        #[arg(short, long, default_value = "16")]
        min_length: usize,

        /// Try to decode detected strings
        #[arg(short, long)]
        decode: bool,
    },

    /// Analyze Base64 encoded data
    Analyze {
        /// Base64 data to analyze
        data: Option<String>,

        /// Read from file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Check for sensitive patterns in decoded content
        #[arg(short, long)]
        sensitive: bool,
    },

    /// Convert between encoding formats
    Convert {
        /// Input data
        data: Option<String>,

        /// Read from file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Source encoding
        #[arg(short, long)]
        from: String,

        /// Target encoding
        #[arg(short, long)]
        to: String,
    },

    /// Compare two Base64 strings
    Compare {
        /// First Base64 string
        first: String,

        /// Second Base64 string
        second: String,
    },

    /// Generate random Base64 data
    Generate {
        /// Number of bytes to generate
        #[arg(short, long, default_value = "32")]
        bytes: usize,

        /// Encoding type
        #[arg(short, long, default_value = "standard")]
        encoding: EncodingType,
    },
}

// ============================================================================
// BASE64 ENCODING/DECODING FUNCTIONS
// ============================================================================

/// Gets the appropriate Base64 engine for the encoding type
fn get_engine(encoding: &EncodingType) -> &'static dyn base64::Engine<Config = base64::engine::GeneralPurposeConfig> {
    match encoding {
        EncodingType::Standard => &general_purpose::STANDARD,
        EncodingType::UrlSafe => &general_purpose::URL_SAFE,
        EncodingType::NoPad => &general_purpose::STANDARD_NO_PAD,
        EncodingType::UrlSafeNoPad => &general_purpose::URL_SAFE_NO_PAD,
    }
}

/// Encodes data to Base64
///
/// # Arguments
/// * `data` - Bytes to encode
/// * `encoding` - Encoding type to use
///
/// # Returns
/// * `String` - Base64 encoded string
fn encode_base64(data: &[u8], encoding: &EncodingType) -> String {
    get_engine(encoding).encode(data)
}

/// Decodes Base64 data
///
/// # Arguments
/// * `data` - Base64 string to decode
/// * `encoding` - Encoding type to use
///
/// # Returns
/// * `Result<Vec<u8>>` - Decoded bytes or error
fn decode_base64(data: &str, encoding: &EncodingType) -> Result<Vec<u8>> {
    // Clean input (remove whitespace)
    let cleaned: String = data.chars().filter(|c| !c.is_whitespace()).collect();

    get_engine(encoding)
        .decode(&cleaned)
        .map_err(|e| Base64Error::DecodeError(e.to_string()).into())
}

/// Attempts to decode Base64 using any encoding type
///
/// # Arguments
/// * `data` - Base64 string to decode
///
/// # Returns
/// * `Option<(Vec<u8>, EncodingType)>` - Decoded bytes and detected encoding
fn try_decode_any(data: &str) -> Option<(Vec<u8>, String)> {
    let encodings = [
        (EncodingType::Standard, "standard"),
        (EncodingType::UrlSafe, "url-safe"),
        (EncodingType::NoPad, "standard-nopad"),
        (EncodingType::UrlSafeNoPad, "url-safe-nopad"),
    ];

    for (encoding, name) in encodings {
        if let Ok(decoded) = decode_base64(data, &encoding) {
            return Some((decoded, name.to_string()));
        }
    }
    None
}

/// Wraps a string at specified width
///
/// # Arguments
/// * `s` - String to wrap
/// * `width` - Characters per line (0 = no wrap)
///
/// # Returns
/// * `String` - Wrapped string
fn wrap_string(s: &str, width: usize) -> String {
    if width == 0 {
        return s.to_string();
    }

    s.chars()
        .collect::<Vec<char>>()
        .chunks(width)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n")
}

// ============================================================================
// DETECTION FUNCTIONS
// ============================================================================

/// Pattern for detecting potential Base64 strings
/// Base64 consists of: A-Z, a-z, 0-9, +, /, and = for padding
/// URL-safe variant uses - and _ instead of + and /

/// Checks if a string could be valid Base64
///
/// # Arguments
/// * `s` - String to check
///
/// # Returns
/// * `bool` - True if string could be Base64
fn is_potential_base64(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }

    // Check character set
    let valid_chars = s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    });

    if !valid_chars {
        return false;
    }

    // Check padding
    let padding_count = s.chars().rev().take_while(|&c| c == '=').count();
    if padding_count > 2 {
        return false;
    }

    // Check if padding is only at the end
    if s.contains('=') && !s.ends_with('=') {
        return false;
    }

    // Length should be divisible by 4 (with padding)
    // Or valid for no-padding variant
    true
}

/// Extracts potential Base64 strings from text
///
/// # Arguments
/// * `text` - Text to search
/// * `min_length` - Minimum length for detection
///
/// # Returns
/// * `Vec<(usize, String)>` - List of (position, base64_string)
fn detect_base64_strings(text: &str, min_length: usize) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    let mut current_start = None;
    let mut current_string = String::new();

    for (i, c) in text.chars().enumerate() {
        let is_base64_char =
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_';

        if is_base64_char {
            if current_start.is_none() {
                current_start = Some(i);
            }
            current_string.push(c);
        } else {
            if let Some(start) = current_start {
                if current_string.len() >= min_length && is_potential_base64(&current_string) {
                    results.push((start, current_string.clone()));
                }
            }
            current_start = None;
            current_string.clear();
        }
    }

    // Check last string
    if let Some(start) = current_start {
        if current_string.len() >= min_length && is_potential_base64(&current_string) {
            results.push((start, current_string));
        }
    }

    results
}

// ============================================================================
// ANALYSIS FUNCTIONS
// ============================================================================

/// Sensitive patterns to look for in decoded content
const SENSITIVE_PATTERNS: &[(&str, &str)] = &[
    ("password", "Password field detected"),
    ("passwd", "Password field detected"),
    ("secret", "Secret value detected"),
    ("token", "Authentication token detected"),
    ("api_key", "API key detected"),
    ("apikey", "API key detected"),
    ("private_key", "Private key detected"),
    ("BEGIN RSA", "RSA private key detected"),
    ("BEGIN PRIVATE", "Private key detected"),
    ("BEGIN CERTIFICATE", "Certificate detected"),
    ("ssh-rsa", "SSH key detected"),
    ("aws_access", "AWS credentials detected"),
    ("Authorization:", "Authorization header detected"),
    ("Bearer ", "Bearer token detected"),
];

/// Analyzes decoded content for security-relevant patterns
///
/// # Arguments
/// * `content` - Decoded content (as string if possible)
/// * `bytes` - Raw decoded bytes
///
/// # Returns
/// * `Vec<(String, String)>` - List of (pattern, description) findings
fn analyze_content(content: Option<&str>, bytes: &[u8]) -> Vec<(String, String)> {
    let mut findings = Vec::new();

    // Check string content if available
    if let Some(text) = content {
        for (pattern, description) in SENSITIVE_PATTERNS {
            if text.to_lowercase().contains(&pattern.to_lowercase()) {
                findings.push((pattern.to_string(), description.to_string()));
            }
        }

        // Check for JSON structure
        if text.trim_start().starts_with('{') || text.trim_start().starts_with('[') {
            findings.push(("JSON".to_string(), "JSON data structure detected".to_string()));
        }

        // Check for URL
        if text.contains("http://") || text.contains("https://") {
            findings.push(("URL".to_string(), "URL detected in content".to_string()));
        }

        // Check for email patterns
        if text.contains('@') && text.contains('.') {
            findings.push(("Email".to_string(), "Possible email address detected".to_string()));
        }
    }

    // Check binary patterns
    if bytes.len() >= 2 {
        // PNG signature
        if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            findings.push(("PNG".to_string(), "PNG image detected".to_string()));
        }
        // JPEG signature
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            findings.push(("JPEG".to_string(), "JPEG image detected".to_string()));
        }
        // PDF signature
        if bytes.starts_with(&[0x25, 0x50, 0x44, 0x46]) {
            findings.push(("PDF".to_string(), "PDF document detected".to_string()));
        }
        // ZIP/DOCX/etc signature
        if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            findings.push(("ZIP".to_string(), "ZIP archive detected".to_string()));
        }
        // ELF binary
        if bytes.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
            findings.push(("ELF".to_string(), "ELF executable detected".to_string()));
        }
        // Windows PE
        if bytes.starts_with(&[0x4D, 0x5A]) {
            findings.push(("PE".to_string(), "Windows executable detected".to_string()));
        }
        // GZIP
        if bytes.starts_with(&[0x1F, 0x8B]) {
            findings.push(("GZIP".to_string(), "GZIP compressed data detected".to_string()));
        }
    }

    findings
}

/// Recursively decodes Base64 until no more encoding is detected
///
/// # Arguments
/// * `data` - Initial data to decode
/// * `max_depth` - Maximum recursion depth
///
/// # Returns
/// * `Vec<(usize, String, Vec<u8>)>` - List of (depth, encoding_type, decoded_bytes)
fn decode_recursive(data: &str, max_depth: usize) -> Vec<(usize, String, Vec<u8>)> {
    let mut results = Vec::new();
    let mut current = data.to_string();

    for depth in 0..max_depth {
        if let Some((decoded, encoding)) = try_decode_any(&current) {
            results.push((depth + 1, encoding, decoded.clone()));

            // Try to continue if result looks like Base64
            if let Ok(text) = String::from_utf8(decoded.clone()) {
                if is_potential_base64(text.trim()) && text.len() >= 4 {
                    current = text;
                    continue;
                }
            }
            break;
        } else {
            break;
        }
    }

    results
}

// ============================================================================
// CONVERSION FUNCTIONS
// ============================================================================

/// Converts between different encodings
///
/// Supported encodings: base64, hex, url
///
/// # Arguments
/// * `data` - Data to convert
/// * `from` - Source encoding
/// * `to` - Target encoding
///
/// # Returns
/// * `Result<String>` - Converted data or error
fn convert_encoding(data: &str, from: &str, to: &str) -> Result<String> {
    // First decode from source encoding
    let bytes = match from.to_lowercase().as_str() {
        "base64" => decode_base64(data, &EncodingType::Standard)?,
        "base64url" => decode_base64(data, &EncodingType::UrlSafe)?,
        "hex" => hex::decode(data.trim())
            .context("Invalid hex input")?,
        "url" => urlencoding::decode(data)
            .context("Invalid URL encoding")?
            .into_owned()
            .into_bytes(),
        "text" | "raw" => data.as_bytes().to_vec(),
        _ => anyhow::bail!("Unknown source encoding: {}", from),
    };

    // Then encode to target encoding
    let result = match to.to_lowercase().as_str() {
        "base64" => encode_base64(&bytes, &EncodingType::Standard),
        "base64url" => encode_base64(&bytes, &EncodingType::UrlSafe),
        "hex" => hex::encode(&bytes),
        "url" => urlencoding::encode(&String::from_utf8_lossy(&bytes)).to_string(),
        "text" | "raw" => String::from_utf8_lossy(&bytes).to_string(),
        _ => anyhow::bail!("Unknown target encoding: {}", to),
    };

    Ok(result)
}

// ============================================================================
// INPUT/OUTPUT FUNCTIONS
// ============================================================================

/// Reads input from various sources
fn read_input(data: Option<&String>, file: Option<&PathBuf>) -> Result<Vec<u8>> {
    if let Some(d) = data {
        Ok(d.as_bytes().to_vec())
    } else if let Some(path) = file {
        fs::read(path).with_context(|| format!("Failed to read file: {:?}", path))
    } else {
        let mut buffer = Vec::new();
        io::stdin()
            .read_to_end(&mut buffer)
            .context("Failed to read from stdin")?;
        Ok(buffer)
    }
}

/// Writes output to various destinations
fn write_output(data: &[u8], output: Option<&PathBuf>, as_text: bool) -> Result<()> {
    if let Some(path) = output {
        fs::write(path, data).with_context(|| format!("Failed to write to {:?}", path))?;
        eprintln!("{} Wrote {} bytes to {:?}", "Success:".green(), data.len(), path);
    } else if as_text {
        print!("{}", String::from_utf8_lossy(data));
    } else {
        io::stdout()
            .write_all(data)
            .context("Failed to write to stdout")?;
    }
    Ok(())
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

/// Formats bytes as a hex dump
fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Displays analysis results
fn display_analysis(
    original: &str,
    decoded: &[u8],
    encoding_type: &str,
    findings: &[(String, String)],
) {
    println!("\n{}", "Base64 Analysis".bold().underline());
    println!("Original length: {} characters", original.len());
    println!("Decoded length: {} bytes", decoded.len());
    println!("Detected encoding: {}", encoding_type.cyan());

    // Show decoded preview
    println!("\n{}", "Decoded Preview:".yellow());
    match String::from_utf8(decoded.to_vec()) {
        Ok(text) => {
            let preview = if text.len() > 200 {
                format!("{}...", &text[..200])
            } else {
                text
            };
            println!("{}", preview);
        }
        Err(_) => {
            println!("(Binary data - showing hex)");
            let hex = format_hex(&decoded[..decoded.len().min(64)]);
            println!("{}", hex);
            if decoded.len() > 64 {
                println!("...");
            }
        }
    }

    // Show findings
    if !findings.is_empty() {
        println!("\n{}", "Security Findings:".red().bold());
        for (pattern, description) in findings {
            println!("  {} {}: {}", "!".red(), pattern.cyan(), description);
        }
    } else {
        println!("\n{} No security-relevant patterns detected", "OK:".green());
    }
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode {
            data,
            file,
            encoding,
            output,
            wrap,
        } => {
            let input = read_input(data.as_ref(), file.as_ref())?;
            let encoded = encode_base64(&input, &encoding);
            let wrapped = wrap_string(&encoded, wrap);

            write_output(wrapped.as_bytes(), output.as_ref(), true)?;
            if output.is_none() {
                println!(); // Add newline for terminal output
            }

            if cli.verbose {
                eprintln!("{} Encoded {} bytes to {} Base64 characters",
                    "Info:".blue(), input.len(), encoded.len());
            }
        }

        Commands::Decode {
            data,
            file,
            encoding,
            output_format,
            output,
            recursive,
            max_depth,
        } => {
            let input = read_input(data.as_ref(), file.as_ref())?;
            let input_str = String::from_utf8_lossy(&input);

            if recursive {
                let results = decode_recursive(input_str.trim(), max_depth);

                if results.is_empty() {
                    println!("{} Could not decode as Base64", "Error:".red());
                    std::process::exit(1);
                }

                println!("\n{}", "Recursive Decoding Results".bold().underline());
                for (depth, encoding, bytes) in &results {
                    println!("\n{}Layer {}{} (encoding: {})",
                        "=".repeat(10), depth, "=".repeat(10), encoding.cyan());
                    println!("Size: {} bytes", bytes.len());

                    match String::from_utf8(bytes.clone()) {
                        Ok(text) => {
                            let preview = if text.len() > 200 {
                                format!("{}...", &text[..200])
                            } else {
                                text
                            };
                            println!("{}", preview);
                        }
                        Err(_) => {
                            println!("(Binary data)");
                            println!("{}", format_hex(&bytes[..bytes.len().min(32)]));
                        }
                    }
                }

                // Output final result
                if let Some((_, _, final_bytes)) = results.last() {
                    write_output(final_bytes, output.as_ref(), output.is_none())?;
                }
            } else {
                let decoded = decode_base64(input_str.trim(), &encoding)?;

                match output_format {
                    OutputFormat::Text => {
                        write_output(&decoded, output.as_ref(), true)?;
                    }
                    OutputFormat::Hex => {
                        let hex = hex::encode(&decoded);
                        write_output(hex.as_bytes(), output.as_ref(), true)?;
                        println!();
                    }
                    OutputFormat::Binary => {
                        write_output(&decoded, output.as_ref(), false)?;
                    }
                }
            }
        }

        Commands::Detect {
            data,
            file,
            min_length,
            decode,
        } => {
            let input = read_input(data.as_ref(), file.as_ref())?;
            let text = String::from_utf8_lossy(&input);

            let detections = detect_base64_strings(&text, min_length);

            println!("\n{}", "Base64 Detection Results".bold().underline());
            println!("Minimum length: {}", min_length);
            println!("Found: {} potential Base64 strings\n", detections.len());

            if detections.is_empty() {
                println!("{} No Base64 strings detected", "Info:".blue());
            } else {
                for (i, (pos, b64_str)) in detections.iter().enumerate() {
                    println!("\n{}. Position: {}, Length: {}",
                        (i + 1).to_string().cyan(), pos, b64_str.len());

                    // Show preview of Base64
                    let preview = if b64_str.len() > 60 {
                        format!("{}...", &b64_str[..60])
                    } else {
                        b64_str.clone()
                    };
                    println!("   Base64: {}", preview.dimmed());

                    // Try to decode if requested
                    if decode {
                        if let Some((decoded, encoding)) = try_decode_any(b64_str) {
                            println!("   Encoding: {}", encoding.green());
                            match String::from_utf8(decoded.clone()) {
                                Ok(text) => {
                                    let decoded_preview = if text.len() > 60 {
                                        format!("{}...", &text[..60])
                                    } else {
                                        text
                                    };
                                    println!("   Decoded: {}", decoded_preview);
                                }
                                Err(_) => {
                                    println!("   Decoded: (binary, {} bytes)", decoded.len());
                                }
                            }
                        } else {
                            println!("   {} Could not decode", "Warning:".yellow());
                        }
                    }
                }
            }
        }

        Commands::Analyze {
            data,
            file,
            sensitive,
        } => {
            let input = read_input(data.as_ref(), file.as_ref())?;
            let input_str = String::from_utf8_lossy(&input);

            if let Some((decoded, encoding)) = try_decode_any(input_str.trim()) {
                let text_content = String::from_utf8(decoded.clone()).ok();
                let findings = if sensitive {
                    analyze_content(text_content.as_deref(), &decoded)
                } else {
                    Vec::new()
                };

                display_analysis(input_str.trim(), &decoded, &encoding, &findings);
            } else {
                println!("{} Input is not valid Base64", "Error:".red());
                std::process::exit(1);
            }
        }

        Commands::Convert { data, file, from, to } => {
            let input = read_input(data.as_ref(), file.as_ref())?;
            let input_str = String::from_utf8_lossy(&input);

            let result = convert_encoding(input_str.trim(), &from, &to)?;
            println!("{}", result);

            if cli.verbose {
                eprintln!("{} Converted from {} to {}", "Info:".blue(), from, to);
            }
        }

        Commands::Compare { first, second } => {
            println!("\n{}", "Base64 Comparison".bold().underline());

            let decode1 = try_decode_any(&first);
            let decode2 = try_decode_any(&second);

            println!("\nString 1: {} chars", first.len());
            println!("String 2: {} chars", second.len());

            match (decode1, decode2) {
                (Some((bytes1, enc1)), Some((bytes2, enc2))) => {
                    println!("\nDecoded 1: {} bytes ({})", bytes1.len(), enc1);
                    println!("Decoded 2: {} bytes ({})", bytes2.len(), enc2);

                    if bytes1 == bytes2 {
                        println!("\n{} Decoded content is IDENTICAL", "OK:".green().bold());
                    } else {
                        println!("\n{} Decoded content is DIFFERENT", "DIFF:".red().bold());

                        // Show difference
                        let min_len = bytes1.len().min(bytes2.len());
                        let mut first_diff = None;
                        for i in 0..min_len {
                            if bytes1[i] != bytes2[i] {
                                first_diff = Some(i);
                                break;
                            }
                        }

                        if let Some(pos) = first_diff {
                            println!("First difference at byte: {}", pos);
                        } else if bytes1.len() != bytes2.len() {
                            println!("Length difference: {} vs {} bytes",
                                bytes1.len(), bytes2.len());
                        }
                    }
                }
                _ => {
                    println!("\n{} One or both inputs are not valid Base64", "Error:".red());
                }
            }
        }

        Commands::Generate { bytes, encoding } => {
            use std::time::{SystemTime, UNIX_EPOCH};

            // Simple random generation (not cryptographically secure)
            // In production, use rand crate with OsRng
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;

            let mut random_bytes = Vec::with_capacity(bytes);
            let mut state = seed;
            for _ in 0..bytes {
                // Simple LCG for demo purposes
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                random_bytes.push((state >> 33) as u8);
            }

            let encoded = encode_base64(&random_bytes, &encoding);
            println!("{}", encoded);

            if cli.verbose {
                eprintln!("{} Generated {} random bytes, encoded to {} characters",
                    "Info:".blue(), bytes, encoded.len());
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

    #[test]
    fn test_encode_decode_standard() {
        let original = b"Hello, World!";
        let encoded = encode_base64(original, &EncodingType::Standard);
        let decoded = decode_base64(&encoded, &EncodingType::Standard).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_encode_decode_url_safe() {
        let original = b"Test+Data/With=Special";
        let encoded = encode_base64(original, &EncodingType::UrlSafe);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        let decoded = decode_base64(&encoded, &EncodingType::UrlSafe).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_encode_decode_no_padding() {
        let original = b"Test";
        let encoded = encode_base64(original, &EncodingType::NoPad);
        assert!(!encoded.contains('='));

        let decoded = decode_base64(&encoded, &EncodingType::NoPad).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_is_potential_base64() {
        assert!(is_potential_base64("SGVsbG8="));
        assert!(is_potential_base64("SGVsbG8gV29ybGQh"));
        assert!(!is_potential_base64("abc")); // Too short
        assert!(!is_potential_base64("Hello World!")); // Contains space
    }

    #[test]
    fn test_detect_base64_strings() {
        let text = "The password is SGVsbG8gV29ybGQh and the key is dGVzdA==";
        let detections = detect_base64_strings(text, 4);

        assert_eq!(detections.len(), 2);
        assert!(detections.iter().any(|(_, s)| s == "SGVsbG8gV29ybGQh"));
        assert!(detections.iter().any(|(_, s)| s == "dGVzdA=="));
    }

    #[test]
    fn test_try_decode_any() {
        let b64 = "SGVsbG8=";
        let result = try_decode_any(b64);
        assert!(result.is_some());
        let (decoded, _) = result.unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_wrap_string() {
        let s = "ABCDEFGHIJ";
        let wrapped = wrap_string(s, 3);
        assert_eq!(wrapped, "ABC\nDEF\nGHI\nJ");

        let no_wrap = wrap_string(s, 0);
        assert_eq!(no_wrap, s);
    }

    #[test]
    fn test_convert_encoding() {
        // Base64 to hex
        let b64 = "SGVsbG8=";
        let hex = convert_encoding(b64, "base64", "hex").unwrap();
        assert_eq!(hex, "48656c6c6f");

        // Hex to Base64
        let back = convert_encoding(&hex, "hex", "base64").unwrap();
        assert_eq!(back, b64);
    }

    #[test]
    fn test_analyze_content() {
        let content = "password=secret123";
        let findings = analyze_content(Some(content), content.as_bytes());

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|(p, _)| p.to_lowercase() == "password"));
    }

    #[test]
    fn test_decode_recursive() {
        // Double encoded: "Hello" -> "SGVsbG8=" -> "U0dWc2JHOD0="
        let double_encoded = "U0dWc2JHOD0=";
        let results = decode_recursive(double_encoded, 10);

        assert_eq!(results.len(), 2);
        // Final result should be "Hello"
        assert_eq!(results.last().unwrap().2, b"Hello");
    }

    #[test]
    fn test_invalid_base64() {
        let result = decode_base64("Not valid base64!!!", &EncodingType::Standard);
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_detection() {
        // PNG signature
        let png_header: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let findings = analyze_content(None, &png_header);
        assert!(findings.iter().any(|(p, _)| p == "PNG"));
    }
}
