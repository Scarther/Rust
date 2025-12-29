//! # Encoding Converter - Rust Security Bible
//!
//! A comprehensive tool for converting between various encodings commonly
//! encountered in security analysis, CTFs, and web application testing.
//!
//! ## Features
//! - Base64 encoding/decoding (standard and URL-safe)
//! - Hexadecimal encoding/decoding
//! - URL encoding/decoding
//! - HTML entity encoding/decoding
//! - Unicode transformations
//! - ROT13 and Caesar cipher
//! - Binary representations
//! - Hash-like transformations
//!
//! ## Security Applications
//! - Analyzing encoded payloads
//! - CTF challenges
//! - Web application testing
//! - Malware analysis
//! - Data exfiltration detection

use base64::{engine::general_purpose, Engine};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Custom error types for encoding operations
#[derive(Error, Debug)]
pub enum EncodingError {
    #[error("Invalid input for {encoding}: {reason}")]
    InvalidInput { encoding: String, reason: String },

    #[error("Decode error: {0}")]
    DecodeError(String),

    #[error("Unsupported encoding: {0}")]
    UnsupportedEncoding(String),

    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
}

pub type EncodingResult<T> = Result<T, EncodingError>;

// =============================================================================
// CLI INTERFACE
// =============================================================================

/// Encoding Converter - Multi-format encoding tool
#[derive(Parser, Debug)]
#[command(name = "encoder")]
#[command(author = "Security Developer")]
#[command(version = "1.0")]
#[command(about = "Convert between various encodings for security analysis")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encode input using specified encoding
    Encode {
        /// Encoding type to use
        #[arg(short, long)]
        encoding: EncodingType,

        /// Input string to encode
        input: String,

        /// Read input from file instead
        #[arg(short, long)]
        file: Option<String>,
    },

    /// Decode input using specified encoding
    Decode {
        /// Encoding type to use
        #[arg(short, long)]
        encoding: EncodingType,

        /// Input string to decode
        input: String,

        /// Read input from file instead
        #[arg(short, long)]
        file: Option<String>,
    },

    /// Auto-detect and decode input
    Auto {
        /// Input string to analyze
        input: String,
    },

    /// Apply multiple encodings in sequence
    Chain {
        /// Comma-separated list of encodings
        #[arg(short, long)]
        encodings: String,

        /// Input string
        input: String,

        /// Decode instead of encode
        #[arg(short, long)]
        decode: bool,
    },

    /// Analyze a string for possible encodings
    Analyze {
        /// Input string to analyze
        input: String,
    },

    /// Show all representations of input
    All {
        /// Input string to convert
        input: String,
    },

    /// XOR encode/decode with a key
    Xor {
        /// Input string
        input: String,

        /// XOR key
        #[arg(short, long)]
        key: String,

        /// Treat input as hex
        #[arg(long)]
        hex_input: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum EncodingType {
    Base64,
    Base64Url,
    Hex,
    Url,
    UrlFull,
    Html,
    HtmlDec,
    HtmlHex,
    Unicode,
    UnicodeEscape,
    Binary,
    Octal,
    Rot13,
    Caesar,
    Reverse,
    Ascii,
    Lower,
    Upper,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Result of encoding analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingAnalysis {
    pub input: String,
    pub possible_encodings: Vec<String>,
    pub decoded_attempts: HashMap<String, String>,
    pub characteristics: Vec<String>,
}

/// Multi-encoding result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiEncodingResult {
    pub original: String,
    pub encodings: HashMap<String, String>,
}

// =============================================================================
// ENCODING IMPLEMENTATIONS
// =============================================================================

/// Encoder/Decoder for various formats
pub struct Encoder;

impl Encoder {
    // =========================================================================
    // BASE64
    // =========================================================================

    /// Encode to standard Base64
    pub fn base64_encode(input: &str) -> String {
        general_purpose::STANDARD.encode(input.as_bytes())
    }

    /// Decode from standard Base64
    pub fn base64_decode(input: &str) -> EncodingResult<String> {
        let bytes = general_purpose::STANDARD.decode(input)?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Encode to URL-safe Base64
    pub fn base64url_encode(input: &str) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(input.as_bytes())
    }

    /// Decode from URL-safe Base64
    pub fn base64url_decode(input: &str) -> EncodingResult<String> {
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(input)?;
        Ok(String::from_utf8(bytes)?)
    }

    // =========================================================================
    // HEXADECIMAL
    // =========================================================================

    /// Encode to hexadecimal
    pub fn hex_encode(input: &str) -> String {
        hex::encode(input.as_bytes())
    }

    /// Decode from hexadecimal
    pub fn hex_decode(input: &str) -> EncodingResult<String> {
        let bytes = hex::decode(input)?;
        Ok(String::from_utf8(bytes)?)
    }

    // =========================================================================
    // URL ENCODING
    // =========================================================================

    /// URL encode (standard - only special characters)
    pub fn url_encode(input: &str) -> String {
        urlencoding::encode(input).into_owned()
    }

    /// URL decode
    pub fn url_decode(input: &str) -> EncodingResult<String> {
        percent_decode_str(input)
            .decode_utf8()
            .map(|s| s.into_owned())
            .map_err(|e| EncodingError::DecodeError(e.to_string()))
    }

    /// Full URL encode (all characters except alphanumeric)
    pub fn url_encode_full(input: &str) -> String {
        const FULL_ENCODE: &AsciiSet = &CONTROLS
            .add(b' ')
            .add(b'!')
            .add(b'"')
            .add(b'#')
            .add(b'$')
            .add(b'%')
            .add(b'&')
            .add(b'\'')
            .add(b'(')
            .add(b')')
            .add(b'*')
            .add(b'+')
            .add(b',')
            .add(b'-')
            .add(b'.')
            .add(b'/')
            .add(b':')
            .add(b';')
            .add(b'<')
            .add(b'=')
            .add(b'>')
            .add(b'?')
            .add(b'@')
            .add(b'[')
            .add(b'\\')
            .add(b']')
            .add(b'^')
            .add(b'_')
            .add(b'`')
            .add(b'{')
            .add(b'|')
            .add(b'}')
            .add(b'~');

        utf8_percent_encode(input, FULL_ENCODE).to_string()
    }

    // =========================================================================
    // HTML ENCODING
    // =========================================================================

    /// HTML entity encode
    pub fn html_encode(input: &str) -> String {
        html_escape::encode_text(input).into_owned()
    }

    /// HTML entity decode
    pub fn html_decode(input: &str) -> String {
        html_escape::decode_html_entities(input).into_owned()
    }

    /// HTML decimal encode (&#65; format)
    pub fn html_decimal_encode(input: &str) -> String {
        input.chars().map(|c| format!("&#{};", c as u32)).collect()
    }

    /// HTML hex encode (&#x41; format)
    pub fn html_hex_encode(input: &str) -> String {
        input
            .chars()
            .map(|c| format!("&#x{:x};", c as u32))
            .collect()
    }

    // =========================================================================
    // UNICODE
    // =========================================================================

    /// Unicode escape encode (\u0041 format)
    pub fn unicode_escape_encode(input: &str) -> String {
        input
            .chars()
            .map(|c| {
                if c.is_ascii() {
                    format!("\\u{:04x}", c as u32)
                } else {
                    format!("\\u{:04x}", c as u32)
                }
            })
            .collect()
    }

    /// Unicode escape decode
    pub fn unicode_escape_decode(input: &str) -> EncodingResult<String> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'u') {
                chars.next(); // consume 'u'
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() == 4 {
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(decoded) = char::from_u32(code) {
                            result.push(decoded);
                            continue;
                        }
                    }
                }
                result.push_str(&format!("\\u{}", hex));
            } else {
                result.push(c);
            }
        }

        Ok(result)
    }

    /// Unicode codepoints (U+0041 format)
    pub fn unicode_codepoint_encode(input: &str) -> String {
        input
            .chars()
            .map(|c| format!("U+{:04X}", c as u32))
            .collect::<Vec<_>>()
            .join(" ")
    }

    // =========================================================================
    // BINARY AND OCTAL
    // =========================================================================

    /// Binary encode
    pub fn binary_encode(input: &str) -> String {
        input
            .bytes()
            .map(|b| format!("{:08b}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Binary decode
    pub fn binary_decode(input: &str) -> EncodingResult<String> {
        let bytes: Result<Vec<u8>, _> = input
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 2))
            .collect();

        let bytes =
            bytes.map_err(|e| EncodingError::DecodeError(format!("Invalid binary: {}", e)))?;

        Ok(String::from_utf8(bytes)?)
    }

    /// Octal encode
    pub fn octal_encode(input: &str) -> String {
        input
            .bytes()
            .map(|b| format!("{:03o}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Octal decode
    pub fn octal_decode(input: &str) -> EncodingResult<String> {
        let bytes: Result<Vec<u8>, _> = input
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 8))
            .collect();

        let bytes =
            bytes.map_err(|e| EncodingError::DecodeError(format!("Invalid octal: {}", e)))?;

        Ok(String::from_utf8(bytes)?)
    }

    // =========================================================================
    // CIPHERS
    // =========================================================================

    /// ROT13 encode/decode (symmetric)
    pub fn rot13(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
                'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
                _ => c,
            })
            .collect()
    }

    /// Caesar cipher with custom shift
    pub fn caesar(input: &str, shift: i32) -> String {
        let shift = ((shift % 26) + 26) % 26; // Normalize to 0-25
        input
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                    let offset = (c as u8 - base + shift as u8) % 26;
                    (base + offset) as char
                } else {
                    c
                }
            })
            .collect()
    }

    // =========================================================================
    // STRING TRANSFORMATIONS
    // =========================================================================

    /// Reverse string
    pub fn reverse(input: &str) -> String {
        input.chars().rev().collect()
    }

    /// To ASCII values
    pub fn to_ascii(input: &str) -> String {
        input
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// From ASCII values
    pub fn from_ascii(input: &str) -> EncodingResult<String> {
        let bytes: Result<Vec<u8>, _> = input.split_whitespace().map(|s| s.parse::<u8>()).collect();

        let bytes =
            bytes.map_err(|e| EncodingError::DecodeError(format!("Invalid ASCII: {}", e)))?;

        Ok(String::from_utf8(bytes)?)
    }

    // =========================================================================
    // XOR OPERATIONS
    // =========================================================================

    /// XOR with key
    pub fn xor(input: &[u8], key: &[u8]) -> Vec<u8> {
        input
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect()
    }

    /// XOR and return as hex
    pub fn xor_to_hex(input: &str, key: &str) -> String {
        let result = Self::xor(input.as_bytes(), key.as_bytes());
        hex::encode(result)
    }

    /// XOR from hex
    pub fn xor_from_hex(input: &str, key: &str) -> EncodingResult<String> {
        let bytes = hex::decode(input)?;
        let result = Self::xor(&bytes, key.as_bytes());
        Ok(String::from_utf8(result)?)
    }

    // =========================================================================
    // ENCODING DETECTION
    // =========================================================================

    /// Detect possible encoding of input
    pub fn detect_encoding(input: &str) -> Vec<String> {
        let mut possible = Vec::new();

        // Check for Base64
        if Self::looks_like_base64(input) {
            possible.push("Base64".to_string());
        }

        // Check for Hex
        if Self::looks_like_hex(input) {
            possible.push("Hex".to_string());
        }

        // Check for URL encoding
        if input.contains('%') {
            possible.push("URL Encoded".to_string());
        }

        // Check for HTML entities
        if input.contains('&') && input.contains(';') {
            possible.push("HTML Entities".to_string());
        }

        // Check for Unicode escapes
        if input.contains("\\u") {
            possible.push("Unicode Escape".to_string());
        }

        // Check for binary
        if input.chars().all(|c| c == '0' || c == '1' || c == ' ') {
            possible.push("Binary".to_string());
        }

        if possible.is_empty() {
            possible.push("Plain Text".to_string());
        }

        possible
    }

    /// Check if string looks like Base64
    fn looks_like_base64(input: &str) -> bool {
        let clean = input.trim();
        if clean.is_empty() {
            return false;
        }

        // Base64 characteristics
        let valid_chars = clean
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

        let proper_padding = !clean.contains("===") && clean.matches('=').count() <= 2;

        valid_chars && proper_padding && clean.len() >= 4
    }

    /// Check if string looks like hex
    fn looks_like_hex(input: &str) -> bool {
        let clean = input.replace(' ', "").to_lowercase();
        clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) && clean.len() >= 2
    }

    /// Get all characteristics of input
    pub fn analyze_characteristics(input: &str) -> Vec<String> {
        let mut chars = Vec::new();

        chars.push(format!("Length: {} characters", input.len()));
        chars.push(format!("Bytes: {} bytes", input.as_bytes().len()));

        if input.is_ascii() {
            chars.push("ASCII only".to_string());
        } else {
            chars.push("Contains non-ASCII".to_string());
        }

        let alpha = input.chars().filter(|c| c.is_alphabetic()).count();
        let digit = input.chars().filter(|c| c.is_numeric()).count();
        let special = input.chars().filter(|c| !c.is_alphanumeric()).count();

        chars.push(format!(
            "Composition: {} alpha, {} digit, {} special",
            alpha, digit, special
        ));

        if input.chars().all(|c| c.is_uppercase() || !c.is_alphabetic()) {
            chars.push("All uppercase".to_string());
        } else if input.chars().all(|c| c.is_lowercase() || !c.is_alphabetic()) {
            chars.push("All lowercase".to_string());
        }

        chars
    }
}

// =============================================================================
// MAIN ENCODING/DECODING DISPATCHER
// =============================================================================

/// Apply encoding to input
fn encode(encoding: &EncodingType, input: &str) -> EncodingResult<String> {
    Ok(match encoding {
        EncodingType::Base64 => Encoder::base64_encode(input),
        EncodingType::Base64Url => Encoder::base64url_encode(input),
        EncodingType::Hex => Encoder::hex_encode(input),
        EncodingType::Url => Encoder::url_encode(input),
        EncodingType::UrlFull => Encoder::url_encode_full(input),
        EncodingType::Html => Encoder::html_encode(input),
        EncodingType::HtmlDec => Encoder::html_decimal_encode(input),
        EncodingType::HtmlHex => Encoder::html_hex_encode(input),
        EncodingType::Unicode => Encoder::unicode_codepoint_encode(input),
        EncodingType::UnicodeEscape => Encoder::unicode_escape_encode(input),
        EncodingType::Binary => Encoder::binary_encode(input),
        EncodingType::Octal => Encoder::octal_encode(input),
        EncodingType::Rot13 => Encoder::rot13(input),
        EncodingType::Caesar => Encoder::caesar(input, 3), // Default shift of 3
        EncodingType::Reverse => Encoder::reverse(input),
        EncodingType::Ascii => Encoder::to_ascii(input),
        EncodingType::Lower => input.to_lowercase(),
        EncodingType::Upper => input.to_uppercase(),
    })
}

/// Apply decoding to input
fn decode(encoding: &EncodingType, input: &str) -> EncodingResult<String> {
    match encoding {
        EncodingType::Base64 => Encoder::base64_decode(input),
        EncodingType::Base64Url => Encoder::base64url_decode(input),
        EncodingType::Hex => Encoder::hex_decode(input),
        EncodingType::Url | EncodingType::UrlFull => Encoder::url_decode(input),
        EncodingType::Html | EncodingType::HtmlDec | EncodingType::HtmlHex => {
            Ok(Encoder::html_decode(input))
        }
        EncodingType::UnicodeEscape => Encoder::unicode_escape_decode(input),
        EncodingType::Binary => Encoder::binary_decode(input),
        EncodingType::Octal => Encoder::octal_decode(input),
        EncodingType::Rot13 => Ok(Encoder::rot13(input)), // Symmetric
        EncodingType::Caesar => Ok(Encoder::caesar(input, -3)), // Reverse shift
        EncodingType::Reverse => Ok(Encoder::reverse(input)), // Symmetric
        EncodingType::Ascii => Encoder::from_ascii(input),
        EncodingType::Unicode => Err(EncodingError::UnsupportedEncoding(
            "Unicode codepoint decode not supported".to_string(),
        )),
        EncodingType::Lower => Ok(input.to_lowercase()),
        EncodingType::Upper => Ok(input.to_uppercase()),
    }
}

/// Generate all encodings of input
fn all_encodings(input: &str) -> MultiEncodingResult {
    let mut encodings = HashMap::new();

    encodings.insert("Base64".to_string(), Encoder::base64_encode(input));
    encodings.insert("Base64-URL".to_string(), Encoder::base64url_encode(input));
    encodings.insert("Hex".to_string(), Encoder::hex_encode(input));
    encodings.insert("URL".to_string(), Encoder::url_encode(input));
    encodings.insert("URL-Full".to_string(), Encoder::url_encode_full(input));
    encodings.insert("HTML".to_string(), Encoder::html_encode(input));
    encodings.insert("HTML-Dec".to_string(), Encoder::html_decimal_encode(input));
    encodings.insert("HTML-Hex".to_string(), Encoder::html_hex_encode(input));
    encodings.insert(
        "Unicode".to_string(),
        Encoder::unicode_codepoint_encode(input),
    );
    encodings.insert(
        "Unicode-Escape".to_string(),
        Encoder::unicode_escape_encode(input),
    );
    encodings.insert("Binary".to_string(), Encoder::binary_encode(input));
    encodings.insert("Octal".to_string(), Encoder::octal_encode(input));
    encodings.insert("ROT13".to_string(), Encoder::rot13(input));
    encodings.insert("Reversed".to_string(), Encoder::reverse(input));
    encodings.insert("ASCII".to_string(), Encoder::to_ascii(input));

    MultiEncodingResult {
        original: input.to_string(),
        encodings,
    }
}

/// Try to auto-decode input
fn auto_decode(input: &str) -> EncodingAnalysis {
    let possible = Encoder::detect_encoding(input);
    let characteristics = Encoder::analyze_characteristics(input);
    let mut decoded_attempts = HashMap::new();

    // Try Base64
    if let Ok(decoded) = Encoder::base64_decode(input) {
        if decoded.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
            decoded_attempts.insert("Base64".to_string(), decoded);
        }
    }

    // Try Hex
    if let Ok(decoded) = Encoder::hex_decode(input) {
        if decoded.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
            decoded_attempts.insert("Hex".to_string(), decoded);
        }
    }

    // Try URL decode
    if let Ok(decoded) = Encoder::url_decode(input) {
        if decoded != input {
            decoded_attempts.insert("URL".to_string(), decoded);
        }
    }

    // Try HTML decode
    let html_decoded = Encoder::html_decode(input);
    if html_decoded != input {
        decoded_attempts.insert("HTML".to_string(), html_decoded);
    }

    // Try ROT13
    let rot13 = Encoder::rot13(input);
    decoded_attempts.insert("ROT13".to_string(), rot13);

    EncodingAnalysis {
        input: input.to_string(),
        possible_encodings: possible,
        decoded_attempts,
        characteristics,
    }
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!(
        "{}",
        "Encoding Converter - Security Analysis Tool"
            .bright_cyan()
            .bold()
    );
    println!("{}", "=".repeat(50));

    match cli.command {
        Commands::Encode {
            encoding,
            input,
            file,
        } => {
            let input_data = if let Some(path) = file {
                std::fs::read_to_string(path)?
            } else {
                input
            };

            println!(
                "\n{} with {:?}\n",
                "Encoding".cyan(),
                encoding
            );
            println!("{}: {}", "Input".bold(), input_data.green());

            match encode(&encoding, &input_data) {
                Ok(result) => {
                    println!("{}: {}", "Output".bold(), result.yellow());
                }
                Err(e) => {
                    eprintln!("{}: {}", "Error".red(), e);
                }
            }
        }

        Commands::Decode {
            encoding,
            input,
            file,
        } => {
            let input_data = if let Some(path) = file {
                std::fs::read_to_string(path)?
            } else {
                input
            };

            println!(
                "\n{} from {:?}\n",
                "Decoding".cyan(),
                encoding
            );
            println!("{}: {}", "Input".bold(), input_data.green());

            match decode(&encoding, &input_data) {
                Ok(result) => {
                    println!("{}: {}", "Output".bold(), result.yellow());
                }
                Err(e) => {
                    eprintln!("{}: {}", "Error".red(), e);
                }
            }
        }

        Commands::Auto { input } => {
            println!("\n{}\n", "Auto-detecting and decoding".cyan());

            let analysis = auto_decode(&input);

            println!("{}: {}", "Input".bold(), input.green());
            println!(
                "\n{}: {}",
                "Possible Encodings".bold(),
                analysis.possible_encodings.join(", ").yellow()
            );

            println!("\n{}:", "Characteristics".bold());
            for char in &analysis.characteristics {
                println!("  - {}", char);
            }

            println!("\n{}:", "Decoded Attempts".bold());
            for (enc, decoded) in &analysis.decoded_attempts {
                println!("  {}: {}", enc.cyan(), decoded);
            }
        }

        Commands::Chain {
            encodings,
            input,
            decode: do_decode,
        } => {
            let encoding_list: Vec<&str> = encodings.split(',').map(|s| s.trim()).collect();

            println!(
                "\n{} through: {}\n",
                if do_decode { "Decoding" } else { "Encoding" }.cyan(),
                encodings.yellow()
            );

            let mut current = input.clone();
            println!("{}: {}", "Start".bold(), current.green());

            for enc_str in encoding_list {
                let enc = match enc_str.to_lowercase().as_str() {
                    "base64" => EncodingType::Base64,
                    "base64url" => EncodingType::Base64Url,
                    "hex" => EncodingType::Hex,
                    "url" => EncodingType::Url,
                    "urlfull" => EncodingType::UrlFull,
                    "html" => EncodingType::Html,
                    "rot13" => EncodingType::Rot13,
                    "reverse" => EncodingType::Reverse,
                    "binary" => EncodingType::Binary,
                    _ => {
                        eprintln!("{}: Unknown encoding '{}'", "Warning".yellow(), enc_str);
                        continue;
                    }
                };

                let result = if do_decode {
                    decode(&enc, &current)
                } else {
                    encode(&enc, &current)
                };

                match result {
                    Ok(output) => {
                        println!("  {} {}: {}", "->".dimmed(), enc_str.cyan(), output);
                        current = output;
                    }
                    Err(e) => {
                        eprintln!("{} at {}: {}", "Error".red(), enc_str, e);
                        break;
                    }
                }
            }

            println!("\n{}: {}", "Final".bold(), current.yellow());
        }

        Commands::Analyze { input } => {
            println!("\n{}\n", "Analyzing input".cyan());

            let analysis = auto_decode(&input);

            println!("{}: {}", "Input".bold(), input.green());
            println!("{}: {} chars", "Length".bold(), input.len());

            println!("\n{}:", "Characteristics".bold());
            for char in &analysis.characteristics {
                println!("  - {}", char);
            }

            println!(
                "\n{}: {}",
                "Possible Encodings".bold(),
                analysis.possible_encodings.join(", ").yellow()
            );

            // Entropy calculation (simple)
            let mut freq = HashMap::new();
            for c in input.chars() {
                *freq.entry(c).or_insert(0) += 1;
            }
            let len = input.len() as f64;
            let entropy: f64 = freq
                .values()
                .map(|&count| {
                    let p = count as f64 / len;
                    -p * p.log2()
                })
                .sum();
            println!("\n{}: {:.2} bits/char", "Entropy".bold(), entropy);
        }

        Commands::All { input } => {
            println!("\n{}\n", "All encodings".cyan());
            println!("{}: {}\n", "Input".bold(), input.green());

            let result = all_encodings(&input);

            for (name, encoded) in &result.encodings {
                println!("{}: {}", name.cyan().bold(), encoded);
            }
        }

        Commands::Xor {
            input,
            key,
            hex_input,
        } => {
            println!("\n{}\n", "XOR Operation".cyan());
            println!("{}: {}", "Input".bold(), input.green());
            println!("{}: {}", "Key".bold(), key.yellow());

            if hex_input {
                match Encoder::xor_from_hex(&input, &key) {
                    Ok(result) => {
                        println!("\n{}: {}", "Decoded".bold(), result);
                    }
                    Err(e) => {
                        eprintln!("{}: {}", "Error".red(), e);
                    }
                }
            } else {
                let result = Encoder::xor_to_hex(&input, &key);
                println!("\n{}: {}", "Encoded (hex)".bold(), result);
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
    fn test_base64_encode_decode() {
        let input = "Hello, World!";
        let encoded = Encoder::base64_encode(input);
        let decoded = Encoder::base64_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_base64url_encode_decode() {
        let input = "Hello+World/Test";
        let encoded = Encoder::base64url_encode(input);
        let decoded = Encoder::base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
        // URL-safe should not contain + or /
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_hex_encode_decode() {
        let input = "Test";
        let encoded = Encoder::hex_encode(input);
        assert_eq!(encoded, "54657374");
        let decoded = Encoder::hex_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_url_encode_decode() {
        let input = "Hello World!";
        let encoded = Encoder::url_encode(input);
        assert!(encoded.contains("%20") || encoded.contains("+"));
        let decoded = Encoder::url_decode(&encoded).unwrap();
        // URL decode converts + back to space
        assert!(decoded == input || decoded == "Hello+World!");
    }

    #[test]
    fn test_html_encode_decode() {
        let input = "<script>alert('xss')</script>";
        let encoded = Encoder::html_encode(input);
        assert!(encoded.contains("&lt;"));
        let decoded = Encoder::html_decode(&encoded);
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_html_decimal() {
        let input = "A";
        let encoded = Encoder::html_decimal_encode(input);
        assert_eq!(encoded, "&#65;");
    }

    #[test]
    fn test_html_hex() {
        let input = "A";
        let encoded = Encoder::html_hex_encode(input);
        assert_eq!(encoded, "&#x41;");
    }

    #[test]
    fn test_rot13() {
        let input = "Hello";
        let encoded = Encoder::rot13(input);
        assert_eq!(encoded, "Uryyb");
        // ROT13 is symmetric
        let decoded = Encoder::rot13(&encoded);
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_caesar() {
        let input = "ABC";
        let encoded = Encoder::caesar(input, 3);
        assert_eq!(encoded, "DEF");
        let decoded = Encoder::caesar(&encoded, -3);
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_reverse() {
        let input = "Hello";
        let reversed = Encoder::reverse(input);
        assert_eq!(reversed, "olleH");
    }

    #[test]
    fn test_binary_encode_decode() {
        let input = "A";
        let encoded = Encoder::binary_encode(input);
        assert_eq!(encoded, "01000001");
        let decoded = Encoder::binary_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_octal_encode_decode() {
        let input = "A";
        let encoded = Encoder::octal_encode(input);
        assert_eq!(encoded, "101");
        let decoded = Encoder::octal_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_ascii() {
        let input = "AB";
        let encoded = Encoder::to_ascii(input);
        assert_eq!(encoded, "65 66");
        let decoded = Encoder::from_ascii(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_unicode_escape() {
        let input = "A";
        let encoded = Encoder::unicode_escape_encode(input);
        assert_eq!(encoded, "\\u0041");
        let decoded = Encoder::unicode_escape_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_xor() {
        let input = b"Hello";
        let key = b"key";
        let encrypted = Encoder::xor(input, key);
        let decrypted = Encoder::xor(&encrypted, key);
        assert_eq!(decrypted, input);
    }

    #[test]
    fn test_detect_base64() {
        let encoded = Encoder::base64_encode("test");
        let detected = Encoder::detect_encoding(&encoded);
        assert!(detected.contains(&"Base64".to_string()));
    }

    #[test]
    fn test_detect_hex() {
        let encoded = Encoder::hex_encode("test");
        let detected = Encoder::detect_encoding(&encoded);
        assert!(detected.contains(&"Hex".to_string()));
    }

    #[test]
    fn test_looks_like_base64() {
        assert!(Encoder::looks_like_base64("SGVsbG8="));
        assert!(!Encoder::looks_like_base64("Not Base64!@#"));
    }

    #[test]
    fn test_looks_like_hex() {
        assert!(Encoder::looks_like_hex("48656c6c6f"));
        assert!(!Encoder::looks_like_hex("Not Hex!"));
    }

    #[test]
    fn test_analyze_characteristics() {
        let chars = Encoder::analyze_characteristics("Hello123!");
        assert!(chars.iter().any(|c| c.contains("Length")));
        assert!(chars.iter().any(|c| c.contains("ASCII")));
    }

    #[test]
    fn test_all_encodings() {
        let result = all_encodings("test");
        assert!(result.encodings.contains_key("Base64"));
        assert!(result.encodings.contains_key("Hex"));
    }
}
