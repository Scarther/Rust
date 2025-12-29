//! # HTTP Client Security Tool
//!
//! This module demonstrates making HTTP requests in Rust with security
//! considerations, including:
//! - GET and POST requests
//! - Header manipulation
//! - Cookie handling
//! - Response analysis
//! - Security header checking
//!
//! ## Security Use Cases
//! - Testing web application endpoints
//! - Checking security headers
//! - Analyzing server responses
//! - Basic web reconnaissance

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, USER_AGENT};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use url::Url;

// ============================================================================
// CUSTOM ERROR TYPES
// ============================================================================

/// Custom error types for HTTP operations
#[derive(Error, Debug)]
pub enum HttpError {
    /// Error when URL is invalid
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Error when request fails
    #[error("Request failed: {0}")]
    RequestFailed(String),

    /// Error when response parsing fails
    #[error("Failed to parse response: {0}")]
    ParseError(String),

    /// Error when timeout occurs
    #[error("Request timed out after {0} seconds")]
    Timeout(u64),
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Represents an HTTP response with analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseInfo {
    /// HTTP status code
    pub status_code: u16,
    /// Status reason phrase
    pub status_reason: String,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body (truncated if large)
    pub body: String,
    /// Content length
    pub content_length: Option<u64>,
    /// Content type
    pub content_type: Option<String>,
    /// Response time in milliseconds
    pub response_time_ms: u128,
    /// Final URL (after redirects)
    pub final_url: String,
    /// Number of redirects followed
    pub redirect_count: u32,
}

/// Security header analysis result
#[derive(Debug)]
pub struct SecurityHeaderAnalysis {
    /// Header name
    pub header: String,
    /// Whether header is present
    pub present: bool,
    /// Header value if present
    pub value: Option<String>,
    /// Recommendation
    pub recommendation: String,
    /// Severity (1-10)
    pub severity: u8,
}

/// Output format options
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Pretty printed output
    Pretty,
    /// JSON output
    Json,
    /// Headers only
    Headers,
    /// Body only
    Body,
}

// ============================================================================
// CLI ARGUMENT STRUCTURES
// ============================================================================

/// HTTP Client Tool - Security-focused web requests
///
/// This tool provides HTTP client functionality with security analysis.
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

/// Available subcommands for HTTP operations
#[derive(Subcommand, Debug)]
enum Commands {
    /// Make a GET request
    Get {
        /// URL to request
        url: String,

        /// Custom headers (format: "Header: Value")
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Request timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Follow redirects (max count)
        #[arg(short, long, default_value = "10")]
        redirects: usize,

        /// Output format
        #[arg(short, long, default_value = "pretty")]
        output: OutputFormat,

        /// Save response body to file
        #[arg(short, long)]
        save: Option<PathBuf>,

        /// Custom User-Agent string
        #[arg(short = 'A', long)]
        user_agent: Option<String>,

        /// Disable SSL certificate verification (INSECURE!)
        #[arg(long)]
        insecure: bool,
    },

    /// Make a POST request
    Post {
        /// URL to request
        url: String,

        /// Request body data
        #[arg(short, long)]
        data: Option<String>,

        /// Send data as JSON
        #[arg(short, long)]
        json: bool,

        /// Read body from file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Custom headers (format: "Header: Value")
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Request timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Output format
        #[arg(short, long, default_value = "pretty")]
        output: OutputFormat,

        /// Custom User-Agent string
        #[arg(short = 'A', long)]
        user_agent: Option<String>,

        /// Disable SSL certificate verification (INSECURE!)
        #[arg(long)]
        insecure: bool,
    },

    /// Analyze a URL for security headers
    Analyze {
        /// URL to analyze
        url: String,

        /// Request timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Custom User-Agent string
        #[arg(short = 'A', long)]
        user_agent: Option<String>,
    },

    /// Check if a URL is accessible
    Check {
        /// URL to check
        url: String,

        /// Expected status code
        #[arg(short, long, default_value = "200")]
        expected: u16,

        /// Request timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Make a HEAD request
    Head {
        /// URL to request
        url: String,

        /// Custom headers (format: "Header: Value")
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Request timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
}

// ============================================================================
// HTTP CLIENT FUNCTIONS
// ============================================================================

/// Default User-Agent string for the client
const DEFAULT_USER_AGENT: &str = "RustSecurityClient/1.0";

/// Builds a configured HTTP client
///
/// # Arguments
/// * `timeout` - Request timeout in seconds
/// * `max_redirects` - Maximum number of redirects to follow
/// * `user_agent` - Optional custom User-Agent
/// * `insecure` - Whether to skip SSL verification
///
/// # Returns
/// * `Result<Client>` - Configured client or error
fn build_client(
    timeout: u64,
    max_redirects: usize,
    user_agent: Option<&str>,
    insecure: bool,
) -> Result<Client> {
    let mut builder = ClientBuilder::new()
        .timeout(Duration::from_secs(timeout))
        .redirect(Policy::limited(max_redirects))
        .user_agent(user_agent.unwrap_or(DEFAULT_USER_AGENT));

    // Only disable SSL verification if explicitly requested
    // This is a security risk and should be avoided in production
    if insecure {
        eprintln!(
            "{} SSL certificate verification is disabled!",
            "WARNING:".yellow().bold()
        );
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder
        .build()
        .context("Failed to build HTTP client")
}

/// Validates and parses a URL
///
/// # Arguments
/// * `url_str` - URL string to validate
///
/// # Returns
/// * `Result<Url>` - Parsed URL or error
fn validate_url(url_str: &str) -> Result<Url> {
    // Add scheme if missing
    let url_with_scheme = if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        format!("https://{}", url_str)
    } else {
        url_str.to_string()
    };

    Url::parse(&url_with_scheme)
        .map_err(|e| HttpError::InvalidUrl(format!("{}: {}", url_str, e)).into())
}

/// Parses custom headers from command line format
///
/// # Arguments
/// * `header_strings` - Vector of "Header: Value" strings
///
/// # Returns
/// * `Result<HeaderMap>` - Parsed headers or error
fn parse_headers(header_strings: &[String]) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();

    for header_str in header_strings {
        // Split on first ':'
        let parts: Vec<&str> = header_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid header format: '{}'. Use 'Header: Value'", header_str);
        }

        let name = parts[0].trim();
        let value = parts[1].trim();

        let header_name = HeaderName::try_from(name)
            .context(format!("Invalid header name: {}", name))?;
        let header_value = HeaderValue::from_str(value)
            .context(format!("Invalid header value for {}", name))?;

        headers.insert(header_name, header_value);
    }

    Ok(headers)
}

/// Makes a GET request
///
/// # Arguments
/// * `url` - URL to request
/// * `headers` - Custom headers
/// * `timeout` - Timeout in seconds
/// * `max_redirects` - Maximum redirects
/// * `user_agent` - Custom User-Agent
/// * `insecure` - Skip SSL verification
///
/// # Returns
/// * `Result<(Response, u128)>` - Response and response time in ms
fn make_get_request(
    url: &Url,
    headers: HeaderMap,
    timeout: u64,
    max_redirects: usize,
    user_agent: Option<&str>,
    insecure: bool,
) -> Result<(Response, u128)> {
    let client = build_client(timeout, max_redirects, user_agent, insecure)?;

    let start = std::time::Instant::now();

    let response = client
        .get(url.as_str())
        .headers(headers)
        .send()
        .context("Failed to send GET request")?;

    let elapsed = start.elapsed().as_millis();

    Ok((response, elapsed))
}

/// Makes a POST request
///
/// # Arguments
/// * `url` - URL to request
/// * `body` - Request body
/// * `headers` - Custom headers
/// * `is_json` - Whether body is JSON
/// * `timeout` - Timeout in seconds
/// * `user_agent` - Custom User-Agent
/// * `insecure` - Skip SSL verification
///
/// # Returns
/// * `Result<(Response, u128)>` - Response and response time in ms
fn make_post_request(
    url: &Url,
    body: String,
    mut headers: HeaderMap,
    is_json: bool,
    timeout: u64,
    user_agent: Option<&str>,
    insecure: bool,
) -> Result<(Response, u128)> {
    let client = build_client(timeout, 10, user_agent, insecure)?;

    // Set Content-Type if not already set
    if is_json && !headers.contains_key(CONTENT_TYPE) {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }

    let start = std::time::Instant::now();

    let response = client
        .post(url.as_str())
        .headers(headers)
        .body(body)
        .send()
        .context("Failed to send POST request")?;

    let elapsed = start.elapsed().as_millis();

    Ok((response, elapsed))
}

/// Makes a HEAD request
///
/// # Arguments
/// * `url` - URL to request
/// * `headers` - Custom headers
/// * `timeout` - Timeout in seconds
///
/// # Returns
/// * `Result<(Response, u128)>` - Response and response time in ms
fn make_head_request(
    url: &Url,
    headers: HeaderMap,
    timeout: u64,
) -> Result<(Response, u128)> {
    let client = build_client(timeout, 10, None, false)?;

    let start = std::time::Instant::now();

    let response = client
        .head(url.as_str())
        .headers(headers)
        .send()
        .context("Failed to send HEAD request")?;

    let elapsed = start.elapsed().as_millis();

    Ok((response, elapsed))
}

// ============================================================================
// RESPONSE ANALYSIS FUNCTIONS
// ============================================================================

/// Extracts response information into a structured format
///
/// # Arguments
/// * `response` - The HTTP response
/// * `elapsed_ms` - Response time in milliseconds
///
/// # Returns
/// * `Result<ResponseInfo>` - Structured response info
fn extract_response_info(response: Response, elapsed_ms: u128) -> Result<ResponseInfo> {
    let status_code = response.status().as_u16();
    let status_reason = response
        .status()
        .canonical_reason()
        .unwrap_or("Unknown")
        .to_string();

    let final_url = response.url().to_string();

    // Extract headers
    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let content_length = response.content_length();
    let content_type = headers.get("content-type").cloned();

    // Get body
    let body = response.text().unwrap_or_default();

    Ok(ResponseInfo {
        status_code,
        status_reason,
        headers,
        body,
        content_length,
        content_type,
        response_time_ms: elapsed_ms,
        final_url,
        redirect_count: 0, // Would need to track this manually
    })
}

/// Analyzes security headers in the response
///
/// # Arguments
/// * `headers` - Response headers
///
/// # Returns
/// * `Vec<SecurityHeaderAnalysis>` - Security header analysis results
fn analyze_security_headers(headers: &HashMap<String, String>) -> Vec<SecurityHeaderAnalysis> {
    let security_headers = vec![
        (
            "strict-transport-security",
            "HSTS header enforces HTTPS connections",
            8,
        ),
        (
            "content-security-policy",
            "CSP prevents XSS and injection attacks",
            9,
        ),
        (
            "x-frame-options",
            "Prevents clickjacking attacks",
            7,
        ),
        (
            "x-content-type-options",
            "Prevents MIME type sniffing",
            6,
        ),
        (
            "x-xss-protection",
            "Enables XSS filter in older browsers",
            5,
        ),
        (
            "referrer-policy",
            "Controls referrer information leakage",
            5,
        ),
        (
            "permissions-policy",
            "Controls browser feature access",
            6,
        ),
        (
            "cache-control",
            "Controls caching of sensitive data",
            4,
        ),
        (
            "x-permitted-cross-domain-policies",
            "Controls Flash/PDF cross-domain access",
            3,
        ),
    ];

    security_headers
        .into_iter()
        .map(|(header, recommendation, severity)| {
            let header_lower = header.to_lowercase();
            let value = headers.get(&header_lower).or_else(|| {
                // Try case-insensitive lookup
                headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == header_lower)
                    .map(|(_, v)| v)
            });

            SecurityHeaderAnalysis {
                header: header.to_string(),
                present: value.is_some(),
                value: value.cloned(),
                recommendation: recommendation.to_string(),
                severity: if value.is_some() { 0 } else { severity },
            }
        })
        .collect()
}

/// Checks for potentially dangerous headers in response
///
/// # Arguments
/// * `headers` - Response headers
///
/// # Returns
/// * `Vec<(String, String)>` - Warning messages
fn check_dangerous_headers(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut warnings = Vec::new();

    // Check for server information disclosure
    if let Some(server) = headers.get("server") {
        if server.contains('/') {
            warnings.push((
                "Server".to_string(),
                format!("Server header discloses version: {}", server),
            ));
        }
    }

    // Check for X-Powered-By disclosure
    if let Some(powered_by) = headers.get("x-powered-by") {
        warnings.push((
            "X-Powered-By".to_string(),
            format!("Technology stack disclosed: {}", powered_by),
        ));
    }

    // Check for ASP.NET version
    if let Some(aspnet) = headers.get("x-aspnet-version") {
        warnings.push((
            "X-AspNet-Version".to_string(),
            format!("ASP.NET version disclosed: {}", aspnet),
        ));
    }

    // Check for debug mode indicators
    if headers.contains_key("x-debug-token") || headers.contains_key("x-debug-token-link") {
        warnings.push((
            "Debug".to_string(),
            "Debug headers present - application may be in debug mode".to_string(),
        ));
    }

    warnings
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

/// Displays response in pretty format
fn display_response_pretty(info: &ResponseInfo, verbose: bool) {
    // Status line
    let status_color = match info.status_code {
        200..=299 => info.status_code.to_string().green(),
        300..=399 => info.status_code.to_string().yellow(),
        400..=499 => info.status_code.to_string().red(),
        500..=599 => info.status_code.to_string().red().bold(),
        _ => info.status_code.to_string().normal(),
    };

    println!("\n{}", "Response".bold().underline());
    println!(
        "Status: {} {}",
        status_color,
        info.status_reason
    );
    println!("URL: {}", info.final_url.cyan());
    println!("Time: {} ms", info.response_time_ms);

    if let Some(length) = info.content_length {
        println!("Content-Length: {} bytes", length);
    }
    if let Some(ref content_type) = info.content_type {
        println!("Content-Type: {}", content_type);
    }

    // Headers
    if verbose {
        println!("\n{}", "Headers:".yellow());
        let mut sorted_headers: Vec<_> = info.headers.iter().collect();
        sorted_headers.sort_by_key(|(k, _)| *k);
        for (key, value) in sorted_headers {
            println!("  {}: {}", key.cyan(), value);
        }
    }

    // Body (truncated if large)
    println!("\n{}", "Body:".yellow());
    if info.body.len() > 2000 {
        println!("{}", &info.body[..2000]);
        println!("\n... (truncated, {} total bytes)", info.body.len());
    } else if info.body.is_empty() {
        println!("(empty)");
    } else {
        println!("{}", info.body);
    }
}

/// Displays security header analysis
fn display_security_analysis(analysis: &[SecurityHeaderAnalysis], warnings: &[(String, String)]) {
    println!("\n{}", "Security Header Analysis".bold().underline());

    let mut total_issues = 0;

    for item in analysis {
        let status = if item.present {
            "PRESENT".green()
        } else {
            total_issues += 1;
            "MISSING".red()
        };

        println!("\n{}: {}", item.header.cyan().bold(), status);
        if let Some(ref value) = item.value {
            // Truncate long values
            let display_value = if value.len() > 80 {
                format!("{}...", &value[..80])
            } else {
                value.clone()
            };
            println!("  Value: {}", display_value.dimmed());
        }
        if item.severity > 0 {
            println!(
                "  {} {} (severity: {})",
                "Recommendation:".yellow(),
                item.recommendation,
                item.severity
            );
        }
    }

    // Display warnings
    if !warnings.is_empty() {
        println!("\n{}", "Security Warnings:".red().bold());
        for (header, message) in warnings {
            println!("  {} {}: {}", "!".red(), header.yellow(), message);
        }
    }

    // Summary
    println!("\n{}", "Summary:".bold());
    println!(
        "  Missing security headers: {}",
        if total_issues > 0 {
            total_issues.to_string().red()
        } else {
            "0".to_string().green()
        }
    );
    println!("  Information disclosure warnings: {}", warnings.len());
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Get {
            url,
            headers,
            timeout,
            redirects,
            output,
            save,
            user_agent,
            insecure,
        } => {
            let parsed_url = validate_url(&url)?;
            let custom_headers = parse_headers(&headers)?;

            if cli.verbose {
                println!("{} GET {}", "Request:".blue(), parsed_url);
            }

            let (response, elapsed) = make_get_request(
                &parsed_url,
                custom_headers,
                timeout,
                redirects,
                user_agent.as_deref(),
                insecure,
            )?;

            let info = extract_response_info(response, elapsed)?;

            // Save to file if requested
            if let Some(path) = save {
                fs::write(&path, &info.body)
                    .with_context(|| format!("Failed to save to {:?}", path))?;
                println!("{} Saved to {:?}", "Success:".green(), path);
            }

            // Display based on output format
            match output {
                OutputFormat::Pretty => display_response_pretty(&info, cli.verbose),
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&info)?);
                }
                OutputFormat::Headers => {
                    for (key, value) in &info.headers {
                        println!("{}: {}", key, value);
                    }
                }
                OutputFormat::Body => {
                    println!("{}", info.body);
                }
            }
        }

        Commands::Post {
            url,
            data,
            json,
            file,
            headers,
            timeout,
            output,
            user_agent,
            insecure,
        } => {
            let parsed_url = validate_url(&url)?;
            let custom_headers = parse_headers(&headers)?;

            // Get body from data, file, or empty
            let body = if let Some(file_path) = file {
                fs::read_to_string(&file_path)
                    .with_context(|| format!("Failed to read {:?}", file_path))?
            } else {
                data.unwrap_or_default()
            };

            // Validate JSON if specified
            if json && !body.is_empty() {
                let _: serde_json::Value = serde_json::from_str(&body)
                    .context("Invalid JSON in request body")?;
            }

            if cli.verbose {
                println!("{} POST {}", "Request:".blue(), parsed_url);
                if !body.is_empty() {
                    println!("Body: {} bytes", body.len());
                }
            }

            let (response, elapsed) = make_post_request(
                &parsed_url,
                body,
                custom_headers,
                json,
                timeout,
                user_agent.as_deref(),
                insecure,
            )?;

            let info = extract_response_info(response, elapsed)?;

            match output {
                OutputFormat::Pretty => display_response_pretty(&info, cli.verbose),
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&info)?);
                }
                OutputFormat::Headers => {
                    for (key, value) in &info.headers {
                        println!("{}: {}", key, value);
                    }
                }
                OutputFormat::Body => {
                    println!("{}", info.body);
                }
            }
        }

        Commands::Analyze { url, timeout, user_agent } => {
            let parsed_url = validate_url(&url)?;

            println!("{} Analyzing {}", "Info:".blue(), parsed_url);

            let (response, _) = make_get_request(
                &parsed_url,
                HeaderMap::new(),
                timeout,
                10,
                user_agent.as_deref(),
                false,
            )?;

            let info = extract_response_info(response, 0)?;
            let analysis = analyze_security_headers(&info.headers);
            let warnings = check_dangerous_headers(&info.headers);

            display_security_analysis(&analysis, &warnings);
        }

        Commands::Check { url, expected, timeout } => {
            let parsed_url = validate_url(&url)?;

            let start = std::time::Instant::now();
            let client = build_client(timeout, 10, None, false)?;

            let result = client.get(parsed_url.as_str()).send();
            let elapsed = start.elapsed().as_millis();

            match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    if status == expected {
                        println!(
                            "{} {} returned {} in {} ms",
                            "OK:".green(),
                            url,
                            status.to_string().green(),
                            elapsed
                        );
                    } else {
                        println!(
                            "{} {} returned {} (expected {}) in {} ms",
                            "FAIL:".red(),
                            url,
                            status.to_string().yellow(),
                            expected,
                            elapsed
                        );
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    println!("{} {} is not accessible: {}", "FAIL:".red(), url, e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Head { url, headers, timeout } => {
            let parsed_url = validate_url(&url)?;
            let custom_headers = parse_headers(&headers)?;

            let (response, elapsed) = make_head_request(&parsed_url, custom_headers, timeout)?;

            println!("\n{}", "HEAD Response".bold().underline());
            println!("Status: {} {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("")
            );
            println!("Time: {} ms\n", elapsed);

            println!("{}", "Headers:".yellow());
            for (key, value) in response.headers() {
                println!("  {}: {}", key.as_str().cyan(), value.to_str().unwrap_or(""));
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
    fn test_validate_url_with_scheme() {
        let url = validate_url("https://example.com");
        assert!(url.is_ok());
        assert_eq!(url.unwrap().scheme(), "https");
    }

    #[test]
    fn test_validate_url_without_scheme() {
        let url = validate_url("example.com");
        assert!(url.is_ok());
        // Should default to https
        assert_eq!(url.unwrap().scheme(), "https");
    }

    #[test]
    fn test_validate_url_with_path() {
        let url = validate_url("https://example.com/path/to/resource");
        assert!(url.is_ok());
        assert_eq!(url.unwrap().path(), "/path/to/resource");
    }

    #[test]
    fn test_parse_headers() {
        let headers = vec![
            "Content-Type: application/json".to_string(),
            "Authorization: Bearer token123".to_string(),
        ];

        let parsed = parse_headers(&headers);
        assert!(parsed.is_ok());

        let map = parsed.unwrap();
        assert!(map.contains_key("content-type"));
        assert!(map.contains_key("authorization"));
    }

    #[test]
    fn test_parse_headers_invalid() {
        let headers = vec!["InvalidHeader".to_string()];
        let parsed = parse_headers(&headers);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_analyze_security_headers_all_missing() {
        let headers = HashMap::new();
        let analysis = analyze_security_headers(&headers);

        // All headers should be marked as missing
        assert!(analysis.iter().all(|a| !a.present));
        assert!(analysis.iter().all(|a| a.severity > 0));
    }

    #[test]
    fn test_analyze_security_headers_some_present() {
        let mut headers = HashMap::new();
        headers.insert("strict-transport-security".to_string(), "max-age=31536000".to_string());
        headers.insert("x-frame-options".to_string(), "DENY".to_string());

        let analysis = analyze_security_headers(&headers);

        let hsts = analysis.iter().find(|a| a.header == "strict-transport-security");
        assert!(hsts.is_some());
        assert!(hsts.unwrap().present);

        let xfo = analysis.iter().find(|a| a.header == "x-frame-options");
        assert!(xfo.is_some());
        assert!(xfo.unwrap().present);
    }

    #[test]
    fn test_check_dangerous_headers() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string());
        headers.insert("x-powered-by".to_string(), "PHP/7.4.3".to_string());

        let warnings = check_dangerous_headers(&headers);

        assert_eq!(warnings.len(), 2);
        assert!(warnings.iter().any(|(h, _)| h == "Server"));
        assert!(warnings.iter().any(|(h, _)| h == "X-Powered-By"));
    }

    #[test]
    fn test_check_dangerous_headers_safe() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        headers.insert("server".to_string(), "nginx".to_string()); // No version

        let warnings = check_dangerous_headers(&headers);

        // Server without version shouldn't trigger warning
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_build_client() {
        let client = build_client(30, 10, None, false);
        assert!(client.is_ok());
    }

    #[test]
    fn test_response_info_serialization() {
        let info = ResponseInfo {
            status_code: 200,
            status_reason: "OK".to_string(),
            headers: HashMap::new(),
            body: "test".to_string(),
            content_length: Some(4),
            content_type: Some("text/plain".to_string()),
            response_time_ms: 100,
            final_url: "https://example.com".to_string(),
            redirect_count: 0,
        };

        let json = serde_json::to_string(&info);
        assert!(json.is_ok());
    }
}
