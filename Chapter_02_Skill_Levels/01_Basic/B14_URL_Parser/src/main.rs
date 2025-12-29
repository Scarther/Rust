//! # URL Parser - Web Security URL Analysis Tool
//!
//! Parses and analyzes URLs for security applications.
//! Use cases include:
//! - Analyzing phishing URLs for suspicious patterns
//! - Extracting domains for threat intelligence
//! - Decoding obfuscated URLs
//! - Validating URLs in security configurations
//!
//! ## Rust Concepts Covered:
//! - URL parsing with the url crate
//! - String manipulation and encoding
//! - Option and Result handling
//! - Struct with optional fields
//! - Trait implementations
//! - Iterator methods
//! - Error handling patterns

use clap::{Parser, Subcommand};
use colored::*;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// URL Parser - Web security URL analysis tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse and analyze a URL
    Parse {
        /// URL to parse
        url: String,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Extract specific component from URL
    Extract {
        /// URL to parse
        url: String,

        /// Component to extract (scheme, host, port, path, query, fragment)
        #[arg(short, long)]
        component: String,
    },

    /// Decode URL-encoded string
    Decode {
        /// URL-encoded string
        input: String,
    },

    /// Encode string for URL
    Encode {
        /// String to encode
        input: String,
    },

    /// Parse query string parameters
    Query {
        /// URL or query string
        input: String,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Build a URL from components
    Build {
        /// Scheme (http, https, ftp)
        #[arg(short, long, default_value = "https")]
        scheme: String,

        /// Host/domain
        #[arg(short = 'H', long)]
        host: String,

        /// Port (optional)
        #[arg(short, long)]
        port: Option<u16>,

        /// Path (optional)
        #[arg(short = 'P', long)]
        path: Option<String>,

        /// Query string (optional)
        #[arg(short, long)]
        query: Option<String>,

        /// Fragment (optional)
        #[arg(short, long)]
        fragment: Option<String>,
    },

    /// Analyze URL for security issues
    Security {
        /// URL to analyze
        url: String,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Compare two URLs
    Compare {
        /// First URL
        url1: String,

        /// Second URL
        url2: String,
    },

    /// Normalize a URL
    Normalize {
        /// URL to normalize
        url: String,
    },
}

/// Result of URL parsing
#[derive(Debug, Serialize, Deserialize)]
struct UrlAnalysis {
    /// Original URL
    original: String,
    /// Whether the URL is valid
    valid: bool,
    /// URL scheme (http, https, etc.)
    scheme: Option<String>,
    /// Username if present
    username: Option<String>,
    /// Password if present (security risk!)
    password: Option<String>,
    /// Host/domain
    host: Option<String>,
    /// Port number
    port: Option<u16>,
    /// Effective port (including defaults)
    effective_port: Option<u16>,
    /// Path
    path: Option<String>,
    /// Query string
    query: Option<String>,
    /// Fragment/anchor
    fragment: Option<String>,
    /// Parsed query parameters
    query_params: HashMap<String, String>,
    /// Domain parts
    domain_parts: Option<DomainParts>,
    /// Whether URL uses default port
    uses_default_port: bool,
    /// URL length
    length: usize,
    /// Error message if invalid
    error: Option<String>,
}

/// Domain name components
#[derive(Debug, Serialize, Deserialize)]
struct DomainParts {
    /// Full domain
    full: String,
    /// Top-level domain (com, org, etc.)
    tld: Option<String>,
    /// Registered domain (example.com)
    registered_domain: Option<String>,
    /// Subdomain if present
    subdomain: Option<String>,
    /// Number of subdomains
    subdomain_count: usize,
    /// Whether it's an IP address
    is_ip: bool,
}

/// Security analysis result
#[derive(Debug, Serialize, Deserialize)]
struct SecurityAnalysis {
    /// Original URL
    url: String,
    /// Risk level (low, medium, high)
    risk_level: String,
    /// Security issues found
    issues: Vec<SecurityIssue>,
    /// Security recommendations
    recommendations: Vec<String>,
}

/// A security issue found in the URL
#[derive(Debug, Serialize, Deserialize)]
struct SecurityIssue {
    /// Issue category
    category: String,
    /// Severity (info, warning, critical)
    severity: String,
    /// Description
    description: String,
}

/// Custom error type for URL operations
#[derive(Debug)]
enum UrlError {
    ParseError(String),
    InvalidComponent(String),
    BuildError(String),
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            UrlError::InvalidComponent(msg) => write!(f, "Invalid component: {}", msg),
            UrlError::BuildError(msg) => write!(f, "Build error: {}", msg),
        }
    }
}

impl std::error::Error for UrlError {}

/// Parses and analyzes a URL
fn analyze_url(input: &str) -> UrlAnalysis {
    // Try to parse the URL
    let parsed = match Url::parse(input) {
        Ok(url) => url,
        Err(e) => {
            // Try adding https:// if no scheme
            let with_scheme = format!("https://{}", input);
            match Url::parse(&with_scheme) {
                Ok(url) => url,
                Err(_) => {
                    return UrlAnalysis {
                        original: input.to_string(),
                        valid: false,
                        scheme: None,
                        username: None,
                        password: None,
                        host: None,
                        port: None,
                        effective_port: None,
                        path: None,
                        query: None,
                        fragment: None,
                        query_params: HashMap::new(),
                        domain_parts: None,
                        uses_default_port: false,
                        length: input.len(),
                        error: Some(e.to_string()),
                    };
                }
            }
        }
    };

    // Parse query parameters
    let query_params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Determine effective port
    let default_port = match parsed.scheme() {
        "http" => Some(80),
        "https" => Some(443),
        "ftp" => Some(21),
        "ssh" => Some(22),
        _ => None,
    };
    let effective_port = parsed.port().or(default_port);
    let uses_default_port = parsed.port().is_none();

    // Parse domain parts
    let domain_parts = parsed.host_str().map(|host| parse_domain(host));

    UrlAnalysis {
        original: input.to_string(),
        valid: true,
        scheme: Some(parsed.scheme().to_string()),
        username: if parsed.username().is_empty() {
            None
        } else {
            Some(parsed.username().to_string())
        },
        password: parsed.password().map(|s| s.to_string()),
        host: parsed.host_str().map(|s| s.to_string()),
        port: parsed.port(),
        effective_port,
        path: Some(parsed.path().to_string()),
        query: parsed.query().map(|s| s.to_string()),
        fragment: parsed.fragment().map(|s| s.to_string()),
        query_params,
        domain_parts,
        uses_default_port,
        length: input.len(),
        error: None,
    }
}

/// Parses domain name into components
fn parse_domain(domain: &str) -> DomainParts {
    // Check if it's an IP address
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return DomainParts {
            full: domain.to_string(),
            tld: None,
            registered_domain: None,
            subdomain: None,
            subdomain_count: 0,
            is_ip: true,
        };
    }

    let parts: Vec<&str> = domain.split('.').collect();

    // Handle different domain structures
    let (tld, registered, subdomain, count) = if parts.len() == 1 {
        // Single part (localhost, etc.)
        (None, Some(domain.to_string()), None, 0)
    } else if parts.len() == 2 {
        // example.com
        (
            Some(parts[1].to_string()),
            Some(domain.to_string()),
            None,
            0,
        )
    } else {
        // Check for multi-part TLDs (co.uk, com.au, etc.)
        let known_multi_tlds = ["co.uk", "com.au", "co.nz", "org.uk", "gov.uk", "ac.uk"];
        let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

        if known_multi_tlds.contains(&last_two.as_str()) {
            // Multi-part TLD
            let tld = Some(last_two);
            let registered = if parts.len() >= 3 {
                Some(format!("{}.{}.{}", parts[parts.len() - 3], parts[parts.len() - 2], parts[parts.len() - 1]))
            } else {
                Some(domain.to_string())
            };
            let subdomain = if parts.len() > 3 {
                Some(parts[..parts.len() - 3].join("."))
            } else {
                None
            };
            let count = parts.len().saturating_sub(3);
            (tld, registered, subdomain, count)
        } else {
            // Single TLD
            let tld = Some(parts.last().unwrap().to_string());
            let registered = Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]));
            let subdomain = if parts.len() > 2 {
                Some(parts[..parts.len() - 2].join("."))
            } else {
                None
            };
            let count = parts.len().saturating_sub(2);
            (tld, registered, subdomain, count)
        }
    };

    DomainParts {
        full: domain.to_string(),
        tld,
        registered_domain: registered,
        subdomain,
        subdomain_count: count,
        is_ip: false,
    }
}

/// Performs security analysis on a URL
fn analyze_security(input: &str) -> Result<SecurityAnalysis, UrlError> {
    let parsed = Url::parse(input)
        .or_else(|_| Url::parse(&format!("https://{}", input)))
        .map_err(|e| UrlError::ParseError(e.to_string()))?;

    let mut issues = Vec::new();
    let mut recommendations = Vec::new();

    // Check for password in URL
    if parsed.password().is_some() {
        issues.push(SecurityIssue {
            category: "Credentials".to_string(),
            severity: "critical".to_string(),
            description: "Password embedded in URL - visible in logs and history".to_string(),
        });
        recommendations.push("Remove credentials from URL and use proper authentication".to_string());
    }

    // Check for username in URL
    if !parsed.username().is_empty() {
        issues.push(SecurityIssue {
            category: "Credentials".to_string(),
            severity: "warning".to_string(),
            description: "Username embedded in URL".to_string(),
        });
    }

    // Check for HTTP (not HTTPS)
    if parsed.scheme() == "http" {
        issues.push(SecurityIssue {
            category: "Encryption".to_string(),
            severity: "warning".to_string(),
            description: "Using HTTP instead of HTTPS - data transmitted in plain text".to_string(),
        });
        recommendations.push("Use HTTPS for secure communication".to_string());
    }

    // Check for suspicious TLDs
    let suspicious_tlds = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site"];
    if let Some(host) = parsed.host_str() {
        let parts: Vec<&str> = host.split('.').collect();
        if let Some(tld) = parts.last() {
            if suspicious_tlds.contains(tld) {
                issues.push(SecurityIssue {
                    category: "Domain".to_string(),
                    severity: "info".to_string(),
                    description: format!("Uses potentially suspicious TLD: .{}", tld),
                });
            }
        }

        // Check for IP address instead of domain
        if host.parse::<std::net::IpAddr>().is_ok() {
            issues.push(SecurityIssue {
                category: "Domain".to_string(),
                severity: "warning".to_string(),
                description: "Uses IP address instead of domain name".to_string(),
            });
        }

        // Check for excessive subdomains (potential phishing)
        let subdomain_count = parts.len().saturating_sub(2);
        if subdomain_count > 3 {
            issues.push(SecurityIssue {
                category: "Domain".to_string(),
                severity: "warning".to_string(),
                description: format!("Excessive subdomains ({}) - potential phishing indicator", subdomain_count),
            });
        }

        // Check for numbers in domain (homograph attacks)
        if parts.iter().any(|p| p.chars().any(|c| c.is_numeric()) && p.chars().any(|c| c.is_alphabetic())) {
            issues.push(SecurityIssue {
                category: "Domain".to_string(),
                severity: "info".to_string(),
                description: "Domain contains mixed letters and numbers - potential homograph".to_string(),
            });
        }

        // Check for very long domain
        if host.len() > 50 {
            issues.push(SecurityIssue {
                category: "Domain".to_string(),
                severity: "info".to_string(),
                description: format!("Unusually long domain name ({} chars)", host.len()),
            });
        }
    }

    // Check for suspicious query parameters
    let sensitive_params = ["password", "pwd", "pass", "token", "key", "secret", "api_key", "apikey", "auth"];
    for (key, _) in parsed.query_pairs() {
        let lower_key = key.to_lowercase();
        if sensitive_params.iter().any(|p| lower_key.contains(p)) {
            issues.push(SecurityIssue {
                category: "Query Parameters".to_string(),
                severity: "critical".to_string(),
                description: format!("Sensitive parameter in URL: {}", key),
            });
            recommendations.push("Never pass sensitive data in URL query parameters".to_string());
        }
    }

    // Check URL length (potential buffer overflow)
    if input.len() > 2000 {
        issues.push(SecurityIssue {
            category: "Length".to_string(),
            severity: "info".to_string(),
            description: format!("Very long URL ({} chars) - may cause issues with some systems", input.len()),
        });
    }

    // Check for non-standard port
    if let Some(port) = parsed.port() {
        let standard_ports = [80, 443, 21, 22, 8080, 8443];
        if !standard_ports.contains(&port) {
            issues.push(SecurityIssue {
                category: "Port".to_string(),
                severity: "info".to_string(),
                description: format!("Non-standard port: {}", port),
            });
        }
    }

    // Check for encoded characters that might bypass filters
    if input.contains("%00") || input.contains("%0a") || input.contains("%0d") {
        issues.push(SecurityIssue {
            category: "Encoding".to_string(),
            severity: "warning".to_string(),
            description: "Contains null bytes or newline characters - potential injection".to_string(),
        });
    }

    // Determine overall risk level
    let risk_level = if issues.iter().any(|i| i.severity == "critical") {
        "high"
    } else if issues.iter().any(|i| i.severity == "warning") {
        "medium"
    } else {
        "low"
    };

    Ok(SecurityAnalysis {
        url: input.to_string(),
        risk_level: risk_level.to_string(),
        issues,
        recommendations,
    })
}

/// Normalizes a URL
fn normalize_url(input: &str) -> Result<String, UrlError> {
    let mut url = Url::parse(input)
        .or_else(|_| Url::parse(&format!("https://{}", input)))
        .map_err(|e| UrlError::ParseError(e.to_string()))?;

    // Convert scheme to lowercase
    let scheme = url.scheme().to_lowercase();
    url.set_scheme(&scheme).ok();

    // Convert host to lowercase
    if let Some(host) = url.host_str() {
        let _ = url.set_host(Some(&host.to_lowercase()));
    }

    // Remove default ports
    match (url.scheme(), url.port()) {
        ("http", Some(80)) | ("https", Some(443)) | ("ftp", Some(21)) => {
            let _ = url.set_port(None);
        }
        _ => {}
    }

    // Remove trailing slash for root path
    let path = url.path().to_string();
    if path == "/" {
        url.set_path("");
    }

    // Sort query parameters
    let mut params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    params.sort_by(|a, b| a.0.cmp(&b.0));

    if !params.is_empty() {
        let query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        url.set_query(Some(&query));
    }

    Ok(url.to_string())
}

/// Prints URL analysis result
fn print_url_analysis(analysis: &UrlAnalysis) {
    if !analysis.valid {
        println!("{}: {}", "Invalid URL".red().bold(), analysis.error.as_ref().unwrap());
        return;
    }

    println!("{}", "URL Analysis".bold().green());
    println!("{}", "=".repeat(60).dimmed());
    println!("  Original:       {}", analysis.original.cyan());
    println!("  Length:         {} characters", analysis.length);
    println!();
    println!("{}", "Components:".yellow());
    println!("  Scheme:         {}", analysis.scheme.as_ref().unwrap());
    if let Some(ref user) = analysis.username {
        println!("  Username:       {}", user.red());
    }
    if analysis.password.is_some() {
        println!("  Password:       {}", "[REDACTED]".red().bold());
    }
    println!("  Host:           {}", analysis.host.as_ref().unwrap_or(&"N/A".to_string()));
    if let Some(port) = analysis.port {
        println!("  Port:           {} (explicit)", port);
    } else {
        println!("  Port:           {} (default)", analysis.effective_port.unwrap_or(0));
    }
    println!("  Path:           {}", analysis.path.as_ref().unwrap_or(&"/".to_string()));
    if let Some(ref query) = analysis.query {
        println!("  Query:          {}", query);
    }
    if let Some(ref fragment) = analysis.fragment {
        println!("  Fragment:       #{}", fragment);
    }

    if let Some(ref domain) = analysis.domain_parts {
        println!();
        println!("{}", "Domain Analysis:".yellow());
        if domain.is_ip {
            println!("  Type:           IP Address");
        } else {
            if let Some(ref tld) = domain.tld {
                println!("  TLD:            .{}", tld);
            }
            if let Some(ref registered) = domain.registered_domain {
                println!("  Registered:     {}", registered);
            }
            if let Some(ref subdomain) = domain.subdomain {
                println!("  Subdomain:      {}", subdomain);
            }
            println!("  Subdomain Count: {}", domain.subdomain_count);
        }
    }

    if !analysis.query_params.is_empty() {
        println!();
        println!("{}", "Query Parameters:".yellow());
        for (key, value) in &analysis.query_params {
            println!("  {}={}", key.cyan(), value);
        }
    }
}

/// Prints security analysis result
fn print_security_analysis(analysis: &SecurityAnalysis) {
    println!("{}", "Security Analysis".bold().green());
    println!("{}", "=".repeat(60).dimmed());
    println!("  URL: {}", analysis.url.cyan());

    let risk_colored = match analysis.risk_level.as_str() {
        "high" => analysis.risk_level.red().bold(),
        "medium" => analysis.risk_level.yellow().bold(),
        _ => analysis.risk_level.green().bold(),
    };
    println!("  Risk Level: {}", risk_colored);
    println!();

    if analysis.issues.is_empty() {
        println!("  {}", "No security issues found".green());
    } else {
        println!("{}", "Issues Found:".yellow());
        for issue in &analysis.issues {
            let severity_colored = match issue.severity.as_str() {
                "critical" => format!("[{}]", issue.severity).red().bold(),
                "warning" => format!("[{}]", issue.severity).yellow(),
                _ => format!("[{}]", issue.severity).dimmed(),
            };
            println!("  {} {}: {}", severity_colored, issue.category.cyan(), issue.description);
        }
    }

    if !analysis.recommendations.is_empty() {
        println!();
        println!("{}", "Recommendations:".yellow());
        for rec in &analysis.recommendations {
            println!("  - {}", rec);
        }
    }
}

fn main() {
    let args = Args::parse();

    let result = match args.command {
        Commands::Parse { url, json } => handle_parse(&url, json),
        Commands::Extract { url, component } => handle_extract(&url, &component),
        Commands::Decode { input } => handle_decode(&input),
        Commands::Encode { input } => handle_encode(&input),
        Commands::Query { input, json } => handle_query(&input, json),
        Commands::Build { scheme, host, port, path, query, fragment } => {
            handle_build(&scheme, &host, port, path.as_deref(), query.as_deref(), fragment.as_deref())
        }
        Commands::Security { url, json } => handle_security(&url, json),
        Commands::Compare { url1, url2 } => handle_compare(&url1, &url2),
        Commands::Normalize { url } => handle_normalize(&url),
    };

    if let Err(e) = result {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

fn handle_parse(url: &str, json: bool) -> Result<(), UrlError> {
    let analysis = analyze_url(url);

    if json {
        println!("{}", serde_json::to_string_pretty(&analysis).unwrap());
    } else {
        print_url_analysis(&analysis);
    }

    Ok(())
}

fn handle_extract(url: &str, component: &str) -> Result<(), UrlError> {
    let analysis = analyze_url(url);

    if !analysis.valid {
        return Err(UrlError::ParseError(analysis.error.unwrap_or_default()));
    }

    let value = match component.to_lowercase().as_str() {
        "scheme" => analysis.scheme,
        "host" | "domain" => analysis.host,
        "port" => analysis.effective_port.map(|p| p.to_string()),
        "path" => analysis.path,
        "query" => analysis.query,
        "fragment" => analysis.fragment,
        "username" => analysis.username,
        "password" => analysis.password,
        _ => return Err(UrlError::InvalidComponent(format!("Unknown component: {}", component))),
    };

    match value {
        Some(v) => println!("{}", v),
        None => println!("{}", "[not present]".dimmed()),
    }

    Ok(())
}

fn handle_decode(input: &str) -> Result<(), UrlError> {
    let decoded = percent_decode_str(input)
        .decode_utf8()
        .map_err(|e| UrlError::ParseError(e.to_string()))?;

    println!("{}", "URL Decode".bold().green());
    println!("  Input:   {}", input.cyan());
    println!("  Decoded: {}", decoded.green());

    Ok(())
}

fn handle_encode(input: &str) -> Result<(), UrlError> {
    let encoded = utf8_percent_encode(input, NON_ALPHANUMERIC).to_string();

    println!("{}", "URL Encode".bold().green());
    println!("  Input:   {}", input.cyan());
    println!("  Encoded: {}", encoded.green());

    Ok(())
}

fn handle_query(input: &str, json: bool) -> Result<(), UrlError> {
    // Try to parse as URL first, then as raw query string
    let query_str = if input.contains("://") {
        Url::parse(input)
            .map_err(|e| UrlError::ParseError(e.to_string()))?
            .query()
            .unwrap_or("")
            .to_string()
    } else if input.starts_with('?') {
        input[1..].to_string()
    } else {
        input.to_string()
    };

    // Parse query parameters
    let params: HashMap<String, String> = url::form_urlencoded::parse(query_str.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&params).unwrap());
    } else {
        println!("{}", "Query Parameters".bold().green());
        println!("{}", "=".repeat(40).dimmed());
        for (key, value) in &params {
            println!("  {} = {}", key.cyan(), value);
        }
    }

    Ok(())
}

fn handle_build(
    scheme: &str,
    host: &str,
    port: Option<u16>,
    path: Option<&str>,
    query: Option<&str>,
    fragment: Option<&str>,
) -> Result<(), UrlError> {
    let mut url = Url::parse(&format!("{}://{}", scheme, host))
        .map_err(|e| UrlError::BuildError(e.to_string()))?;

    if let Some(p) = port {
        url.set_port(Some(p)).map_err(|_| UrlError::BuildError("Invalid port".to_string()))?;
    }

    if let Some(p) = path {
        url.set_path(p);
    }

    if let Some(q) = query {
        url.set_query(Some(q));
    }

    if let Some(f) = fragment {
        url.set_fragment(Some(f));
    }

    println!("{}", url);

    Ok(())
}

fn handle_security(url: &str, json: bool) -> Result<(), UrlError> {
    let analysis = analyze_security(url)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&analysis).unwrap());
    } else {
        print_security_analysis(&analysis);
    }

    Ok(())
}

fn handle_compare(url1: &str, url2: &str) -> Result<(), UrlError> {
    let a1 = analyze_url(url1);
    let a2 = analyze_url(url2);

    println!("{}", "URL Comparison".bold().green());
    println!("{}", "=".repeat(70).dimmed());

    println!("{:<15} {:<27} {:<27}", "", "URL 1".cyan(), "URL 2".cyan());
    println!("{:<15} {:<27} {:<27}", "Scheme:", a1.scheme.as_deref().unwrap_or("-"), a2.scheme.as_deref().unwrap_or("-"));
    println!("{:<15} {:<27} {:<27}", "Host:", a1.host.as_deref().unwrap_or("-"), a2.host.as_deref().unwrap_or("-"));
    println!("{:<15} {:<27} {:<27}", "Port:", a1.effective_port.map(|p| p.to_string()).unwrap_or("-".to_string()), a2.effective_port.map(|p| p.to_string()).unwrap_or("-".to_string()));
    println!("{:<15} {:<27} {:<27}", "Path:", a1.path.as_deref().unwrap_or("-"), a2.path.as_deref().unwrap_or("-"));

    // Check if URLs are equivalent
    let n1 = normalize_url(url1)?;
    let n2 = normalize_url(url2)?;

    println!();
    if n1 == n2 {
        println!("{}", "URLs are EQUIVALENT (after normalization)".green().bold());
    } else {
        println!("{}", "URLs are DIFFERENT".yellow());
    }

    Ok(())
}

fn handle_normalize(url: &str) -> Result<(), UrlError> {
    let normalized = normalize_url(url)?;

    println!("{}", "URL Normalization".bold().green());
    println!("  Original:   {}", url.cyan());
    println!("  Normalized: {}", normalized.green());

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_url() {
        let analysis = analyze_url("https://example.com:8080/path?query=value#fragment");
        assert!(analysis.valid);
        assert_eq!(analysis.scheme, Some("https".to_string()));
        assert_eq!(analysis.host, Some("example.com".to_string()));
        assert_eq!(analysis.port, Some(8080));
        assert_eq!(analysis.path, Some("/path".to_string()));
        assert_eq!(analysis.query, Some("query=value".to_string()));
        assert_eq!(analysis.fragment, Some("fragment".to_string()));
    }

    #[test]
    fn test_parse_url_without_scheme() {
        let analysis = analyze_url("example.com/path");
        assert!(analysis.valid);
        assert_eq!(analysis.scheme, Some("https".to_string()));
    }

    #[test]
    fn test_parse_invalid_url() {
        let analysis = analyze_url("not a valid url!!!");
        assert!(!analysis.valid);
    }

    #[test]
    fn test_domain_parsing() {
        let domain = parse_domain("sub.example.com");
        assert_eq!(domain.tld, Some("com".to_string()));
        assert_eq!(domain.registered_domain, Some("example.com".to_string()));
        assert_eq!(domain.subdomain, Some("sub".to_string()));
        assert!(!domain.is_ip);
    }

    #[test]
    fn test_ip_domain() {
        let domain = parse_domain("192.168.1.1");
        assert!(domain.is_ip);
    }

    #[test]
    fn test_query_params() {
        let analysis = analyze_url("https://example.com?foo=bar&baz=qux");
        assert_eq!(analysis.query_params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(analysis.query_params.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_security_password_in_url() {
        let analysis = analyze_security("https://user:password@example.com").unwrap();
        assert_eq!(analysis.risk_level, "high");
        assert!(analysis.issues.iter().any(|i| i.category == "Credentials"));
    }

    #[test]
    fn test_security_http() {
        let analysis = analyze_security("http://example.com").unwrap();
        assert!(analysis.issues.iter().any(|i| i.category == "Encryption"));
    }

    #[test]
    fn test_normalize() {
        let normalized = normalize_url("HTTP://EXAMPLE.COM:80/path/").unwrap();
        assert!(normalized.contains("http://example.com"));
    }

    #[test]
    fn test_encode_decode() {
        let original = "hello world!";
        let encoded = utf8_percent_encode(original, NON_ALPHANUMERIC).to_string();
        let decoded = percent_decode_str(&encoded).decode_utf8().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_multi_tld() {
        let domain = parse_domain("www.example.co.uk");
        assert_eq!(domain.tld, Some("co.uk".to_string()));
        assert_eq!(domain.registered_domain, Some("example.co.uk".to_string()));
    }
}
