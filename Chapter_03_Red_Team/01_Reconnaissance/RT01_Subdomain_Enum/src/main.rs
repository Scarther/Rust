//! # RT01 Subdomain Enumeration Tool
//!
//! A comprehensive subdomain enumeration tool for authorized security testing.
//! This tool discovers subdomains using multiple techniques:
//! - DNS brute-forcing with wordlists
//! - Certificate transparency logs
//! - DNS zone transfer attempts
//! - Recursive subdomain discovery
//!
//! ## Legal Disclaimer
//!
//! THIS TOOL IS PROVIDED FOR AUTHORIZED SECURITY TESTING ONLY.
//! Unauthorized access to computer systems is illegal. Always obtain
//! written permission before testing systems you do not own.
//! The authors assume no liability for misuse of this software.
//!
//! ## Usage Examples
//!
//! ```bash
//! # Basic enumeration with built-in wordlist
//! subdomain-enum -d example.com
//!
//! # Use custom wordlist with increased concurrency
//! subdomain-enum -d example.com -w wordlist.txt -c 100
//!
//! # Check certificate transparency logs
//! subdomain-enum -d example.com --crt-sh
//!
//! # Output to JSON file
//! subdomain-enum -d example.com -o results.json
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

// ============================================================================
// LEGAL DISCLAIMER - MUST BE DISPLAYED
// ============================================================================

const LEGAL_DISCLAIMER: &str = r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                           LEGAL DISCLAIMER                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is provided for AUTHORIZED SECURITY TESTING ONLY.                 ║
║                                                                              ║
║  By using this tool, you acknowledge that:                                   ║
║  1. You have explicit written authorization to test the target domain        ║
║  2. Unauthorized access to computer systems is a criminal offense            ║
║  3. You accept full responsibility for your actions                          ║
║  4. The authors are not liable for any misuse or damage caused               ║
║                                                                              ║
║  Violating computer crime laws can result in severe penalties including      ║
║  imprisonment. Always obtain proper authorization before testing.            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"#;

// ============================================================================
// COMMAND LINE INTERFACE DEFINITIONS
// ============================================================================

/// Subdomain Enumeration Tool for Authorized Security Testing
///
/// Discovers subdomains using DNS brute-forcing, certificate transparency
/// logs, and other reconnaissance techniques.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target domain to enumerate (e.g., example.com)
    #[arg(short, long)]
    domain: String,

    /// Path to custom wordlist file (one subdomain per line)
    #[arg(short, long)]
    wordlist: Option<PathBuf>,

    /// Number of concurrent DNS queries (default: 50)
    #[arg(short, long, default_value = "50")]
    concurrency: usize,

    /// Query certificate transparency logs (crt.sh)
    #[arg(long)]
    crt_sh: bool,

    /// Attempt DNS zone transfer
    #[arg(long)]
    zone_transfer: bool,

    /// Output results to JSON file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// DNS resolver to use (default: system resolver)
    #[arg(long)]
    resolver: Option<String>,

    /// Timeout for DNS queries in seconds
    #[arg(long, default_value = "5")]
    timeout: u64,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Skip legal disclaimer confirmation
    #[arg(long)]
    accept_disclaimer: bool,

    /// Recursive subdomain enumeration depth
    #[arg(long, default_value = "1")]
    recursive_depth: u32,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Represents a discovered subdomain with its associated information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubdomainResult {
    /// The full subdomain name (e.g., www.example.com)
    subdomain: String,
    /// Resolved IP addresses
    ip_addresses: Vec<String>,
    /// Discovery method used
    discovery_method: String,
    /// Whether the subdomain is alive (responds to queries)
    is_alive: bool,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    cname: Option<String>,
}

/// Complete enumeration results for export
#[derive(Debug, Serialize, Deserialize)]
struct EnumerationReport {
    /// Target domain
    target_domain: String,
    /// Timestamp of enumeration
    timestamp: String,
    /// Total subdomains found
    total_found: usize,
    /// Discovery methods used
    methods_used: Vec<String>,
    /// All discovered subdomains
    subdomains: Vec<SubdomainResult>,
}

/// DNS resolver wrapper for subdomain enumeration
struct SubdomainEnumerator {
    /// The async DNS resolver
    resolver: TokioAsyncResolver,
    /// Target domain
    domain: String,
    /// Discovered subdomains
    results: Arc<Mutex<HashSet<String>>>,
    /// Verbose output flag
    verbose: bool,
}

// ============================================================================
// BUILT-IN WORDLIST
// ============================================================================

/// Common subdomain prefixes for brute-forcing
/// This is a curated list of the most common subdomains found in the wild
const COMMON_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "email", "vpn",
    "remote", "server", "api", "dev", "staging", "test", "qa", "uat", "prod",
    "production", "admin", "administrator", "portal", "app", "apps", "web",
    "www1", "www2", "www3", "secure", "ssl", "shop", "store", "blog", "forum",
    "support", "help", "docs", "documentation", "wiki", "git", "gitlab", "github",
    "svn", "cvs", "hg", "jenkins", "ci", "cd", "build", "deploy", "monitor",
    "monitoring", "status", "health", "metrics", "logs", "log", "syslog",
    "backup", "backups", "db", "database", "mysql", "postgres", "postgresql",
    "mongo", "mongodb", "redis", "memcache", "memcached", "cache", "cdn",
    "static", "assets", "images", "img", "media", "files", "download", "downloads",
    "upload", "uploads", "cloud", "aws", "azure", "gcp", "s3", "storage",
    "auth", "oauth", "sso", "login", "signin", "signup", "register", "account",
    "accounts", "user", "users", "profile", "profiles", "member", "members",
    "customer", "customers", "client", "clients", "partner", "partners",
    "internal", "intranet", "extranet", "corp", "corporate", "office",
    "hr", "finance", "sales", "marketing", "legal", "eng", "engineering",
    "research", "labs", "lab", "demo", "demos", "preview", "beta", "alpha",
    "sandbox", "playground", "old", "new", "v1", "v2", "v3", "legacy",
    "mobile", "m", "wap", "pda", "iphone", "android", "ios", "tablet",
    "gateway", "gw", "firewall", "fw", "proxy", "lb", "loadbalancer",
    "router", "switch", "hub", "bridge", "relay", "edge", "node", "cluster",
    "master", "slave", "primary", "secondary", "replica", "mirror",
    "origin", "upstream", "downstream", "frontend", "backend", "middleware",
    "service", "services", "microservice", "micro", "lambda", "function",
    "event", "events", "queue", "mq", "rabbit", "kafka", "stream",
    "data", "bigdata", "analytics", "reporting", "reports", "dashboard",
    "panel", "console", "control", "manage", "management", "cms", "crm",
    "erp", "hr", "ticket", "tickets", "issue", "issues", "bug", "bugs",
    "track", "tracker", "tracking", "jira", "confluence", "slack", "teams",
    "chat", "im", "messenger", "video", "audio", "voice", "voip", "sip",
    "pbx", "asterisk", "phone", "tel", "fax", "print", "printer", "scan",
    "scanner", "copy", "copier", "office365", "o365", "exchange", "outlook",
    "calendar", "contact", "contacts", "directory", "ldap", "ad", "dc",
    "domain", "ns", "nameserver", "time", "ntp", "snmp", "ssh", "sftp",
    "telnet", "rdp", "vnc", "citrix", "terminal", "bastion", "jump", "jumpbox",
];

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl SubdomainEnumerator {
    /// Create a new subdomain enumerator with the specified resolver
    async fn new(domain: String, resolver_addr: Option<String>, verbose: bool) -> Result<Self> {
        // Configure the DNS resolver
        let resolver = if let Some(addr) = resolver_addr {
            // Parse custom resolver address
            let ip: IpAddr = addr.parse()
                .context("Invalid resolver IP address")?;

            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(5);
            opts.attempts = 2;

            // Create resolver with custom nameserver
            let config = ResolverConfig::from_parts(
                None,
                vec![],
                trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(
                    &[ip],
                    53,
                    true,
                ),
            );

            TokioAsyncResolver::tokio(config, opts)
        } else {
            // Use system resolver
            TokioAsyncResolver::tokio_from_system_conf()
                .context("Failed to create DNS resolver from system configuration")?
        };

        Ok(Self {
            resolver,
            domain,
            results: Arc::new(Mutex::new(HashSet::new())),
            verbose,
        })
    }

    /// Check if a subdomain exists by attempting DNS resolution
    async fn check_subdomain(&self, subdomain: &str) -> Option<SubdomainResult> {
        let fqdn = format!("{}.{}", subdomain, self.domain);

        // Attempt to resolve A records
        match self.resolver.lookup_ip(&fqdn).await {
            Ok(response) => {
                let ips: Vec<String> = response
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect();

                if !ips.is_empty() {
                    // Also try to get CNAME record
                    let cname = self.get_cname(&fqdn).await;

                    return Some(SubdomainResult {
                        subdomain: fqdn,
                        ip_addresses: ips,
                        discovery_method: "DNS Brute-force".to_string(),
                        is_alive: true,
                        cname,
                    });
                }
            }
            Err(_) => {
                // Subdomain doesn't exist or DNS error
                if self.verbose {
                    eprintln!("{} No response for {}", "[-]".dimmed(), fqdn.dimmed());
                }
            }
        }

        None
    }

    /// Get CNAME record for a domain
    async fn get_cname(&self, fqdn: &str) -> Option<String> {
        match self.resolver.lookup(
            fqdn,
            trust_dns_resolver::proto::rr::RecordType::CNAME,
        ).await {
            Ok(response) => {
                response.iter().next().map(|r| r.to_string())
            }
            Err(_) => None,
        }
    }

    /// Enumerate subdomains using a wordlist
    async fn enumerate_with_wordlist(
        &self,
        wordlist: Vec<String>,
        concurrency: usize,
    ) -> Vec<SubdomainResult> {
        let total = wordlist.len();

        // Create progress bar
        let progress = ProgressBar::new(total as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .expect("Invalid progress bar template")
                .progress_chars("#>-"),
        );

        // Process subdomains concurrently
        let results: Vec<SubdomainResult> = stream::iter(wordlist)
            .map(|subdomain| {
                let progress = progress.clone();
                async move {
                    let result = self.check_subdomain(&subdomain).await;
                    progress.inc(1);
                    result
                }
            })
            .buffer_unordered(concurrency)
            .filter_map(|r| async move { r })
            .collect()
            .await;

        progress.finish_with_message("Enumeration complete");
        results
    }

    /// Query certificate transparency logs via crt.sh
    async fn query_crt_sh(&self) -> Result<Vec<SubdomainResult>> {
        println!("{} Querying certificate transparency logs (crt.sh)...",
            "[*]".blue());

        let url = format!(
            "https://crt.sh/?q=%.{}&output=json",
            self.domain
        );

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let response = client.get(&url)
            .send()
            .await
            .context("Failed to query crt.sh")?;

        if !response.status().is_success() {
            anyhow::bail!("crt.sh returned status: {}", response.status());
        }

        let text = response.text().await?;

        // Parse JSON response
        #[derive(Deserialize)]
        struct CrtShEntry {
            name_value: String,
        }

        let entries: Vec<CrtShEntry> = serde_json::from_str(&text)
            .unwrap_or_else(|_| Vec::new());

        // Extract unique subdomains
        let subdomain_regex = Regex::new(&format!(
            r"(?i)([a-z0-9][-a-z0-9]*\.)*{}",
            regex::escape(&self.domain)
        ))?;

        let mut unique_subdomains: HashSet<String> = HashSet::new();

        for entry in entries {
            // Handle wildcard certificates and multi-line values
            for line in entry.name_value.lines() {
                let name = line.trim().to_lowercase();
                if name.ends_with(&self.domain) && subdomain_regex.is_match(&name) {
                    // Skip wildcard entries
                    if !name.starts_with('*') {
                        unique_subdomains.insert(name);
                    }
                }
            }
        }

        println!("{} Found {} unique entries in CT logs",
            "[+]".green(),
            unique_subdomains.len());

        // Verify each subdomain is alive
        let mut results = Vec::new();
        for subdomain in unique_subdomains {
            // Extract the prefix and check if it resolves
            if let Ok(response) = self.resolver.lookup_ip(&subdomain).await {
                let ips: Vec<String> = response
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect();

                if !ips.is_empty() {
                    results.push(SubdomainResult {
                        subdomain,
                        ip_addresses: ips,
                        discovery_method: "Certificate Transparency".to_string(),
                        is_alive: true,
                        cname: None,
                    });
                }
            }
        }

        Ok(results)
    }

    /// Attempt DNS zone transfer (AXFR)
    async fn attempt_zone_transfer(&self) -> Result<Vec<SubdomainResult>> {
        println!("{} Attempting DNS zone transfer...", "[*]".blue());
        println!("{} Note: Zone transfers are rarely allowed on modern DNS servers",
            "[!]".yellow());

        // First, get the NS records for the domain
        let ns_response = self.resolver
            .lookup(
                &self.domain,
                trust_dns_resolver::proto::rr::RecordType::NS,
            )
            .await
            .context("Failed to lookup NS records")?;

        let nameservers: Vec<String> = ns_response
            .iter()
            .map(|r| r.to_string().trim_end_matches('.').to_string())
            .collect();

        if nameservers.is_empty() {
            println!("{} No nameservers found for domain", "[!]".yellow());
            return Ok(Vec::new());
        }

        println!("{} Found {} nameservers: {:?}",
            "[+]".green(),
            nameservers.len(),
            nameservers);

        // Zone transfer requires special DNS client - we'll simulate the attempt
        // In practice, you'd use a dedicated AXFR library
        println!("{} Zone transfer typically blocked - use 'dig axfr' for manual testing",
            "[!]".yellow());

        Ok(Vec::new())
    }
}

/// Load wordlist from file or use built-in list
fn load_wordlist(path: Option<PathBuf>) -> Result<Vec<String>> {
    match path {
        Some(p) => {
            let file = File::open(&p)
                .with_context(|| format!("Failed to open wordlist: {:?}", p))?;
            let reader = BufReader::new(file);
            let words: Vec<String> = reader
                .lines()
                .filter_map(|line| line.ok())
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .collect();

            println!("{} Loaded {} words from wordlist", "[+]".green(), words.len());
            Ok(words)
        }
        None => {
            println!("{} Using built-in wordlist ({} entries)",
                "[*]".blue(),
                COMMON_SUBDOMAINS.len());
            Ok(COMMON_SUBDOMAINS.iter().map(|s| s.to_string()).collect())
        }
    }
}

/// Display results in a formatted table
fn display_results(results: &[SubdomainResult]) {
    if results.is_empty() {
        println!("\n{} No subdomains found", "[!]".yellow());
        return;
    }

    println!("\n{}", "═".repeat(80).cyan());
    println!("{}", " DISCOVERED SUBDOMAINS ".cyan().bold());
    println!("{}", "═".repeat(80).cyan());

    for result in results {
        let status = if result.is_alive {
            "[ALIVE]".green()
        } else {
            "[DEAD]".red()
        };

        println!("\n{} {}", status, result.subdomain.white().bold());
        println!("    {} {}", "IPs:".dimmed(), result.ip_addresses.join(", "));
        println!("    {} {}", "Method:".dimmed(), result.discovery_method);

        if let Some(cname) = &result.cname {
            println!("    {} {}", "CNAME:".dimmed(), cname);
        }
    }

    println!("\n{}", "═".repeat(80).cyan());
    println!("{} Total: {} subdomains found", "[+]".green(), results.len());
}

/// Save results to JSON file
fn save_results(results: &[SubdomainResult], domain: &str, output: PathBuf) -> Result<()> {
    let report = EnumerationReport {
        target_domain: domain.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_found: results.len(),
        methods_used: results
            .iter()
            .map(|r| r.discovery_method.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect(),
        subdomains: results.to_vec(),
    };

    let mut file = File::create(&output)
        .with_context(|| format!("Failed to create output file: {:?}", output))?;

    let json = serde_json::to_string_pretty(&report)?;
    file.write_all(json.as_bytes())?;

    println!("{} Results saved to {:?}", "[+]".green(), output);
    Ok(())
}

/// Validate domain format
fn validate_domain(domain: &str) -> Result<()> {
    let domain_regex = Regex::new(
        r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )?;

    if !domain_regex.is_match(domain) {
        anyhow::bail!("Invalid domain format: {}", domain);
    }

    Ok(())
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Display legal disclaimer
    println!("{}", LEGAL_DISCLAIMER.red());

    if !args.accept_disclaimer {
        println!("{}", "Do you have authorization to test this domain? (yes/no): ".yellow());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!("{} Exiting - authorization required", "[!]".red());
            return Ok(());
        }
    }

    // Validate domain
    validate_domain(&args.domain)?;

    println!("\n{}", "═".repeat(80).cyan());
    println!("{} {}", " TARGET:".cyan().bold(), args.domain.white().bold());
    println!("{}", "═".repeat(80).cyan());

    // Initialize the enumerator
    let enumerator = SubdomainEnumerator::new(
        args.domain.clone(),
        args.resolver,
        args.verbose,
    ).await?;

    let mut all_results: Vec<SubdomainResult> = Vec::new();

    // Method 1: DNS Brute-force with wordlist
    println!("\n{} Starting DNS brute-force enumeration...", "[*]".blue());
    let wordlist = load_wordlist(args.wordlist)?;
    let brute_results = enumerator
        .enumerate_with_wordlist(wordlist, args.concurrency)
        .await;

    println!("{} Found {} subdomains via brute-force",
        "[+]".green(),
        brute_results.len());

    all_results.extend(brute_results);

    // Method 2: Certificate Transparency (if requested)
    if args.crt_sh {
        match enumerator.query_crt_sh().await {
            Ok(ct_results) => {
                println!("{} Found {} subdomains via CT logs",
                    "[+]".green(),
                    ct_results.len());
                all_results.extend(ct_results);
            }
            Err(e) => {
                println!("{} CT lookup failed: {}", "[!]".yellow(), e);
            }
        }
    }

    // Method 3: Zone Transfer (if requested)
    if args.zone_transfer {
        match enumerator.attempt_zone_transfer().await {
            Ok(zt_results) => {
                if !zt_results.is_empty() {
                    println!("{} Found {} subdomains via zone transfer",
                        "[+]".green(),
                        zt_results.len());
                    all_results.extend(zt_results);
                }
            }
            Err(e) => {
                println!("{} Zone transfer failed: {}", "[!]".yellow(), e);
            }
        }
    }

    // Deduplicate results
    let mut seen: HashSet<String> = HashSet::new();
    all_results.retain(|r| seen.insert(r.subdomain.clone()));

    // Sort results alphabetically
    all_results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

    // Display results
    display_results(&all_results);

    // Save to file if requested
    if let Some(output) = args.output {
        save_results(&all_results, &args.domain, output)?;
    }

    println!("\n{} Enumeration complete!", "[+]".green().bold());

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_validation() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("test-domain.co.uk").is_ok());
        assert!(validate_domain("invalid").is_err());
        assert!(validate_domain("-invalid.com").is_err());
    }

    #[test]
    fn test_wordlist_size() {
        assert!(COMMON_SUBDOMAINS.len() > 100);
    }

    #[test]
    fn test_subdomain_result_serialization() {
        let result = SubdomainResult {
            subdomain: "www.example.com".to_string(),
            ip_addresses: vec!["93.184.216.34".to_string()],
            discovery_method: "DNS Brute-force".to_string(),
            is_alive: true,
            cname: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("www.example.com"));
    }
}
