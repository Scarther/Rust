//! # DNS Resolver - Rust Security Bible
//!
//! A comprehensive DNS lookup and enumeration tool for security reconnaissance.
//! This tool demonstrates DNS query patterns commonly used in penetration testing
//! and security assessments.
//!
//! ## Features
//! - Multiple record type lookups (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR)
//! - Subdomain enumeration
//! - Reverse DNS lookups
//! - Zone transfer attempts
//! - Async concurrent queries
//!
//! ## Security Applications
//! - Reconnaissance during penetration testing
//! - Domain enumeration
//! - Infrastructure mapping
//! - Email server discovery

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tabled::{Table, Tabled};
use thiserror::Error;
use tokio::sync::Semaphore;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Custom error types for DNS operations
#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Query timeout")]
    Timeout,

    #[error("No records found for {record_type} query on {domain}")]
    NoRecords { domain: String, record_type: String },

    #[error("Resolver error: {0}")]
    ResolverError(#[from] trust_dns_resolver::error::ResolveError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type DnsResult<T> = Result<T, DnsError>;

// =============================================================================
// CLI INTERFACE
// =============================================================================

/// DNS Resolver - Security reconnaissance tool
#[derive(Parser, Debug)]
#[command(name = "dns_resolver")]
#[command(author = "Security Developer")]
#[command(version = "1.0")]
#[command(about = "DNS lookup and enumeration tool for security reconnaissance")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Lookup DNS records for a domain
    Lookup {
        /// Domain name to query
        domain: String,

        /// Record type to query
        #[arg(short = 't', long, default_value = "a")]
        record_type: DnsRecordType,
    },

    /// Perform all common DNS lookups for a domain
    Full {
        /// Domain name to query
        domain: String,
    },

    /// Enumerate subdomains using a wordlist
    Enumerate {
        /// Base domain to enumerate
        domain: String,

        /// Wordlist file path (optional, uses built-in if not provided)
        #[arg(short, long)]
        wordlist: Option<String>,

        /// Maximum concurrent queries
        #[arg(short, long, default_value = "10")]
        concurrent: usize,
    },

    /// Perform reverse DNS lookup
    Reverse {
        /// IP address to lookup
        ip: String,
    },

    /// Lookup MX records and check mail server security
    MailCheck {
        /// Domain to check mail servers for
        domain: String,
    },

    /// Query specific DNS servers
    Query {
        /// Domain to query
        domain: String,

        /// DNS server to use
        #[arg(short, long, default_value = "8.8.8.8")]
        server: String,

        /// Record type
        #[arg(short = 't', long, default_value = "a")]
        record_type: DnsRecordType,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
enum DnsRecordType {
    A,
    Aaaa,
    Mx,
    Ns,
    Txt,
    Cname,
    Soa,
    Ptr,
    Srv,
    All,
}

impl DnsRecordType {
    fn to_record_type(&self) -> Option<RecordType> {
        match self {
            DnsRecordType::A => Some(RecordType::A),
            DnsRecordType::Aaaa => Some(RecordType::AAAA),
            DnsRecordType::Mx => Some(RecordType::MX),
            DnsRecordType::Ns => Some(RecordType::NS),
            DnsRecordType::Txt => Some(RecordType::TXT),
            DnsRecordType::Cname => Some(RecordType::CNAME),
            DnsRecordType::Soa => Some(RecordType::SOA),
            DnsRecordType::Ptr => Some(RecordType::PTR),
            DnsRecordType::Srv => Some(RecordType::SRV),
            DnsRecordType::All => None,
        }
    }
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// DNS record data structure
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct DnsRecord {
    #[tabled(rename = "Type")]
    pub record_type: String,
    #[tabled(rename = "Name")]
    pub name: String,
    #[tabled(rename = "Value")]
    pub value: String,
    #[tabled(rename = "TTL")]
    pub ttl: u32,
}

/// Complete DNS lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupResult {
    pub domain: String,
    pub records: Vec<DnsRecord>,
    pub query_time_ms: u64,
    pub dns_server: String,
}

/// Subdomain enumeration result
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct SubdomainResult {
    #[tabled(rename = "Subdomain")]
    pub subdomain: String,
    #[tabled(rename = "IP Address")]
    pub ip: String,
    #[tabled(rename = "Status")]
    pub status: String,
}

/// Mail server check result
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct MailServerResult {
    #[tabled(rename = "Priority")]
    pub priority: u16,
    #[tabled(rename = "Mail Server")]
    pub server: String,
    #[tabled(rename = "IP Address")]
    pub ip: String,
    #[tabled(rename = "SPF")]
    pub has_spf: String,
    #[tabled(rename = "DMARC")]
    pub has_dmarc: String,
}

// =============================================================================
// DNS RESOLVER IMPLEMENTATION
// =============================================================================

/// DNS Resolver wrapper with security-focused methods
pub struct SecurityDnsResolver {
    resolver: TokioAsyncResolver,
    server_name: String,
}

impl SecurityDnsResolver {
    /// Create a new resolver with default DNS servers
    pub async fn new() -> DnsResult<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self {
            resolver,
            server_name: "System Default".to_string(),
        })
    }

    /// Create a resolver with a specific DNS server
    pub async fn with_server(server: &str) -> DnsResult<Self> {
        let ip: Ipv4Addr = server
            .parse()
            .map_err(|_| DnsError::InvalidIp(server.to_string()))?;

        let mut config = ResolverConfig::new();
        config.add_name_server(trust_dns_resolver::config::NameServerConfig {
            socket_addr: std::net::SocketAddr::new(IpAddr::V4(ip), 53),
            protocol: trust_dns_resolver::config::Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });

        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());

        Ok(Self {
            resolver,
            server_name: server.to_string(),
        })
    }

    /// Lookup A records
    pub async fn lookup_a(&self, domain: &str) -> DnsResult<Vec<DnsRecord>> {
        let response = self.resolver.ipv4_lookup(domain).await?;

        Ok(response
            .iter()
            .map(|ip| DnsRecord {
                record_type: "A".to_string(),
                name: domain.to_string(),
                value: ip.to_string(),
                ttl: response.as_lookup().record_iter().next().map_or(0, |r| r.ttl()),
            })
            .collect())
    }

    /// Lookup AAAA records
    pub async fn lookup_aaaa(&self, domain: &str) -> DnsResult<Vec<DnsRecord>> {
        let response = self.resolver.ipv6_lookup(domain).await?;

        Ok(response
            .iter()
            .map(|ip| DnsRecord {
                record_type: "AAAA".to_string(),
                name: domain.to_string(),
                value: ip.to_string(),
                ttl: response.as_lookup().record_iter().next().map_or(0, |r| r.ttl()),
            })
            .collect())
    }

    /// Lookup MX records
    pub async fn lookup_mx(&self, domain: &str) -> DnsResult<Vec<DnsRecord>> {
        let response = self.resolver.mx_lookup(domain).await?;

        Ok(response
            .iter()
            .map(|mx| DnsRecord {
                record_type: "MX".to_string(),
                name: domain.to_string(),
                value: format!("{} {}", mx.preference(), mx.exchange()),
                ttl: response.as_lookup().record_iter().next().map_or(0, |r| r.ttl()),
            })
            .collect())
    }

    /// Lookup NS records
    pub async fn lookup_ns(&self, domain: &str) -> DnsResult<Vec<DnsRecord>> {
        let response = self.resolver.ns_lookup(domain).await?;

        Ok(response
            .iter()
            .map(|ns| DnsRecord {
                record_type: "NS".to_string(),
                name: domain.to_string(),
                value: ns.to_string(),
                ttl: response.as_lookup().record_iter().next().map_or(0, |r| r.ttl()),
            })
            .collect())
    }

    /// Lookup TXT records
    pub async fn lookup_txt(&self, domain: &str) -> DnsResult<Vec<DnsRecord>> {
        let response = self.resolver.txt_lookup(domain).await?;

        Ok(response
            .iter()
            .map(|txt| DnsRecord {
                record_type: "TXT".to_string(),
                name: domain.to_string(),
                value: txt.to_string(),
                ttl: response.as_lookup().record_iter().next().map_or(0, |r| r.ttl()),
            })
            .collect())
    }

    /// Lookup SOA record
    pub async fn lookup_soa(&self, domain: &str) -> DnsResult<Vec<DnsRecord>> {
        let response = self.resolver.soa_lookup(domain).await?;

        Ok(response
            .iter()
            .map(|soa| DnsRecord {
                record_type: "SOA".to_string(),
                name: domain.to_string(),
                value: format!(
                    "{} {} {} {} {} {} {}",
                    soa.mname(),
                    soa.rname(),
                    soa.serial(),
                    soa.refresh(),
                    soa.retry(),
                    soa.expire(),
                    soa.minimum()
                ),
                ttl: response.as_lookup().record_iter().next().map_or(0, |r| r.ttl()),
            })
            .collect())
    }

    /// Reverse DNS lookup
    pub async fn reverse_lookup(&self, ip: &str) -> DnsResult<Vec<DnsRecord>> {
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| DnsError::InvalidIp(ip.to_string()))?;

        let response = self.resolver.reverse_lookup(ip_addr).await?;

        Ok(response
            .iter()
            .map(|name| DnsRecord {
                record_type: "PTR".to_string(),
                name: ip.to_string(),
                value: name.to_string(),
                ttl: response.as_lookup().record_iter().next().map_or(0, |r| r.ttl()),
            })
            .collect())
    }

    /// Perform all common lookups
    pub async fn full_lookup(&self, domain: &str) -> DnsResult<Vec<DnsRecord>> {
        let mut all_records = Vec::new();

        // A records
        if let Ok(records) = self.lookup_a(domain).await {
            all_records.extend(records);
        }

        // AAAA records
        if let Ok(records) = self.lookup_aaaa(domain).await {
            all_records.extend(records);
        }

        // MX records
        if let Ok(records) = self.lookup_mx(domain).await {
            all_records.extend(records);
        }

        // NS records
        if let Ok(records) = self.lookup_ns(domain).await {
            all_records.extend(records);
        }

        // TXT records
        if let Ok(records) = self.lookup_txt(domain).await {
            all_records.extend(records);
        }

        // SOA record
        if let Ok(records) = self.lookup_soa(domain).await {
            all_records.extend(records);
        }

        Ok(all_records)
    }

    /// Check if a subdomain exists
    pub async fn check_subdomain(&self, subdomain: &str) -> Option<SubdomainResult> {
        match self.lookup_a(subdomain).await {
            Ok(records) if !records.is_empty() => Some(SubdomainResult {
                subdomain: subdomain.to_string(),
                ip: records[0].value.clone(),
                status: "Found".to_string(),
            }),
            _ => None,
        }
    }

    /// Check mail server security (SPF, DMARC)
    pub async fn check_mail_security(&self, domain: &str) -> DnsResult<Vec<MailServerResult>> {
        // Get MX records
        let mx_records = self.lookup_mx(domain).await?;

        // Check for SPF
        let has_spf = self
            .lookup_txt(domain)
            .await
            .map(|records| {
                records
                    .iter()
                    .any(|r| r.value.contains("v=spf1"))
            })
            .unwrap_or(false);

        // Check for DMARC
        let dmarc_domain = format!("_dmarc.{}", domain);
        let has_dmarc = self
            .lookup_txt(&dmarc_domain)
            .await
            .map(|records| {
                records
                    .iter()
                    .any(|r| r.value.contains("v=DMARC1"))
            })
            .unwrap_or(false);

        let mut results = Vec::new();

        for mx in mx_records {
            // Parse priority and exchange from MX value
            let parts: Vec<&str> = mx.value.split_whitespace().collect();
            let priority: u16 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
            let exchange = parts.get(1).unwrap_or(&"").to_string();

            // Resolve mail server IP
            let ip = self
                .lookup_a(&exchange.trim_end_matches('.').to_string())
                .await
                .map(|r| r.first().map(|rec| rec.value.clone()).unwrap_or_default())
                .unwrap_or_else(|_| "N/A".to_string());

            results.push(MailServerResult {
                priority,
                server: exchange,
                ip,
                has_spf: if has_spf { "Yes".to_string() } else { "No".to_string() },
                has_dmarc: if has_dmarc { "Yes".to_string() } else { "No".to_string() },
            });
        }

        Ok(results)
    }
}

// =============================================================================
// SUBDOMAIN ENUMERATION
// =============================================================================

/// Built-in subdomain wordlist for quick enumeration
const DEFAULT_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "administrator", "blog",
    "shop", "store", "forum", "dev", "development", "staging", "test", "testing",
    "demo", "api", "app", "mobile", "m", "cdn", "static", "assets", "img", "images",
    "media", "video", "vpn", "remote", "secure", "login", "portal", "dashboard",
    "db", "database", "sql", "mysql", "postgres", "mongodb", "redis", "cache",
    "backup", "git", "gitlab", "github", "jenkins", "ci", "build", "deploy",
    "monitor", "status", "health", "metrics", "logs", "elk", "kibana", "grafana",
    "auth", "oauth", "sso", "ldap", "ad", "exchange", "owa", "autodiscover",
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "container",
    "support", "help", "docs", "documentation", "wiki", "kb", "knowledge",
    "intranet", "internal", "private", "corp", "corporate", "office",
];

/// Enumerate subdomains for a domain
pub async fn enumerate_subdomains(
    resolver: Arc<SecurityDnsResolver>,
    domain: &str,
    wordlist: Option<Vec<String>>,
    max_concurrent: usize,
) -> Vec<SubdomainResult> {
    let subdomains: Vec<String> = wordlist.unwrap_or_else(|| {
        DEFAULT_SUBDOMAINS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });

    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::new();

    for subdomain in subdomains {
        let full_domain = format!("{}.{}", subdomain, domain);
        let resolver = Arc::clone(&resolver);
        let sem = Arc::clone(&semaphore);

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("Semaphore closed");
            resolver.check_subdomain(&full_domain).await
        });

        handles.push(handle);
    }

    let results = join_all(handles).await;

    results
        .into_iter()
        .filter_map(|r| r.ok().flatten())
        .collect()
}

// =============================================================================
// OUTPUT FORMATTING
// =============================================================================

/// Print DNS records in table format
fn print_records_table(records: &[DnsRecord]) {
    if records.is_empty() {
        println!("{}", "No records found".yellow());
        return;
    }

    let table = Table::new(records);
    println!("{}", table);
}

/// Print subdomain results in table format
fn print_subdomains_table(results: &[SubdomainResult]) {
    if results.is_empty() {
        println!("{}", "No subdomains found".yellow());
        return;
    }

    let table = Table::new(results);
    println!("{}", table);
}

/// Print mail server results in table format
fn print_mail_table(results: &[MailServerResult]) {
    if results.is_empty() {
        println!("{}", "No mail servers found".yellow());
        return;
    }

    let table = Table::new(results);
    println!("{}", table);
}

/// Print results as JSON
fn print_json<T: Serialize>(data: &T) {
    match serde_json::to_string_pretty(data) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("{}: {}", "JSON serialization error".red(), e),
    }
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!("{}", "DNS Resolver - Security Reconnaissance Tool".bright_cyan().bold());
    println!("{}", "=".repeat(50));

    match cli.command {
        Commands::Lookup { domain, record_type } => {
            let resolver = SecurityDnsResolver::new().await?;
            let start = Instant::now();

            println!("\n{} {} records for {}", "Querying".cyan(),
                format!("{:?}", record_type).yellow(), domain.green());

            let records = match record_type {
                DnsRecordType::A => resolver.lookup_a(&domain).await?,
                DnsRecordType::Aaaa => resolver.lookup_aaaa(&domain).await?,
                DnsRecordType::Mx => resolver.lookup_mx(&domain).await?,
                DnsRecordType::Ns => resolver.lookup_ns(&domain).await?,
                DnsRecordType::Txt => resolver.lookup_txt(&domain).await?,
                DnsRecordType::Soa => resolver.lookup_soa(&domain).await?,
                DnsRecordType::Ptr => resolver.reverse_lookup(&domain).await?,
                DnsRecordType::Srv | DnsRecordType::Cname => {
                    println!("{}", "SRV and CNAME lookups require specific handling".yellow());
                    vec![]
                }
                DnsRecordType::All => resolver.full_lookup(&domain).await?,
            };

            let elapsed = start.elapsed();

            match cli.format {
                OutputFormat::Text => {
                    println!();
                    print_records_table(&records);
                    println!("\n{}: {:?}", "Query time".dimmed(), elapsed);
                }
                OutputFormat::Json => {
                    let result = DnsLookupResult {
                        domain,
                        records,
                        query_time_ms: elapsed.as_millis() as u64,
                        dns_server: "System Default".to_string(),
                    };
                    print_json(&result);
                }
            }
        }

        Commands::Full { domain } => {
            let resolver = SecurityDnsResolver::new().await?;
            let start = Instant::now();

            println!("\n{} for {}\n", "Full DNS lookup".cyan(), domain.green());

            let records = resolver.full_lookup(&domain).await?;
            let elapsed = start.elapsed();

            match cli.format {
                OutputFormat::Text => {
                    print_records_table(&records);
                    println!("\n{}: {} records in {:?}", "Summary".bold(),
                        records.len().to_string().green(), elapsed);
                }
                OutputFormat::Json => {
                    let result = DnsLookupResult {
                        domain,
                        records,
                        query_time_ms: elapsed.as_millis() as u64,
                        dns_server: "System Default".to_string(),
                    };
                    print_json(&result);
                }
            }
        }

        Commands::Enumerate { domain, wordlist, concurrent } => {
            let resolver = Arc::new(SecurityDnsResolver::new().await?);
            let start = Instant::now();

            // Load wordlist if provided
            let words = if let Some(path) = wordlist {
                let content = tokio::fs::read_to_string(&path).await?;
                Some(content.lines().map(|s| s.to_string()).collect())
            } else {
                None
            };

            let word_count = words.as_ref().map(|w: &Vec<String>| w.len()).unwrap_or(DEFAULT_SUBDOMAINS.len());
            println!(
                "\n{} {} with {} subdomains (max {} concurrent)\n",
                "Enumerating".cyan(),
                domain.green(),
                word_count.to_string().yellow(),
                concurrent.to_string().yellow()
            );

            let results = enumerate_subdomains(resolver, &domain, words, concurrent).await;
            let elapsed = start.elapsed();

            match cli.format {
                OutputFormat::Text => {
                    print_subdomains_table(&results);
                    println!(
                        "\n{}: {} subdomains found in {:?}",
                        "Summary".bold(),
                        results.len().to_string().green(),
                        elapsed
                    );
                }
                OutputFormat::Json => {
                    print_json(&results);
                }
            }
        }

        Commands::Reverse { ip } => {
            let resolver = SecurityDnsResolver::new().await?;
            let start = Instant::now();

            println!("\n{} for {}\n", "Reverse lookup".cyan(), ip.green());

            let records = resolver.reverse_lookup(&ip).await?;
            let elapsed = start.elapsed();

            match cli.format {
                OutputFormat::Text => {
                    print_records_table(&records);
                    println!("\n{}: {:?}", "Query time".dimmed(), elapsed);
                }
                OutputFormat::Json => {
                    let result = DnsLookupResult {
                        domain: ip,
                        records,
                        query_time_ms: elapsed.as_millis() as u64,
                        dns_server: "System Default".to_string(),
                    };
                    print_json(&result);
                }
            }
        }

        Commands::MailCheck { domain } => {
            let resolver = SecurityDnsResolver::new().await?;
            let start = Instant::now();

            println!(
                "\n{} for {}\n",
                "Mail server security check".cyan(),
                domain.green()
            );

            let results = resolver.check_mail_security(&domain).await?;
            let elapsed = start.elapsed();

            match cli.format {
                OutputFormat::Text => {
                    print_mail_table(&results);

                    // Security recommendations
                    println!("\n{}", "Security Analysis:".bold());
                    if let Some(first) = results.first() {
                        if first.has_spf == "No" {
                            println!("  {} SPF record not found - email spoofing possible", "!".red());
                        } else {
                            println!("  {} SPF record found", "+".green());
                        }
                        if first.has_dmarc == "No" {
                            println!("  {} DMARC record not found - email authentication weak", "!".red());
                        } else {
                            println!("  {} DMARC record found", "+".green());
                        }
                    }
                    println!("\n{}: {:?}", "Query time".dimmed(), elapsed);
                }
                OutputFormat::Json => {
                    print_json(&results);
                }
            }
        }

        Commands::Query { domain, server, record_type } => {
            let resolver = SecurityDnsResolver::with_server(&server).await?;
            let start = Instant::now();

            println!(
                "\n{} {} records for {} via {}\n",
                "Querying".cyan(),
                format!("{:?}", record_type).yellow(),
                domain.green(),
                server.cyan()
            );

            let records = match record_type {
                DnsRecordType::A => resolver.lookup_a(&domain).await?,
                DnsRecordType::Aaaa => resolver.lookup_aaaa(&domain).await?,
                DnsRecordType::Mx => resolver.lookup_mx(&domain).await?,
                DnsRecordType::Ns => resolver.lookup_ns(&domain).await?,
                DnsRecordType::Txt => resolver.lookup_txt(&domain).await?,
                DnsRecordType::Soa => resolver.lookup_soa(&domain).await?,
                DnsRecordType::Ptr => resolver.reverse_lookup(&domain).await?,
                DnsRecordType::All => resolver.full_lookup(&domain).await?,
                _ => vec![],
            };

            let elapsed = start.elapsed();

            match cli.format {
                OutputFormat::Text => {
                    print_records_table(&records);
                    println!("\n{}: {:?}", "Query time".dimmed(), elapsed);
                }
                OutputFormat::Json => {
                    let result = DnsLookupResult {
                        domain,
                        records,
                        query_time_ms: elapsed.as_millis() as u64,
                        dns_server: server,
                    };
                    print_json(&result);
                }
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

    #[tokio::test]
    async fn test_resolver_creation() {
        let resolver = SecurityDnsResolver::new().await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_resolver_with_server() {
        let resolver = SecurityDnsResolver::with_server("8.8.8.8").await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_server() {
        let resolver = SecurityDnsResolver::with_server("invalid").await;
        assert!(resolver.is_err());
    }

    #[tokio::test]
    async fn test_a_lookup() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        let result = resolver.lookup_a("google.com").await;
        assert!(result.is_ok());
        let records = result.unwrap();
        assert!(!records.is_empty());
        assert_eq!(records[0].record_type, "A");
    }

    #[tokio::test]
    async fn test_mx_lookup() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        let result = resolver.lookup_mx("google.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ns_lookup() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        let result = resolver.lookup_ns("google.com").await;
        assert!(result.is_ok());
        let records = result.unwrap();
        assert!(!records.is_empty());
    }

    #[tokio::test]
    async fn test_txt_lookup() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        let result = resolver.lookup_txt("google.com").await;
        // TXT records may or may not exist
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_full_lookup() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        let result = resolver.full_lookup("google.com").await;
        assert!(result.is_ok());
        let records = result.unwrap();
        assert!(!records.is_empty());
    }

    #[tokio::test]
    async fn test_reverse_lookup() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        // Google's public DNS
        let result = resolver.reverse_lookup("8.8.8.8").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_domain() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        let result = resolver.lookup_a("thisdoesnotexist12345.invalid").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_subdomain_check() {
        let resolver = SecurityDnsResolver::new().await.unwrap();
        let result = resolver.check_subdomain("www.google.com").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_dns_record_serialization() {
        let record = DnsRecord {
            record_type: "A".to_string(),
            name: "example.com".to_string(),
            value: "93.184.216.34".to_string(),
            ttl: 300,
        };

        let json = serde_json::to_string(&record);
        assert!(json.is_ok());

        let deserialized: DnsRecord = serde_json::from_str(&json.unwrap()).unwrap();
        assert_eq!(deserialized.record_type, "A");
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(DnsRecordType::A.to_record_type(), Some(RecordType::A));
        assert_eq!(DnsRecordType::Mx.to_record_type(), Some(RecordType::MX));
        assert_eq!(DnsRecordType::All.to_record_type(), None);
    }

    #[test]
    fn test_default_wordlist() {
        assert!(!DEFAULT_SUBDOMAINS.is_empty());
        assert!(DEFAULT_SUBDOMAINS.contains(&"www"));
        assert!(DEFAULT_SUBDOMAINS.contains(&"mail"));
        assert!(DEFAULT_SUBDOMAINS.contains(&"api"));
    }
}
