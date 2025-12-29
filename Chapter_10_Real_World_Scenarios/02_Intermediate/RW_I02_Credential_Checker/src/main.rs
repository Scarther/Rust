//! Credential Leak Checker
//!
//! A security tool to check if credentials have been leaked in known data breaches
//! using the HaveIBeenPwned API with k-anonymity protection.
//!
//! Features:
//! - Single password/email check
//! - Bulk credential checking from file
//! - K-anonymity for secure password checking
//! - Breach details and history
//! - CSV report generation
//! - Rate limiting compliance

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

const HIBP_API_BASE: &str = "https://haveibeenpwned.com/api/v3";
const HIBP_PASSWORD_API: &str = "https://api.pwnedpasswords.com/range";
const USER_AGENT: &str = "RustSecurityBible-CredentialChecker/1.0";

/// Credential Checker CLI
#[derive(Parser)]
#[command(name = "credential-checker")]
#[command(about = "Check for leaked credentials using HaveIBeenPwned API")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// HIBP API key (required for email/breach lookups)
    #[arg(long, global = true, env = "HIBP_API_KEY")]
    api_key: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check if a password has been leaked
    Password {
        /// The password to check
        #[arg(short, long)]
        password: String,
    },
    /// Check if an email has been in breaches
    Email {
        /// The email to check
        #[arg(short, long)]
        email: String,

        /// Include unverified breaches
        #[arg(long)]
        include_unverified: bool,
    },
    /// Bulk check passwords from a file
    BulkPasswords {
        /// Input file (one password per line)
        #[arg(short, long)]
        input: PathBuf,

        /// Output report file
        #[arg(short, long, default_value = "password_report.csv")]
        output: PathBuf,

        /// Delay between requests (ms)
        #[arg(long, default_value = "100")]
        delay_ms: u64,
    },
    /// Bulk check emails from a file
    BulkEmails {
        /// Input file (one email per line)
        #[arg(short, long)]
        input: PathBuf,

        /// Output report file
        #[arg(short, long, default_value = "email_report.csv")]
        output: PathBuf,

        /// Delay between requests (ms)
        #[arg(long, default_value = "1500")]
        delay_ms: u64,
    },
    /// Get breach details
    BreachInfo {
        /// Breach name
        #[arg(short, long)]
        name: String,
    },
    /// List all known breaches
    ListBreaches {
        /// Filter by domain
        #[arg(short, long)]
        domain: Option<String>,

        /// Limit results
        #[arg(short, long)]
        limit: Option<usize>,
    },
    /// Check a domain for pastes
    Pastes {
        /// Email to check for pastes
        #[arg(short, long)]
        email: String,
    },
}

/// Breach information from HIBP
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Breach {
    name: String,
    title: String,
    domain: String,
    breach_date: String,
    added_date: DateTime<Utc>,
    modified_date: DateTime<Utc>,
    pwn_count: u64,
    description: String,
    logo_path: String,
    data_classes: Vec<String>,
    is_verified: bool,
    is_fabricated: bool,
    is_sensitive: bool,
    is_retired: bool,
    is_spam_list: bool,
    #[serde(default)]
    is_malware: bool,
    #[serde(default)]
    is_subscription_free: bool,
}

/// Paste information from HIBP
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Paste {
    source: String,
    id: String,
    title: Option<String>,
    date: Option<DateTime<Utc>>,
    email_count: u64,
}

/// Password check result
#[derive(Debug, Clone, Serialize)]
struct PasswordCheckResult {
    password_hash_prefix: String,
    is_compromised: bool,
    occurrence_count: u64,
    checked_at: DateTime<Utc>,
}

/// Email check result
#[derive(Debug, Clone, Serialize)]
struct EmailCheckResult {
    email: String,
    is_compromised: bool,
    breach_count: usize,
    breaches: Vec<String>,
    total_records_exposed: u64,
    checked_at: DateTime<Utc>,
}

/// Credential checker
struct CredentialChecker {
    client: Client,
    api_key: Option<String>,
}

impl CredentialChecker {
    fn new(api_key: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { client, api_key })
    }

    /// Check password using k-anonymity (SHA-1 prefix)
    async fn check_password(&self, password: &str) -> Result<PasswordCheckResult> {
        // Hash the password with SHA-1
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize()).to_uppercase();

        // Split into prefix (5 chars) and suffix
        let (prefix, suffix) = hash.split_at(5);

        debug!("Checking password hash prefix: {}", prefix);

        // Query HIBP with prefix only (k-anonymity)
        let url = format!("{}/{}", HIBP_PASSWORD_API, prefix);
        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to query password API")?;

        if !response.status().is_success() {
            anyhow::bail!("API error: {}", response.status());
        }

        let body = response.text().await?;

        // Parse response and find our suffix
        let mut occurrence_count = 0u64;
        for line in body.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 && parts[0] == suffix {
                occurrence_count = parts[1].parse().unwrap_or(0);
                break;
            }
        }

        Ok(PasswordCheckResult {
            password_hash_prefix: prefix.to_string(),
            is_compromised: occurrence_count > 0,
            occurrence_count,
            checked_at: Utc::now(),
        })
    }

    /// Check email for breaches
    async fn check_email(&self, email: &str, include_unverified: bool) -> Result<EmailCheckResult> {
        let api_key = self.api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API key required for email checks"))?;

        let url = format!(
            "{}/breachedaccount/{}?truncateResponse=false&includeUnverified={}",
            HIBP_API_BASE,
            urlencoding::encode(email),
            include_unverified
        );

        let response = self.client
            .get(&url)
            .header("hibp-api-key", api_key)
            .send()
            .await
            .context("Failed to query email API")?;

        match response.status().as_u16() {
            200 => {
                let breaches: Vec<Breach> = response.json().await?;
                let breach_names: Vec<String> = breaches.iter()
                    .map(|b| b.name.clone())
                    .collect();
                let total_exposed: u64 = breaches.iter()
                    .map(|b| b.pwn_count)
                    .sum();

                Ok(EmailCheckResult {
                    email: email.to_string(),
                    is_compromised: true,
                    breach_count: breaches.len(),
                    breaches: breach_names,
                    total_records_exposed: total_exposed,
                    checked_at: Utc::now(),
                })
            }
            404 => {
                Ok(EmailCheckResult {
                    email: email.to_string(),
                    is_compromised: false,
                    breach_count: 0,
                    breaches: Vec::new(),
                    total_records_exposed: 0,
                    checked_at: Utc::now(),
                })
            }
            401 => anyhow::bail!("Invalid API key"),
            429 => anyhow::bail!("Rate limit exceeded. Please wait and try again."),
            status => anyhow::bail!("API error: HTTP {}", status),
        }
    }

    /// Get breach details
    async fn get_breach_info(&self, name: &str) -> Result<Breach> {
        let url = format!("{}/breach/{}", HIBP_API_BASE, urlencoding::encode(name));

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to query breach API")?;

        match response.status().as_u16() {
            200 => Ok(response.json().await?),
            404 => anyhow::bail!("Breach '{}' not found", name),
            status => anyhow::bail!("API error: HTTP {}", status),
        }
    }

    /// List all breaches
    async fn list_breaches(&self, domain: Option<&str>) -> Result<Vec<Breach>> {
        let url = match domain {
            Some(d) => format!("{}/breaches?domain={}", HIBP_API_BASE, urlencoding::encode(d)),
            None => format!("{}/breaches", HIBP_API_BASE),
        };

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to query breaches API")?;

        if !response.status().is_success() {
            anyhow::bail!("API error: {}", response.status());
        }

        Ok(response.json().await?)
    }

    /// Check for pastes
    async fn check_pastes(&self, email: &str) -> Result<Vec<Paste>> {
        let api_key = self.api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API key required for paste checks"))?;

        let url = format!("{}/pasteaccount/{}", HIBP_API_BASE, urlencoding::encode(email));

        let response = self.client
            .get(&url)
            .header("hibp-api-key", api_key)
            .send()
            .await
            .context("Failed to query pastes API")?;

        match response.status().as_u16() {
            200 => Ok(response.json().await?),
            404 => Ok(Vec::new()),
            401 => anyhow::bail!("Invalid API key"),
            429 => anyhow::bail!("Rate limit exceeded"),
            status => anyhow::bail!("API error: HTTP {}", status),
        }
    }

    /// Bulk check passwords from file
    async fn bulk_check_passwords(&self, input: PathBuf, output: PathBuf, delay_ms: u64) -> Result<()> {
        let file = File::open(&input)
            .context(format!("Failed to open input file: {}", input.display()))?;
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader.lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .collect();

        println!("\n{}", "=".repeat(60).cyan());
        println!("{}", "Bulk Password Check".bold().cyan());
        println!("{}", "=".repeat(60).cyan());
        println!("Checking {} passwords...\n", passwords.len().to_string().yellow());

        let pb = ProgressBar::new(passwords.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
            .progress_chars("#>-"));

        let mut results = Vec::new();
        let mut compromised_count = 0u64;

        for password in &passwords {
            match self.check_password(password).await {
                Ok(result) => {
                    if result.is_compromised {
                        compromised_count += 1;
                    }
                    results.push((password.clone(), result));
                }
                Err(e) => {
                    warn!("Failed to check password: {}", e);
                    results.push((password.clone(), PasswordCheckResult {
                        password_hash_prefix: String::new(),
                        is_compromised: false,
                        occurrence_count: 0,
                        checked_at: Utc::now(),
                    }));
                }
            }
            pb.inc(1);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        pb.finish_with_message("Complete");

        // Write CSV report
        let mut writer = csv::Writer::from_path(&output)?;
        writer.write_record(&["Password (masked)", "Compromised", "Occurrences", "Checked At"])?;

        for (password, result) in &results {
            let masked = if password.len() > 4 {
                format!("{}***", &password[..2])
            } else {
                "***".to_string()
            };

            writer.write_record(&[
                masked,
                result.is_compromised.to_string(),
                result.occurrence_count.to_string(),
                result.checked_at.to_rfc3339(),
            ])?;
        }

        writer.flush()?;

        println!("\n{}", "Summary:".bold());
        println!("  Total passwords checked: {}", passwords.len().to_string().cyan());
        println!("  Compromised: {}", compromised_count.to_string().red());
        println!("  Safe: {}", (passwords.len() as u64 - compromised_count).to_string().green());
        println!("\nReport saved to: {}", output.display().to_string().cyan());

        Ok(())
    }

    /// Bulk check emails from file
    async fn bulk_check_emails(&self, input: PathBuf, output: PathBuf, delay_ms: u64) -> Result<()> {
        let file = File::open(&input)
            .context(format!("Failed to open input file: {}", input.display()))?;
        let reader = BufReader::new(file);
        let emails: Vec<String> = reader.lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .collect();

        println!("\n{}", "=".repeat(60).cyan());
        println!("{}", "Bulk Email Breach Check".bold().cyan());
        println!("{}", "=".repeat(60).cyan());
        println!("Checking {} emails...\n", emails.len().to_string().yellow());

        let pb = ProgressBar::new(emails.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
            .progress_chars("#>-"));

        let mut results = Vec::new();
        let mut compromised_count = 0usize;

        for email in &emails {
            match self.check_email(email, false).await {
                Ok(result) => {
                    if result.is_compromised {
                        compromised_count += 1;
                    }
                    results.push(result);
                }
                Err(e) => {
                    warn!("Failed to check email {}: {}", email, e);
                    results.push(EmailCheckResult {
                        email: email.clone(),
                        is_compromised: false,
                        breach_count: 0,
                        breaches: Vec::new(),
                        total_records_exposed: 0,
                        checked_at: Utc::now(),
                    });
                }
            }
            pb.inc(1);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        pb.finish_with_message("Complete");

        // Write CSV report
        let mut writer = csv::Writer::from_path(&output)?;
        writer.write_record(&["Email", "Compromised", "Breach Count", "Breaches", "Records Exposed", "Checked At"])?;

        for result in &results {
            writer.write_record(&[
                result.email.clone(),
                result.is_compromised.to_string(),
                result.breach_count.to_string(),
                result.breaches.join("; "),
                result.total_records_exposed.to_string(),
                result.checked_at.to_rfc3339(),
            ])?;
        }

        writer.flush()?;

        println!("\n{}", "Summary:".bold());
        println!("  Total emails checked: {}", emails.len().to_string().cyan());
        println!("  Compromised: {}", compromised_count.to_string().red());
        println!("  Safe: {}", (emails.len() - compromised_count).to_string().green());
        println!("\nReport saved to: {}", output.display().to_string().cyan());

        Ok(())
    }
}

/// Display password check result
fn display_password_result(result: &PasswordCheckResult) {
    println!("\n{}", "=".repeat(50).cyan());
    println!("{}", "Password Check Result".bold().cyan());
    println!("{}", "=".repeat(50).cyan());

    if result.is_compromised {
        println!("\n{} This password has been found in data breaches!",
            "WARNING:".red().bold());
        println!("\n  Occurrences: {} times", result.occurrence_count.to_string().red().bold());
        println!("\n  {}", "This password should NOT be used!".red());
        println!("  {}", "Change this password immediately if in use.".yellow());
    } else {
        println!("\n{} This password was not found in known data breaches.",
            "GOOD:".green().bold());
        println!("\n  {}", "However, this doesn't guarantee the password is secure.".yellow());
        println!("  {}", "Always use strong, unique passwords.".yellow());
    }

    println!("\n  Checked at: {}", result.checked_at.format("%Y-%m-%d %H:%M:%S UTC"));
}

/// Display email check result
fn display_email_result(result: &EmailCheckResult) {
    println!("\n{}", "=".repeat(60).cyan());
    println!("{}", "Email Breach Check Result".bold().cyan());
    println!("{}", "=".repeat(60).cyan());
    println!("Email: {}\n", result.email.cyan());

    if result.is_compromised {
        println!("{} This email was found in {} data breach{}!",
            "WARNING:".red().bold(),
            result.breach_count.to_string().red(),
            if result.breach_count > 1 { "es" } else { "" }
        );

        println!("\n{}", "Breaches:".bold());
        for breach in &result.breaches {
            println!("  {} {}", "●".red(), breach);
        }

        println!("\n  Total records exposed: {}",
            result.total_records_exposed.to_string().red()
        );

        println!("\n{}", "Recommendations:".bold().yellow());
        println!("  1. Change passwords for affected services");
        println!("  2. Enable two-factor authentication");
        println!("  3. Monitor for suspicious activity");
    } else {
        println!("{} This email was not found in known data breaches.",
            "GOOD:".green().bold()
        );
    }

    println!("\n  Checked at: {}", result.checked_at.format("%Y-%m-%d %H:%M:%S UTC"));
}

/// Display breach info
fn display_breach_info(breach: &Breach) {
    println!("\n{}", "=".repeat(60).cyan());
    println!("{}", format!("Breach: {}", breach.title).bold().cyan());
    println!("{}", "=".repeat(60).cyan());

    println!("\n{}", "Details:".bold());
    println!("  Name: {}", breach.name);
    println!("  Domain: {}", breach.domain);
    println!("  Breach Date: {}", breach.breach_date.red());
    println!("  Records: {}", format_number(breach.pwn_count).yellow());

    println!("\n{}", "Data Types Exposed:".bold());
    for data_type in &breach.data_classes {
        println!("  {} {}", "●".red(), data_type);
    }

    println!("\n{}", "Status:".bold());
    println!("  Verified: {}", if breach.is_verified { "Yes".green() } else { "No".yellow() });
    println!("  Sensitive: {}", if breach.is_sensitive { "Yes".red() } else { "No".green() });
    println!("  Fabricated: {}", if breach.is_fabricated { "Yes".red() } else { "No".green() });
    println!("  Spam List: {}", if breach.is_spam_list { "Yes".yellow() } else { "No".green() });

    // Strip HTML from description for display
    let desc = breach.description
        .replace("<a href=\"", "[")
        .replace("\" target=\"_blank\" rel=\"noopener\">", "](")
        .replace("</a>", ")");
    let desc = regex_lite::Regex::new(r"<[^>]+>").unwrap().replace_all(&desc, "");

    println!("\n{}", "Description:".bold());
    println!("  {}", desc);
}

/// Format large numbers with commas
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let checker = CredentialChecker::new(cli.api_key)?;

    match cli.command {
        Commands::Password { password } => {
            let result = checker.check_password(&password).await?;
            display_password_result(&result);
        }
        Commands::Email { email, include_unverified } => {
            let result = checker.check_email(&email, include_unverified).await?;
            display_email_result(&result);
        }
        Commands::BulkPasswords { input, output, delay_ms } => {
            checker.bulk_check_passwords(input, output, delay_ms).await?;
        }
        Commands::BulkEmails { input, output, delay_ms } => {
            checker.bulk_check_emails(input, output, delay_ms).await?;
        }
        Commands::BreachInfo { name } => {
            let breach = checker.get_breach_info(&name).await?;
            display_breach_info(&breach);
        }
        Commands::ListBreaches { domain, limit } => {
            let breaches = checker.list_breaches(domain.as_deref()).await?;
            let breaches: Vec<_> = match limit {
                Some(l) => breaches.into_iter().take(l).collect(),
                None => breaches,
            };

            println!("\n{}", "=".repeat(60).cyan());
            println!("{}", "Known Data Breaches".bold().cyan());
            println!("{}", "=".repeat(60).cyan());
            println!("Total: {} breaches\n", breaches.len().to_string().yellow());

            for breach in &breaches {
                let verified = if breach.is_verified { "✓".green() } else { "?".yellow() };
                println!("  {} {} - {} ({} records)",
                    verified,
                    breach.name.bold(),
                    breach.breach_date,
                    format_number(breach.pwn_count)
                );
            }
        }
        Commands::Pastes { email } => {
            let pastes = checker.check_pastes(&email).await?;

            println!("\n{}", "=".repeat(60).cyan());
            println!("{}", "Paste Check Result".bold().cyan());
            println!("{}", "=".repeat(60).cyan());
            println!("Email: {}\n", email.cyan());

            if pastes.is_empty() {
                println!("{} No pastes found for this email.", "GOOD:".green().bold());
            } else {
                println!("{} Found in {} paste{}!",
                    "WARNING:".red().bold(),
                    pastes.len(),
                    if pastes.len() > 1 { "s" } else { "" }
                );

                for paste in &pastes {
                    println!("\n  Source: {}", paste.source);
                    println!("  ID: {}", paste.id);
                    if let Some(ref title) = paste.title {
                        println!("  Title: {}", title);
                    }
                    if let Some(date) = paste.date {
                        println!("  Date: {}", date.format("%Y-%m-%d"));
                    }
                    println!("  Email count: {}", paste.email_count);
                }
            }
        }
    }

    Ok(())
}
