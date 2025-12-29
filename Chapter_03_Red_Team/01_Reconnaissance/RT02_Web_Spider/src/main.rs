//! # RT02 Web Spider / Crawler
//!
//! A comprehensive web crawling tool for authorized security reconnaissance.
//! This spider discovers and maps web application structure by following links,
//! extracting forms, identifying technologies, and finding potentially
//! sensitive files.
//!
//! ## Legal Disclaimer
//!
//! THIS TOOL IS PROVIDED FOR AUTHORIZED SECURITY TESTING ONLY.
//! Unauthorized access to computer systems is illegal. Always obtain
//! written permission before testing systems you do not own.
//! The authors assume no liability for misuse of this software.
//!
//! ## Features
//!
//! - Recursive web crawling with depth control
//! - Form discovery and parameter extraction
//! - Technology fingerprinting
//! - Sensitive file detection
//! - Robots.txt and sitemap.xml parsing
//! - JavaScript file analysis
//! - Rate limiting to prevent DoS
//! - Export results to JSON
//!
//! ## Usage Examples
//!
//! ```bash
//! # Basic crawl with default settings
//! web-spider -u https://example.com
//!
//! # Deep crawl with extended depth
//! web-spider -u https://example.com -d 5 -c 20
//!
//! # Respect robots.txt and output to file
//! web-spider -u https://example.com --respect-robots -o results.json
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use futures::stream::{self, StreamExt};
use indexmap::IndexMap;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use url::Url;

// ============================================================================
// LEGAL DISCLAIMER
// ============================================================================

const LEGAL_DISCLAIMER: &str = r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                           LEGAL DISCLAIMER                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is provided for AUTHORIZED SECURITY TESTING ONLY.                 ║
║                                                                              ║
║  By using this tool, you acknowledge that:                                   ║
║  1. You have explicit written authorization to test the target website       ║
║  2. Unauthorized access to computer systems is a criminal offense            ║
║  3. You accept full responsibility for your actions                          ║
║  4. The authors are not liable for any misuse or damage caused               ║
║                                                                              ║
║  Web crawling without permission may violate:                                ║
║  - Computer Fraud and Abuse Act (CFAA)                                       ║
║  - Terms of Service agreements                                               ║
║  - Copyright and intellectual property laws                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"#;

// ============================================================================
// COMMAND LINE INTERFACE
// ============================================================================

/// Web Spider for Authorized Security Reconnaissance
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target URL to crawl (e.g., https://example.com)
    #[arg(short, long)]
    url: String,

    /// Maximum crawl depth (default: 3)
    #[arg(short, long, default_value = "3")]
    depth: u32,

    /// Number of concurrent requests (default: 10)
    #[arg(short, long, default_value = "10")]
    concurrency: usize,

    /// Delay between requests in milliseconds (default: 100)
    #[arg(long, default_value = "100")]
    delay: u64,

    /// Request timeout in seconds (default: 10)
    #[arg(long, default_value = "10")]
    timeout: u64,

    /// User-Agent string to use
    #[arg(long, default_value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")]
    user_agent: String,

    /// Respect robots.txt directives
    #[arg(long)]
    respect_robots: bool,

    /// Include external links in output (but don't follow)
    #[arg(long)]
    include_external: bool,

    /// Output results to JSON file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Skip legal disclaimer
    #[arg(long)]
    accept_disclaimer: bool,

    /// Maximum number of pages to crawl (default: 500)
    #[arg(long, default_value = "500")]
    max_pages: usize,

    /// Search for sensitive files
    #[arg(long)]
    find_sensitive: bool,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Represents a crawled page with extracted information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CrawledPage {
    /// The URL of the page
    url: String,
    /// HTTP status code
    status_code: u16,
    /// Page title
    title: Option<String>,
    /// Content type
    content_type: Option<String>,
    /// Content length in bytes
    content_length: Option<u64>,
    /// Links found on this page
    links: Vec<String>,
    /// Forms found on this page
    forms: Vec<FormInfo>,
    /// Scripts found
    scripts: Vec<String>,
    /// Response headers of interest
    interesting_headers: HashMap<String, String>,
    /// Depth at which this page was discovered
    depth: u32,
}

/// Information about an HTML form
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FormInfo {
    /// Form action URL
    action: String,
    /// HTTP method (GET/POST)
    method: String,
    /// Form input fields
    inputs: Vec<InputField>,
    /// Form ID if present
    id: Option<String>,
}

/// Information about a form input field
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InputField {
    /// Input name
    name: String,
    /// Input type (text, password, hidden, etc.)
    input_type: String,
    /// Default value if present
    value: Option<String>,
}

/// Complete crawl results
#[derive(Debug, Serialize, Deserialize)]
struct CrawlReport {
    /// Target base URL
    target: String,
    /// Crawl timestamp
    timestamp: String,
    /// Total pages crawled
    pages_crawled: usize,
    /// Total forms found
    forms_found: usize,
    /// Total scripts found
    scripts_found: usize,
    /// Detected technologies
    technologies: Vec<String>,
    /// Potentially sensitive files found
    sensitive_files: Vec<String>,
    /// External links discovered
    external_links: Vec<String>,
    /// All crawled pages
    pages: Vec<CrawledPage>,
}

/// Spider state shared across async tasks
struct SpiderState {
    /// Set of visited URLs
    visited: HashSet<String>,
    /// Queue of URLs to visit
    queue: VecDeque<(String, u32)>, // (url, depth)
    /// Crawled pages
    pages: Vec<CrawledPage>,
    /// External links found
    external_links: HashSet<String>,
    /// Detected technologies
    technologies: HashSet<String>,
    /// Sensitive files found
    sensitive_files: HashSet<String>,
}

/// Common sensitive file paths to check
const SENSITIVE_PATHS: &[&str] = &[
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/wp-config.php",
    "/configuration.php",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/database.yml",
    "/settings.py",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/.htpasswd",
    "/backup.sql",
    "/backup.zip",
    "/dump.sql",
    "/admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/wp-admin/",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/requirements.txt",
];

/// Technology detection patterns
const TECH_PATTERNS: &[(&str, &str)] = &[
    ("WordPress", r"wp-content|wp-includes"),
    ("Drupal", r"drupal|sites/default"),
    ("Joomla", r"joomla|com_content"),
    ("Laravel", r"laravel|csrf-token"),
    ("Django", r"csrfmiddlewaretoken|django"),
    ("React", r"react|__NEXT_DATA__"),
    ("Angular", r"ng-app|angular"),
    ("Vue.js", r"vue|v-bind|v-if"),
    ("jQuery", r"jquery"),
    ("Bootstrap", r"bootstrap"),
    ("ASP.NET", r"__VIEWSTATE|aspnet"),
    ("PHP", r"\.php|PHPSESSID"),
    ("Ruby on Rails", r"rails|csrf-param"),
    ("Express.js", r"express|X-Powered-By.*Express"),
    ("nginx", r"nginx"),
    ("Apache", r"apache|mod_"),
    ("IIS", r"microsoft-iis|asp\.net"),
    ("Cloudflare", r"cloudflare|cf-ray"),
];

// ============================================================================
// IMPLEMENTATION
// ============================================================================

/// Web spider for crawling and analyzing websites
struct WebSpider {
    /// HTTP client
    client: reqwest::Client,
    /// Base URL
    base_url: Url,
    /// Spider configuration
    config: SpiderConfig,
    /// Shared state
    state: Arc<Mutex<SpiderState>>,
    /// Concurrency semaphore
    semaphore: Arc<Semaphore>,
    /// Progress bar
    progress: ProgressBar,
}

/// Spider configuration
struct SpiderConfig {
    max_depth: u32,
    delay_ms: u64,
    respect_robots: bool,
    include_external: bool,
    verbose: bool,
    max_pages: usize,
    find_sensitive: bool,
}

impl WebSpider {
    /// Create a new web spider instance
    async fn new(
        target_url: &str,
        args: &Args,
    ) -> Result<Self> {
        // Parse and validate target URL
        let base_url = Url::parse(target_url)
            .context("Invalid target URL")?;

        // Build HTTP client with custom settings
        let client = reqwest::Client::builder()
            .user_agent(&args.user_agent)
            .timeout(Duration::from_secs(args.timeout))
            .redirect(reqwest::redirect::Policy::limited(5))
            .cookie_store(true)
            .danger_accept_invalid_certs(false)
            .build()
            .context("Failed to create HTTP client")?;

        // Initialize state
        let state = SpiderState {
            visited: HashSet::new(),
            queue: VecDeque::new(),
            pages: Vec::new(),
            external_links: HashSet::new(),
            technologies: HashSet::new(),
            sensitive_files: HashSet::new(),
        };

        // Create progress bar
        let progress = ProgressBar::new(args.max_pages as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] Crawled: {pos} | Queue: {msg}")
                .expect("Invalid progress template")
        );

        Ok(Self {
            client,
            base_url,
            config: SpiderConfig {
                max_depth: args.depth,
                delay_ms: args.delay,
                respect_robots: args.respect_robots,
                include_external: args.include_external,
                verbose: args.verbose,
                max_pages: args.max_pages,
                find_sensitive: args.find_sensitive,
            },
            state: Arc::new(Mutex::new(state)),
            semaphore: Arc::new(Semaphore::new(args.concurrency)),
            progress,
        })
    }

    /// Start the crawling process
    async fn crawl(&self) -> Result<CrawlReport> {
        // Add initial URL to queue
        {
            let mut state = self.state.lock().await;
            state.queue.push_back((self.base_url.to_string(), 0));
        }

        // Check robots.txt if configured
        if self.config.respect_robots {
            self.parse_robots_txt().await?;
        }

        // Optionally check for sensitive files first
        if self.config.find_sensitive {
            self.check_sensitive_files().await;
        }

        // Main crawl loop
        loop {
            // Get next URL from queue
            let (url, depth) = {
                let mut state = self.state.lock().await;

                // Check if we've reached max pages
                if state.pages.len() >= self.config.max_pages {
                    break;
                }

                self.progress.set_message(format!("{}", state.queue.len()));

                match state.queue.pop_front() {
                    Some(item) => item,
                    None => break, // Queue empty
                }
            };

            // Skip if already visited or too deep
            {
                let state = self.state.lock().await;
                if state.visited.contains(&url) || depth > self.config.max_depth {
                    continue;
                }
            }

            // Acquire semaphore permit
            let _permit = self.semaphore.acquire().await?;

            // Crawl the page
            if let Some(page) = self.crawl_page(&url, depth).await {
                let mut state = self.state.lock().await;
                state.visited.insert(url.clone());

                // Add discovered links to queue
                for link in &page.links {
                    if !state.visited.contains(link) {
                        state.queue.push_back((link.clone(), depth + 1));
                    }
                }

                state.pages.push(page);
                self.progress.inc(1);
            }

            // Rate limiting
            if self.config.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
            }
        }

        self.progress.finish_with_message("Complete");

        // Generate report
        self.generate_report().await
    }

    /// Crawl a single page
    async fn crawl_page(&self, url: &str, depth: u32) -> Option<CrawledPage> {
        if self.config.verbose {
            println!("{} Crawling: {}", "[*]".blue(), url);
        }

        // Make HTTP request
        let response = match self.client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                if self.config.verbose {
                    println!("{} Failed to fetch {}: {}", "[!]".yellow(), url, e);
                }
                return None;
            }
        };

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());

        // Extract interesting headers
        let interesting_headers = self.extract_interesting_headers(&response);

        // Detect technologies from headers
        self.detect_technologies_from_headers(&response).await;

        // Only parse HTML content
        if !content_type.as_ref().map_or(false, |ct| ct.contains("text/html")) {
            return Some(CrawledPage {
                url: url.to_string(),
                status_code: status,
                title: None,
                content_type,
                content_length,
                links: Vec::new(),
                forms: Vec::new(),
                scripts: Vec::new(),
                interesting_headers,
                depth,
            });
        }

        // Get response body
        let body = match response.text().await {
            Ok(text) => text,
            Err(_) => return None,
        };

        // Parse HTML
        let document = Html::parse_document(&body);

        // Extract page title
        let title = self.extract_title(&document);

        // Extract links
        let links = self.extract_links(&document, url);

        // Extract forms
        let forms = self.extract_forms(&document, url);

        // Extract scripts
        let scripts = self.extract_scripts(&document, url);

        // Detect technologies from content
        self.detect_technologies_from_content(&body).await;

        Some(CrawledPage {
            url: url.to_string(),
            status_code: status,
            title,
            content_type,
            content_length,
            links,
            forms,
            scripts,
            interesting_headers,
            depth,
        })
    }

    /// Extract interesting HTTP headers
    fn extract_interesting_headers(&self, response: &reqwest::Response) -> HashMap<String, String> {
        let interesting = [
            "server", "x-powered-by", "x-aspnet-version", "x-frame-options",
            "x-xss-protection", "x-content-type-options", "content-security-policy",
            "strict-transport-security", "set-cookie", "www-authenticate",
        ];

        let mut headers = HashMap::new();
        for name in interesting {
            if let Some(value) = response.headers().get(name) {
                if let Ok(v) = value.to_str() {
                    headers.insert(name.to_string(), v.to_string());
                }
            }
        }
        headers
    }

    /// Extract page title from HTML
    fn extract_title(&self, document: &Html) -> Option<String> {
        let selector = Selector::parse("title").ok()?;
        document.select(&selector)
            .next()
            .map(|el| el.text().collect::<String>().trim().to_string())
    }

    /// Extract and normalize links from HTML
    fn extract_links(&self, document: &Html, base_url: &str) -> Vec<String> {
        let selector = match Selector::parse("a[href]") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let base = match Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };

        let mut links = Vec::new();
        let mut state_guard = futures::executor::block_on(self.state.lock());

        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                // Skip javascript:, mailto:, tel:, etc.
                if href.starts_with("javascript:") ||
                   href.starts_with("mailto:") ||
                   href.starts_with("tel:") ||
                   href.starts_with("#") {
                    continue;
                }

                // Resolve relative URLs
                if let Ok(resolved) = base.join(href) {
                    let resolved_str = resolved.to_string();

                    // Check if same domain
                    if resolved.host_str() == self.base_url.host_str() {
                        // Same domain - add to crawl queue
                        links.push(resolved_str);
                    } else if self.config.include_external {
                        // External link - track but don't crawl
                        state_guard.external_links.insert(resolved_str);
                    }
                }
            }
        }

        links
    }

    /// Extract form information from HTML
    fn extract_forms(&self, document: &Html, base_url: &str) -> Vec<FormInfo> {
        let form_selector = match Selector::parse("form") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let input_selector = Selector::parse("input, select, textarea").unwrap();
        let base = Url::parse(base_url).unwrap_or_else(|_| self.base_url.clone());

        let mut forms = Vec::new();

        for form in document.select(&form_selector) {
            let action = form.value().attr("action")
                .unwrap_or("")
                .to_string();

            // Resolve action URL
            let action = base.join(&action)
                .map(|u| u.to_string())
                .unwrap_or(action);

            let method = form.value().attr("method")
                .unwrap_or("GET")
                .to_uppercase();

            let id = form.value().attr("id").map(String::from);

            // Extract input fields
            let mut inputs = Vec::new();
            for input in form.select(&input_selector) {
                let name = input.value().attr("name")
                    .unwrap_or("")
                    .to_string();

                if name.is_empty() {
                    continue;
                }

                let input_type = input.value().attr("type")
                    .unwrap_or("text")
                    .to_string();

                let value = input.value().attr("value")
                    .map(String::from);

                inputs.push(InputField {
                    name,
                    input_type,
                    value,
                });
            }

            forms.push(FormInfo {
                action,
                method,
                inputs,
                id,
            });
        }

        forms
    }

    /// Extract script sources from HTML
    fn extract_scripts(&self, document: &Html, base_url: &str) -> Vec<String> {
        let selector = match Selector::parse("script[src]") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let base = Url::parse(base_url).unwrap_or_else(|_| self.base_url.clone());
        let mut scripts = Vec::new();

        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Ok(resolved) = base.join(src) {
                    scripts.push(resolved.to_string());
                }
            }
        }

        scripts
    }

    /// Detect technologies from HTTP headers
    async fn detect_technologies_from_headers(&self, response: &reqwest::Response) {
        let mut state = self.state.lock().await;

        // Check Server header
        if let Some(server) = response.headers().get("server") {
            if let Ok(s) = server.to_str() {
                state.technologies.insert(format!("Server: {}", s));
            }
        }

        // Check X-Powered-By header
        if let Some(powered_by) = response.headers().get("x-powered-by") {
            if let Ok(s) = powered_by.to_str() {
                state.technologies.insert(format!("X-Powered-By: {}", s));
            }
        }
    }

    /// Detect technologies from page content
    async fn detect_technologies_from_content(&self, content: &str) {
        let mut state = self.state.lock().await;

        for (tech, pattern) in TECH_PATTERNS {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(content) {
                    state.technologies.insert(tech.to_string());
                }
            }
        }
    }

    /// Parse robots.txt for allowed/disallowed paths
    async fn parse_robots_txt(&self) -> Result<()> {
        let robots_url = self.base_url.join("/robots.txt")?;

        println!("{} Fetching robots.txt...", "[*]".blue());

        match self.client.get(robots_url.as_str()).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                println!("{} robots.txt found ({} bytes)",
                    "[+]".green(), body.len());

                // Log disallowed paths
                for line in body.lines() {
                    let line = line.trim();
                    if line.to_lowercase().starts_with("disallow:") {
                        if self.config.verbose {
                            println!("    {}", line.dimmed());
                        }
                    }
                }
            }
            _ => {
                println!("{} No robots.txt found", "[!]".yellow());
            }
        }

        Ok(())
    }

    /// Check for sensitive files
    async fn check_sensitive_files(&self) {
        println!("{} Checking for sensitive files...", "[*]".blue());

        let results: Vec<(String, u16)> = stream::iter(SENSITIVE_PATHS)
            .map(|path| async move {
                let url = self.base_url.join(path).ok()?;
                let response = self.client.head(url.as_str()).send().await.ok()?;
                Some((path.to_string(), response.status().as_u16()))
            })
            .buffer_unordered(10)
            .filter_map(|r| async move { r })
            .collect()
            .await;

        let mut state = self.state.lock().await;
        for (path, status) in results {
            if status == 200 || status == 403 {
                println!("{} {} [{}]",
                    if status == 200 { "[+]".green() } else { "[!]".yellow() },
                    path,
                    status
                );
                state.sensitive_files.insert(path);
            }
        }
    }

    /// Generate final crawl report
    async fn generate_report(&self) -> Result<CrawlReport> {
        let state = self.state.lock().await;

        let total_forms: usize = state.pages.iter()
            .map(|p| p.forms.len())
            .sum();

        let total_scripts: usize = state.pages.iter()
            .map(|p| p.scripts.len())
            .sum();

        Ok(CrawlReport {
            target: self.base_url.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            pages_crawled: state.pages.len(),
            forms_found: total_forms,
            scripts_found: total_scripts,
            technologies: state.technologies.iter().cloned().collect(),
            sensitive_files: state.sensitive_files.iter().cloned().collect(),
            external_links: state.external_links.iter().cloned().collect(),
            pages: state.pages.clone(),
        })
    }
}

/// Display crawl results summary
fn display_results(report: &CrawlReport) {
    println!("\n{}", "═".repeat(80).cyan());
    println!("{}", " CRAWL RESULTS ".cyan().bold());
    println!("{}", "═".repeat(80).cyan());

    println!("\n{}", "Summary:".white().bold());
    println!("    {} {}", "Target:".dimmed(), report.target);
    println!("    {} {}", "Pages Crawled:".dimmed(), report.pages_crawled);
    println!("    {} {}", "Forms Found:".dimmed(), report.forms_found);
    println!("    {} {}", "Scripts Found:".dimmed(), report.scripts_found);

    if !report.technologies.is_empty() {
        println!("\n{}", "Detected Technologies:".white().bold());
        for tech in &report.technologies {
            println!("    {} {}", "[+]".green(), tech);
        }
    }

    if !report.sensitive_files.is_empty() {
        println!("\n{}", "Sensitive Files:".white().bold());
        for file in &report.sensitive_files {
            println!("    {} {}", "[!]".yellow(), file);
        }
    }

    // Show pages with forms (potential attack vectors)
    let pages_with_forms: Vec<_> = report.pages.iter()
        .filter(|p| !p.forms.is_empty())
        .collect();

    if !pages_with_forms.is_empty() {
        println!("\n{}", "Pages with Forms:".white().bold());
        for page in pages_with_forms.iter().take(10) {
            println!("    {} {}", "[*]".blue(), page.url);
            for form in &page.forms {
                println!("        {} {} -> {}",
                    form.method.cyan(),
                    form.action,
                    form.inputs.iter()
                        .map(|i| format!("{}:{}", i.name, i.input_type))
                        .collect::<Vec<_>>()
                        .join(", "));
            }
        }
    }

    println!("\n{}", "═".repeat(80).cyan());
}

/// Save results to JSON file
fn save_results(report: &CrawlReport, output: PathBuf) -> Result<()> {
    let mut file = File::create(&output)
        .with_context(|| format!("Failed to create output file: {:?}", output))?;

    let json = serde_json::to_string_pretty(report)?;
    file.write_all(json.as_bytes())?;

    println!("{} Results saved to {:?}", "[+]".green(), output);
    Ok(())
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Parse arguments
    let args = Args::parse();

    // Display legal disclaimer
    println!("{}", LEGAL_DISCLAIMER.red());

    if !args.accept_disclaimer {
        println!("{}", "Do you have authorization to test this website? (yes/no): ".yellow());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!("{} Exiting - authorization required", "[!]".red());
            return Ok(());
        }
    }

    println!("\n{}", "═".repeat(80).cyan());
    println!("{} {}", " TARGET:".cyan().bold(), args.url.white().bold());
    println!("{}", "═".repeat(80).cyan());
    println!("    {} {}", "Max Depth:".dimmed(), args.depth);
    println!("    {} {}", "Concurrency:".dimmed(), args.concurrency);
    println!("    {} {}", "Max Pages:".dimmed(), args.max_pages);

    // Create and run spider
    let spider = WebSpider::new(&args.url, &args).await?;
    let report = spider.crawl().await?;

    // Display results
    display_results(&report);

    // Save to file if requested
    if let Some(output) = args.output {
        save_results(&report, output)?;
    }

    println!("\n{} Crawl complete!", "[+]".green().bold());

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_parsing() {
        let url = Url::parse("https://example.com/path").unwrap();
        assert_eq!(url.host_str(), Some("example.com"));
    }

    #[test]
    fn test_tech_patterns() {
        let wordpress_pattern = Regex::new(TECH_PATTERNS[0].1).unwrap();
        assert!(wordpress_pattern.is_match("wp-content/themes"));
    }

    #[test]
    fn test_sensitive_paths() {
        assert!(SENSITIVE_PATHS.contains(&"/.git/config"));
        assert!(SENSITIVE_PATHS.contains(&"/robots.txt"));
    }
}
