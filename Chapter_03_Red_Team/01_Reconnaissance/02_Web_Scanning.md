# Web Scanning in Rust

## Overview

Web scanning involves discovering directories, files, and vulnerabilities on web applications. This lesson covers building HTTP-based reconnaissance tools.

---

## Learning Objectives

- Make HTTP requests with reqwest
- Implement directory brute-forcing
- Extract links and crawl websites
- Detect common vulnerabilities
- Handle authentication and cookies

---

## HTTP Fundamentals

### Basic HTTP Client

```toml
# Cargo.toml
[dependencies]
reqwest = { version = "0.11", features = ["blocking", "json"] }
```

```rust
use reqwest::blocking::Client;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)  // For testing only!
        .build()?;

    let response = client.get("http://example.com").send()?;

    println!("Status: {}", response.status());
    println!("Headers:");
    for (name, value) in response.headers() {
        println!("  {}: {:?}", name, value);
    }

    Ok(())
}
```

### Async HTTP Client

```rust
use reqwest::Client;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Security Scanner)")
        .build()?;

    let response = client
        .get("https://httpbin.org/get")
        .header("X-Custom-Header", "test")
        .send()
        .await?;

    println!("Status: {}", response.status());
    let body = response.text().await?;
    println!("Body length: {} bytes", body.len());

    Ok(())
}
```

---

## Directory Scanner

### Basic Directory Brute-Forcer

```rust
use reqwest::blocking::Client;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Duration;

fn load_wordlist(path: &str) -> Vec<String> {
    let file = File::open(path).expect("Cannot open wordlist");
    BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn check_path(client: &Client, base_url: &str, path: &str) -> Option<(String, u16, usize)> {
    let url = format!("{}/{}", base_url.trim_end_matches('/'), path);

    match client.get(&url).send() {
        Ok(response) => {
            let status = response.status().as_u16();

            // Filter interesting responses
            if status != 404 {
                let size = response.content_length().unwrap_or(0) as usize;
                Some((url, status, size))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn main() {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let base_url = "http://target.local";

    // Common directories to check
    let wordlist = vec![
        "admin", "login", "dashboard", "api", "backup",
        "config", "db", "test", "uploads", "images",
        "css", "js", "includes", "private", "secret",
        ".git", ".env", "robots.txt", "sitemap.xml",
        "wp-admin", "phpmyadmin", "administrator",
    ];

    println!("Scanning {} with {} paths", base_url, wordlist.len());
    println!("{}", "=".repeat(60));
    println!("{:<40} {:>6} {:>10}", "URL", "STATUS", "SIZE");
    println!("{}", "-".repeat(60));

    for path in wordlist {
        if let Some((url, status, size)) = check_path(&client, base_url, &path) {
            let status_indicator = match status {
                200..=299 => "[+]",
                300..=399 => "[R]",
                401 | 403 => "[!]",
                _ => "[-]",
            };
            println!("{} {:<37} {:>6} {:>10}", status_indicator, url, status, size);
        }
    }
}
```

### Async Directory Scanner with Concurrency

```rust
use reqwest::Client;
use futures::stream::{self, StreamExt};
use std::time::Duration;
use std::sync::Arc;

#[derive(Debug)]
struct ScanResult {
    url: String,
    status: u16,
    size: u64,
    redirect: Option<String>,
}

async fn check_path(
    client: &Client,
    base_url: &str,
    path: &str,
) -> Option<ScanResult> {
    let url = format!("{}/{}", base_url.trim_end_matches('/'), path);

    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();

            if status != 404 {
                let redirect = response.headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let size = response.content_length().unwrap_or(0);

                Some(ScanResult {
                    url,
                    status,
                    size,
                    redirect,
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

#[tokio::main]
async fn main() {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let client = Arc::new(client);
    let base_url = "http://target.local";

    let wordlist: Vec<&str> = vec![
        "admin", "login", "api", "config", "backup",
        "test", "dev", "staging", "uploads", ".git",
        ".env", "robots.txt", "sitemap.xml", "wp-admin",
    ];

    println!("Async scanning {} with {} paths", base_url, wordlist.len());

    let results: Vec<Option<ScanResult>> = stream::iter(wordlist)
        .map(|path| {
            let client = client.clone();
            async move {
                check_path(&client, base_url, path).await
            }
        })
        .buffer_unordered(20)  // 20 concurrent requests
        .collect()
        .await;

    println!("\n{:<50} {:>6} {:>8}", "URL", "STATUS", "SIZE");
    println!("{}", "-".repeat(70));

    for result in results.into_iter().flatten() {
        print!("{:<50} {:>6} {:>8}",
            result.url, result.status, result.size);

        if let Some(redirect) = result.redirect {
            print!(" -> {}", redirect);
        }
        println!();
    }
}
```

---

## Web Crawler

### Link Extractor and Crawler

```rust
use reqwest::blocking::Client;
use std::collections::{HashSet, VecDeque};
use regex::Regex;

fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let re = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();

    re.captures_iter(html)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str())
        .filter_map(|link| {
            if link.starts_with("http") {
                Some(link.to_string())
            } else if link.starts_with('/') {
                let base = base_url.trim_end_matches('/');
                Some(format!("{}{}", base, link))
            } else {
                None
            }
        })
        .filter(|link| link.contains(base_url.split("//").last().unwrap_or("")))
        .collect()
}

fn crawl(base_url: &str, max_depth: usize) -> HashSet<String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    queue.push_back((base_url.to_string(), 0));

    while let Some((url, depth)) = queue.pop_front() {
        if depth > max_depth || visited.contains(&url) {
            continue;
        }

        visited.insert(url.clone());
        println!("[{}] Crawling: {}", depth, url);

        if let Ok(response) = client.get(&url).send() {
            if let Ok(body) = response.text() {
                let links = extract_links(&body, base_url);

                for link in links {
                    if !visited.contains(&link) {
                        queue.push_back((link, depth + 1));
                    }
                }
            }
        }
    }

    visited
}

fn main() {
    let target = "http://target.local";
    let pages = crawl(target, 2);

    println!("\n=== Discovered Pages ===");
    for page in &pages {
        println!("  {}", page);
    }
    println!("\nTotal: {} pages", pages.len());
}
```

---

## Vulnerability Checks

### Security Header Checker

```rust
use reqwest::blocking::Client;
use std::collections::HashMap;

struct SecurityHeaders {
    present: Vec<String>,
    missing: Vec<String>,
    warnings: Vec<String>,
}

fn check_security_headers(url: &str) -> Result<SecurityHeaders, String> {
    let client = Client::new();

    let response = client.get(url)
        .send()
        .map_err(|e| e.to_string())?;

    let headers = response.headers();
    let mut result = SecurityHeaders {
        present: Vec::new(),
        missing: Vec::new(),
        warnings: Vec::new(),
    };

    let required_headers = vec![
        ("strict-transport-security", "HSTS"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-xss-protection", "X-XSS-Protection"),
        ("content-security-policy", "CSP"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ];

    for (header, name) in required_headers {
        if let Some(value) = headers.get(header) {
            result.present.push(format!("{}: {:?}", name, value));

            // Check for weak configurations
            let value_str = value.to_str().unwrap_or("");
            if header == "x-xss-protection" && value_str == "0" {
                result.warnings.push(format!("{} is disabled", name));
            }
            if header == "x-frame-options" && value_str.to_uppercase() == "ALLOWALL" {
                result.warnings.push(format!("{} allows framing from anywhere", name));
            }
        } else {
            result.missing.push(name.to_string());
        }
    }

    // Check for information disclosure
    let info_headers = vec!["server", "x-powered-by", "x-aspnet-version"];
    for header in info_headers {
        if let Some(value) = headers.get(header) {
            result.warnings.push(format!("Information disclosure: {}: {:?}", header, value));
        }
    }

    Ok(result)
}

fn main() {
    let url = "https://example.com";

    match check_security_headers(url) {
        Ok(result) => {
            println!("=== Security Header Analysis for {} ===\n", url);

            println!("Present Headers:");
            for h in &result.present {
                println!("  [+] {}", h);
            }

            println!("\nMissing Headers:");
            for h in &result.missing {
                println!("  [-] {}", h);
            }

            if !result.warnings.is_empty() {
                println!("\nWarnings:");
                for w in &result.warnings {
                    println!("  [!] {}", w);
                }
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}
```

### Simple SQL Injection Tester

```rust
use reqwest::blocking::Client;

fn test_sqli(url: &str) -> Vec<String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let payloads = vec![
        ("'", "Single quote"),
        ("\"", "Double quote"),
        ("' OR '1'='1", "Boolean OR"),
        ("' OR '1'='1'--", "Boolean OR with comment"),
        ("1; DROP TABLE users--", "Stacked query"),
        ("' UNION SELECT NULL--", "UNION injection"),
    ];

    let mut findings = Vec::new();

    // Get baseline response
    let baseline = client.get(url).send().ok()
        .and_then(|r| r.text().ok())
        .unwrap_or_default();
    let baseline_len = baseline.len();

    for (payload, description) in payloads {
        let test_url = format!("{}{}", url, urlencoding::encode(payload));

        if let Ok(response) = client.get(&test_url).send() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();

            // Look for SQL error messages
            let error_patterns = vec![
                "sql syntax", "mysql", "sqlite", "postgresql",
                "ora-", "sql server", "syntax error",
                "unclosed quotation", "unterminated string",
            ];

            let has_error = error_patterns.iter()
                .any(|pattern| body.to_lowercase().contains(pattern));

            // Check for significant response changes
            let size_diff = (body.len() as i64 - baseline_len as i64).abs();
            let significant_change = size_diff > baseline_len as i64 / 2;

            if has_error || status == 500 || significant_change {
                findings.push(format!(
                    "[{}] {} - Status: {}, Size diff: {}",
                    description, payload, status, size_diff
                ));
            }
        }
    }

    findings
}

fn main() {
    let target = "http://target.local/search?q=";

    println!("Testing for SQL Injection: {}\n", target);

    let findings = test_sqli(target);

    if findings.is_empty() {
        println!("No obvious SQL injection detected");
    } else {
        println!("Potential SQL Injection found:");
        for finding in findings {
            println!("  {}", finding);
        }
    }
}
```

---

## Complete Web Scanner

```rust
use reqwest::blocking::Client;
use std::time::Duration;

struct WebScanner {
    client: Client,
    target: String,
}

impl WebScanner {
    fn new(target: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap();

        Self {
            client,
            target: target.to_string(),
        }
    }

    fn check_connectivity(&self) -> Result<(u16, String), String> {
        let response = self.client.get(&self.target)
            .send()
            .map_err(|e| e.to_string())?;

        let status = response.status().as_u16();
        let server = response.headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        Ok((status, server))
    }

    fn scan_directories(&self, paths: &[&str]) -> Vec<(String, u16)> {
        let mut results = Vec::new();

        for path in paths {
            let url = format!("{}/{}", self.target.trim_end_matches('/'), path);

            if let Ok(response) = self.client.get(&url).send() {
                let status = response.status().as_u16();
                if status != 404 {
                    results.push((url, status));
                }
            }
        }

        results
    }

    fn check_robots_txt(&self) -> Option<String> {
        let url = format!("{}/robots.txt", self.target.trim_end_matches('/'));

        self.client.get(&url).send().ok()
            .filter(|r| r.status().is_success())
            .and_then(|r| r.text().ok())
    }
}

fn main() {
    let scanner = WebScanner::new("http://target.local");

    println!("=== Web Scanner Report ===\n");

    // Connectivity check
    match scanner.check_connectivity() {
        Ok((status, server)) => {
            println!("[+] Target is reachable");
            println!("    Status: {}", status);
            println!("    Server: {}", server);
        }
        Err(e) => {
            println!("[-] Cannot connect: {}", e);
            return;
        }
    }

    // Directory scan
    println!("\n=== Directory Scan ===");
    let common_paths = vec![
        "admin", "login", "api", "backup", ".git",
        "robots.txt", "sitemap.xml", "wp-admin",
    ];

    for (url, status) in scanner.scan_directories(&common_paths) {
        println!("[+] Found: {} ({})", url, status);
    }

    // Robots.txt
    println!("\n=== robots.txt ===");
    if let Some(content) = scanner.check_robots_txt() {
        for line in content.lines().take(10) {
            println!("    {}", line);
        }
    } else {
        println!("    Not found");
    }
}
```

---

## Exercises

1. **Recursive Spider**: Extend the crawler to respect robots.txt
2. **Form Finder**: Extract and list all forms from discovered pages
3. **Technology Detector**: Identify frameworks (WordPress, Django, etc.)
4. **Screenshot Tool**: Integrate with headless browser for screenshots

---

## Key Takeaways

1. **reqwest is the standard** - Use for all HTTP operations
2. **Async for performance** - Handle many URLs concurrently
3. **Filter responses wisely** - Not just 200 OK matters
4. **Respect targets** - Rate limit and use responsible headers
5. **Check security headers** - Quick wins in assessments

---

[← Previous: Port Scanning](./01_Port_Scanning.md) | [Back to Reconnaissance →](./README.md)
