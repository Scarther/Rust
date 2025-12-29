# Red Team: Reconnaissance

## Overview

Reconnaissance is the first phase of any security assessment. These tools help gather information about targets.

## Projects

| ID | Name | Description | MITRE ATT&CK |
|----|------|-------------|--------------|
| RT01 | Subdomain Enumerator | Find subdomains via DNS and wordlists | T1596.001 |
| RT02 | Web Directory Scanner | Brute force web directories | T1595.003 |
| RT03 | Port Scanner Pro | Advanced port scanning with service detection | T1046 |
| RT04 | OSINT Collector | Gather public information | T1593 |
| RT05 | Technology Fingerprinter | Identify web technologies | T1592.004 |

## RT01: Subdomain Enumerator

A tool to discover subdomains using multiple techniques:

```rust
//! Subdomain Enumerator - Find hidden subdomains
//!
//! Techniques:
//! - DNS brute force with wordlist
//! - Certificate transparency logs
//! - Search engine scraping

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::thread;

struct SubdomainEnumerator {
    domain: String,
    wordlist: Vec<String>,
    threads: usize,
    found: Arc<Mutex<Vec<String>>>,
}

impl SubdomainEnumerator {
    fn new(domain: &str, wordlist: Vec<String>) -> Self {
        Self {
            domain: domain.to_string(),
            wordlist,
            threads: 50,
            found: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn enumerate(&self) -> Vec<String> {
        let chunk_size = (self.wordlist.len() / self.threads).max(1);
        let mut handles = vec![];

        for chunk in self.wordlist.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let domain = self.domain.clone();
            let found = Arc::clone(&self.found);

            handles.push(thread::spawn(move || {
                for word in chunk {
                    let subdomain = format!("{}.{}", word, domain);
                    if Self::resolves(&subdomain) {
                        found.lock().unwrap().push(subdomain);
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        self.found.lock().unwrap().clone()
    }

    fn resolves(subdomain: &str) -> bool {
        format!("{}:80", subdomain).to_socket_addrs().is_ok()
    }
}
```

## RT02: Web Directory Scanner

Brute force directories and files on web servers:

```rust
//! Web Directory Scanner
//!
//! Features:
//! - Async HTTP requests
//! - Custom wordlists
//! - Response analysis
//! - Recursive scanning

use reqwest::Client;
use tokio;

struct DirScanner {
    base_url: String,
    wordlist: Vec<String>,
    client: Client,
}

impl DirScanner {
    async fn scan(&self) -> Vec<ScanResult> {
        let mut results = Vec::new();

        for word in &self.wordlist {
            let url = format!("{}/{}", self.base_url, word);

            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status != 404 {
                        results.push(ScanResult {
                            path: word.clone(),
                            status,
                            size: resp.content_length(),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        results
    }
}

struct ScanResult {
    path: String,
    status: u16,
    size: Option<u64>,
}
```

## Usage Examples

```bash
# Subdomain enumeration
./subdomain_enum -d example.com -w subdomains.txt -t 100

# Directory scanning
./dir_scanner -u https://example.com -w directories.txt --recursive

# Combined reconnaissance
./recon_suite -d example.com --full-scan
```

## Wordlists

Recommended wordlists for reconnaissance:

| Type | Source | Size |
|------|--------|------|
| Subdomains | SecLists | 100k+ |
| Directories | DirBuster | 220k |
| Files | Common extensions | 10k |

## Detection Countermeasures (Blue Team)

These techniques can be detected by:
- DNS query logging (high volume queries)
- Web application firewalls (brute force detection)
- Rate limiting
- Honeypot subdomains/directories
