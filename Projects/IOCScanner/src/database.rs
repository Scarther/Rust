//! IOC Database management

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// IOC Database containing all indicators
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocDatabase {
    #[serde(default)]
    pub version: String,

    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub hashes: Vec<HashIoc>,

    #[serde(default)]
    pub domains: Vec<DomainIoc>,

    #[serde(default)]
    pub ip_addresses: Vec<IpIoc>,

    #[serde(default)]
    pub file_paths: Vec<PathIoc>,

    #[serde(default)]
    pub patterns: Vec<PatternIoc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashIoc {
    pub hash: String,

    #[serde(default = "default_hash_type")]
    pub hash_type: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default = "default_severity")]
    pub severity: String,

    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainIoc {
    pub domain: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default = "default_severity")]
    pub severity: String,

    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIoc {
    pub ip: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default = "default_severity")]
    pub severity: String,

    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathIoc {
    pub path: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default = "default_severity")]
    pub severity: String,

    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternIoc {
    pub pattern: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default = "default_severity")]
    pub severity: String,

    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_hash_type() -> String {
    "sha256".to_string()
}

fn default_severity() -> String {
    "medium".to_string()
}

impl IocDatabase {
    /// Create a new empty database
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            name: "IOC Database".to_string(),
            description: "Custom IOC database".to_string(),
            ..Default::default()
        }
    }

    /// Load database from file (JSON or YAML)
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read database file")?;

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let db: IocDatabase = match ext {
            "json" => serde_json::from_str(&content).context("Failed to parse JSON")?,
            "yaml" | "yml" => serde_yaml::from_str(&content).context("Failed to parse YAML")?,
            _ => {
                // Try JSON first, then YAML
                serde_json::from_str(&content)
                    .or_else(|_| serde_yaml::from_str(&content))
                    .context("Failed to parse database (tried JSON and YAML)")?
            }
        };

        Ok(db)
    }

    /// Save database to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let content = match ext {
            "json" => serde_json::to_string_pretty(self)?,
            _ => serde_yaml::to_string(self)?,
        };

        fs::write(path, content)?;
        Ok(())
    }

    /// Get total IOC count
    pub fn total_count(&self) -> usize {
        self.hashes.len()
            + self.domains.len()
            + self.ip_addresses.len()
            + self.file_paths.len()
            + self.patterns.len()
    }

    /// Add a new IOC
    pub fn add_ioc(
        &mut self,
        ioc_type: &str,
        value: &str,
        description: Option<&str>,
        severity: &str,
    ) -> Result<()> {
        match ioc_type.to_lowercase().as_str() {
            "hash" | "md5" | "sha1" | "sha256" => {
                self.hashes.push(HashIoc {
                    hash: value.to_string(),
                    hash_type: detect_hash_type(value),
                    description: description.map(String::from),
                    severity: severity.to_string(),
                    tags: Vec::new(),
                });
            }
            "domain" => {
                self.domains.push(DomainIoc {
                    domain: value.to_string(),
                    description: description.map(String::from),
                    severity: severity.to_string(),
                    tags: Vec::new(),
                });
            }
            "ip" | "ip_address" => {
                self.ip_addresses.push(IpIoc {
                    ip: value.to_string(),
                    description: description.map(String::from),
                    severity: severity.to_string(),
                    tags: Vec::new(),
                });
            }
            "path" | "file_path" => {
                self.file_paths.push(PathIoc {
                    path: value.to_string(),
                    description: description.map(String::from),
                    severity: severity.to_string(),
                    tags: Vec::new(),
                });
            }
            "pattern" | "regex" => {
                // Validate regex
                regex::Regex::new(value).context("Invalid regex pattern")?;

                self.patterns.push(PatternIoc {
                    pattern: value.to_string(),
                    description: description.map(String::from),
                    severity: severity.to_string(),
                    tags: Vec::new(),
                });
            }
            _ => anyhow::bail!("Unknown IOC type: {}", ioc_type),
        }

        Ok(())
    }

    /// List IOCs
    pub fn list(&self, filter_type: Option<&str>) {
        let filter = filter_type.map(|s| s.to_lowercase());

        println!("\n{}", "IOC DATABASE".bold().underline());
        println!("Name: {}", self.name);
        println!("Version: {}", self.version);
        println!();

        if filter.is_none() || filter.as_deref() == Some("hash") {
            if !self.hashes.is_empty() {
                println!("{}", "Hashes:".cyan().bold());
                for hash in &self.hashes {
                    println!(
                        "  [{}] {} - {}",
                        severity_color(&hash.severity),
                        hash.hash,
                        hash.description.as_deref().unwrap_or("No description")
                    );
                }
                println!();
            }
        }

        if filter.is_none() || filter.as_deref() == Some("domain") {
            if !self.domains.is_empty() {
                println!("{}", "Domains:".cyan().bold());
                for domain in &self.domains {
                    println!(
                        "  [{}] {} - {}",
                        severity_color(&domain.severity),
                        domain.domain,
                        domain.description.as_deref().unwrap_or("No description")
                    );
                }
                println!();
            }
        }

        if filter.is_none() || filter.as_deref() == Some("ip") {
            if !self.ip_addresses.is_empty() {
                println!("{}", "IP Addresses:".cyan().bold());
                for ip in &self.ip_addresses {
                    println!(
                        "  [{}] {} - {}",
                        severity_color(&ip.severity),
                        ip.ip,
                        ip.description.as_deref().unwrap_or("No description")
                    );
                }
                println!();
            }
        }

        if filter.is_none() || filter.as_deref() == Some("path") {
            if !self.file_paths.is_empty() {
                println!("{}", "File Paths:".cyan().bold());
                for path in &self.file_paths {
                    println!(
                        "  [{}] {} - {}",
                        severity_color(&path.severity),
                        path.path,
                        path.description.as_deref().unwrap_or("No description")
                    );
                }
                println!();
            }
        }

        if filter.is_none() || filter.as_deref() == Some("pattern") {
            if !self.patterns.is_empty() {
                println!("{}", "Patterns:".cyan().bold());
                for pattern in &self.patterns {
                    println!(
                        "  [{}] {} - {}",
                        severity_color(&pattern.severity),
                        pattern.pattern,
                        pattern.description.as_deref().unwrap_or("No description")
                    );
                }
                println!();
            }
        }

        println!("Total IOCs: {}", self.total_count());
    }

    /// Import IOCs from a file
    pub fn import(&mut self, path: &Path) -> Result<usize> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mut count = 0;

        match ext {
            "json" => {
                let content = fs::read_to_string(path)?;
                let imported: IocDatabase = serde_json::from_str(&content)?;

                self.hashes.extend(imported.hashes);
                self.domains.extend(imported.domains);
                self.ip_addresses.extend(imported.ip_addresses);
                self.file_paths.extend(imported.file_paths);
                self.patterns.extend(imported.patterns);

                count = imported.total_count();
            }
            "csv" => {
                count = self.import_csv(path)?;
            }
            _ => {
                // Assume plain text with one IOC per line
                count = self.import_text(path)?;
            }
        }

        Ok(count)
    }

    /// Import from CSV
    fn import_csv(&mut self, path: &Path) -> Result<usize> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines().skip(1) {
            // Skip header
            let line = line?;
            let parts: Vec<&str> = line.split(',').collect();

            if parts.len() >= 2 {
                let ioc_type = parts[0].trim();
                let value = parts[1].trim();
                let description = parts.get(2).map(|s| s.trim());
                let severity = parts.get(3).map(|s| s.trim()).unwrap_or("medium");

                if self.add_ioc(ioc_type, value, description, severity).is_ok() {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Import from plain text (one hash per line)
    fn import_text(&mut self, path: &Path) -> Result<usize> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?.trim().to_string();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Detect IOC type from format
            let ioc_type = detect_ioc_type(&line);

            if self.add_ioc(&ioc_type, &line, None, "medium").is_ok() {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Export IOCs to a file
    pub fn export(&self, path: &Path, format: &str) -> Result<()> {
        match format {
            "csv" => {
                let mut output = String::from("type,value,description,severity\n");

                for hash in &self.hashes {
                    output.push_str(&format!(
                        "hash,{},{},{}\n",
                        hash.hash,
                        hash.description.as_deref().unwrap_or(""),
                        hash.severity
                    ));
                }

                for domain in &self.domains {
                    output.push_str(&format!(
                        "domain,{},{},{}\n",
                        domain.domain,
                        domain.description.as_deref().unwrap_or(""),
                        domain.severity
                    ));
                }

                for ip in &self.ip_addresses {
                    output.push_str(&format!(
                        "ip,{},{},{}\n",
                        ip.ip,
                        ip.description.as_deref().unwrap_or(""),
                        ip.severity
                    ));
                }

                for path_ioc in &self.file_paths {
                    output.push_str(&format!(
                        "path,{},{},{}\n",
                        path_ioc.path,
                        path_ioc.description.as_deref().unwrap_or(""),
                        path_ioc.severity
                    ));
                }

                for pattern in &self.patterns {
                    output.push_str(&format!(
                        "pattern,\"{}\",{},{}\n",
                        pattern.pattern.replace('"', "\"\""),
                        pattern.description.as_deref().unwrap_or(""),
                        pattern.severity
                    ));
                }

                fs::write(path, output)?;
            }
            "json" => {
                let output = serde_json::to_string_pretty(self)?;
                fs::write(path, output)?;
            }
            "stix" => {
                // Simplified STIX 2.1 output
                let stix = self.to_stix()?;
                fs::write(path, stix)?;
            }
            _ => anyhow::bail!("Unsupported export format: {}", format),
        }

        Ok(())
    }

    /// Convert to STIX 2.1 format
    fn to_stix(&self) -> Result<String> {
        let mut objects = Vec::new();

        for hash in &self.hashes {
            objects.push(serde_json::json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": format!("indicator--{}", uuid::Uuid::new_v4()),
                "name": format!("Malicious hash: {}", &hash.hash[..8]),
                "description": hash.description.as_deref().unwrap_or(""),
                "pattern": format!("[file:hashes.'SHA-256' = '{}']", hash.hash),
                "pattern_type": "stix",
                "valid_from": chrono::Utc::now().to_rfc3339()
            }));
        }

        for domain in &self.domains {
            objects.push(serde_json::json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": format!("indicator--{}", uuid::Uuid::new_v4()),
                "name": format!("Malicious domain: {}", domain.domain),
                "description": domain.description.as_deref().unwrap_or(""),
                "pattern": format!("[domain-name:value = '{}']", domain.domain),
                "pattern_type": "stix",
                "valid_from": chrono::Utc::now().to_rfc3339()
            }));
        }

        let bundle = serde_json::json!({
            "type": "bundle",
            "id": format!("bundle--{}", uuid::Uuid::new_v4()),
            "objects": objects
        });

        Ok(serde_json::to_string_pretty(&bundle)?)
    }
}

/// Detect hash type from length
fn detect_hash_type(hash: &str) -> String {
    match hash.len() {
        32 => "md5".to_string(),
        40 => "sha1".to_string(),
        64 => "sha256".to_string(),
        128 => "sha512".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Detect IOC type from value
fn detect_ioc_type(value: &str) -> String {
    // Check if it's a hash
    if value.chars().all(|c| c.is_ascii_hexdigit()) {
        return match value.len() {
            32 | 40 | 64 | 128 => "hash".to_string(),
            _ => "unknown".to_string(),
        };
    }

    // Check if it's an IP address
    if value.parse::<std::net::IpAddr>().is_ok() {
        return "ip".to_string();
    }

    // Check if it's a domain
    if value.contains('.') && !value.contains('/') {
        return "domain".to_string();
    }

    // Check if it's a file path
    if value.starts_with('/') || value.contains('\\') {
        return "path".to_string();
    }

    "unknown".to_string()
}

/// Get colored severity string
fn severity_color(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => severity.red().bold().to_string(),
        "high" => severity.red().to_string(),
        "medium" => severity.yellow().to_string(),
        "low" => severity.green().to_string(),
        _ => severity.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hash_type() {
        assert_eq!(detect_hash_type("d41d8cd98f00b204e9800998ecf8427e"), "md5");
        assert_eq!(
            detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            "sha1"
        );
        assert_eq!(
            detect_hash_type(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            "sha256"
        );
    }

    #[test]
    fn test_detect_ioc_type() {
        assert_eq!(detect_ioc_type("192.168.1.1"), "ip");
        assert_eq!(detect_ioc_type("example.com"), "domain");
        assert_eq!(detect_ioc_type("/tmp/malware"), "path");
        assert_eq!(
            detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"),
            "hash"
        );
    }

    #[test]
    fn test_add_ioc() {
        let mut db = IocDatabase::new();

        db.add_ioc("hash", "d41d8cd98f00b204e9800998ecf8427e", Some("Test hash"), "high")
            .unwrap();
        db.add_ioc("domain", "evil.com", Some("Bad domain"), "critical")
            .unwrap();

        assert_eq!(db.hashes.len(), 1);
        assert_eq!(db.domains.len(), 1);
        assert_eq!(db.total_count(), 2);
    }
}
