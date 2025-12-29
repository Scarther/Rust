# B09: Hash Calculator

## Overview

| Property | Value |
|----------|-------|
| **ID** | B09 |
| **Name** | Hash Calculator |
| **Difficulty** | Basic |
| **Time** | 30 minutes |
| **Prerequisites** | B03 File Operations |

## What You'll Learn

1. Cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512)
2. Reading binary files
3. Buffered I/O for large files
4. Hex encoding
5. File integrity verification

---

## Security Context

### Why Hashing Matters

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HASHING IN SECURITY                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  RED TEAM USES                        BLUE TEAM USES                        │
│  ═════════════                        ══════════════                        │
│  • Verify downloaded tools            • File integrity monitoring           │
│  • Compare staged files               • Malware identification (IOCs)       │
│  • Password cracking (hash input)     • Evidence verification               │
│  • Identify known files               • Baseline comparisons                │
│                                                                              │
│  COMMON ALGORITHMS                                                          │
│  ════════════════                                                           │
│  MD5      - 128 bits - Fast, BROKEN for security, still used for IDs       │
│  SHA-1    - 160 bits - Fast, BROKEN for security, legacy systems           │
│  SHA-256  - 256 bits - Current standard, recommended                        │
│  SHA-512  - 512 bits - Higher security, slightly slower                     │
│  BLAKE3   - Variable - Modern, very fast, recommended for new projects     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Code

### Cargo.toml

```toml
[package]
name = "b09_hash_calculator"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
md-5 = "0.10"
sha1 = "0.10"
hex = "0.4"
clap = { version = "4.4", features = ["derive"] }
```

### src/main.rs

```rust
use clap::{Parser, ValueEnum};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;

/// Hash Calculator - Compute cryptographic hashes
#[derive(Parser, Debug)]
#[command(name = "hashcalc")]
#[command(version = "1.0.0")]
#[command(about = "Calculate file and string hashes")]
struct Args {
    /// File(s) to hash
    #[arg(short, long)]
    file: Option<Vec<PathBuf>>,

    /// String to hash
    #[arg(short, long)]
    string: Option<String>,

    /// Read from stdin
    #[arg(long)]
    stdin: bool,

    /// Hash algorithm
    #[arg(short, long, default_value = "sha256")]
    algorithm: HashAlgorithm,

    /// Calculate all algorithms
    #[arg(short = 'A', long)]
    all: bool,

    /// Verify against expected hash
    #[arg(short = 'c', long)]
    check: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "standard")]
    output: OutputFormat,
}

#[derive(Debug, Clone, ValueEnum)]
enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Standard,
    HashOnly,
    Json,
    Bsd,
}

/// Result of a hash computation
struct HashResult {
    algorithm: String,
    hash: String,
    source: String,
    size: Option<u64>,
}

impl HashResult {
    fn format(&self, fmt: &OutputFormat) -> String {
        match fmt {
            OutputFormat::Standard => {
                format!("{}  {}", self.hash, self.source)
            }
            OutputFormat::HashOnly => self.hash.clone(),
            OutputFormat::Json => {
                format!(
                    r#"{{"algorithm":"{}","hash":"{}","file":"{}","size":{}}}"#,
                    self.algorithm,
                    self.hash,
                    self.source,
                    self.size.unwrap_or(0)
                )
            }
            OutputFormat::Bsd => {
                format!("{} ({}) = {}", self.algorithm.to_uppercase(), self.source, self.hash)
            }
        }
    }
}

/// Generic hasher trait for different algorithms
trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> String;
    fn name(&self) -> &'static str;
}

struct Md5Hasher(Md5);
struct Sha1Hasher(Sha1);
struct Sha256Hasher(Sha256);
struct Sha512Hasher(Sha512);

impl Hasher for Md5Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(self) -> String { hex::encode(self.0.finalize()) }
    fn name(&self) -> &'static str { "MD5" }
}

impl Hasher for Sha1Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(self) -> String { hex::encode(self.0.finalize()) }
    fn name(&self) -> &'static str { "SHA1" }
}

impl Hasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(self) -> String { hex::encode(self.0.finalize()) }
    fn name(&self) -> &'static str { "SHA256" }
}

impl Hasher for Sha512Hasher {
    fn update(&mut self, data: &[u8]) { self.0.update(data); }
    fn finalize(self) -> String { hex::encode(self.0.finalize()) }
    fn name(&self) -> &'static str { "SHA512" }
}

fn create_hasher(algo: &HashAlgorithm) -> Box<dyn Hasher> {
    match algo {
        HashAlgorithm::Md5 => Box::new(Md5Hasher(Md5::new())),
        HashAlgorithm::Sha1 => Box::new(Sha1Hasher(Sha1::new())),
        HashAlgorithm::Sha256 => Box::new(Sha256Hasher(Sha256::new())),
        HashAlgorithm::Sha512 => Box::new(Sha512Hasher(Sha512::new())),
    }
}

/// Hash a file using streaming (memory efficient)
fn hash_file(path: &PathBuf, algo: &HashAlgorithm) -> io::Result<HashResult> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let mut reader = BufReader::with_capacity(65536, file);  // 64KB buffer
    let mut hasher = create_hasher(algo);
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(HashResult {
        algorithm: hasher.name().to_string(),
        hash: hasher.finalize(),
        source: path.display().to_string(),
        size: Some(metadata.len()),
    })
}

/// Hash a string
fn hash_string(data: &str, algo: &HashAlgorithm) -> HashResult {
    let mut hasher = create_hasher(algo);
    hasher.update(data.as_bytes());

    HashResult {
        algorithm: hasher.name().to_string(),
        hash: hasher.finalize(),
        source: format!("\"{}\"", if data.len() > 20 {
            format!("{}...", &data[..20])
        } else {
            data.to_string()
        }),
        size: Some(data.len() as u64),
    }
}

/// Hash from stdin
fn hash_stdin(algo: &HashAlgorithm) -> io::Result<HashResult> {
    let mut hasher = create_hasher(algo);
    let mut buffer = [0u8; 65536];
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = handle.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    Ok(HashResult {
        algorithm: hasher.name().to_string(),
        hash: hasher.finalize(),
        source: "-".to_string(),
        size: Some(total_bytes),
    })
}

fn print_banner() {
    println!(r#"
╔════════════════════════════════════════════════════════════╗
║              HASH CALCULATOR v1.0.0                        ║
║          Cryptographic Hash Computation                    ║
╚════════════════════════════════════════════════════════════╝
"#);
}

fn main() {
    let args = Args::parse();

    print_banner();

    let algorithms = if args.all {
        vec![
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
        ]
    } else {
        vec![args.algorithm.clone()]
    };

    // Process files
    if let Some(files) = &args.file {
        for file in files {
            for algo in &algorithms {
                match hash_file(file, algo) {
                    Ok(result) => {
                        let output = result.format(&args.output);
                        println!("{}", output);

                        // Verification
                        if let Some(ref expected) = args.check {
                            if result.hash.to_lowercase() == expected.to_lowercase() {
                                println!("[+] MATCH: Hash verified successfully");
                            } else {
                                println!("[-] MISMATCH: Expected {}", expected);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] Error hashing {}: {}", file.display(), e);
                    }
                }
            }
        }
    }

    // Process string
    if let Some(ref string) = args.string {
        for algo in &algorithms {
            let result = hash_string(string, algo);
            println!("{}", result.format(&args.output));
        }
    }

    // Process stdin
    if args.stdin {
        for algo in &algorithms {
            match hash_stdin(algo) {
                Ok(result) => println!("{}", result.format(&args.output)),
                Err(e) => eprintln!("[-] Error reading stdin: {}", e),
            }
        }
    }

    // Show help if no input
    if args.file.is_none() && args.string.is_none() && !args.stdin {
        println!("[*] No input specified. Use --help for usage.");
        println!();
        println!("Examples:");
        println!("  hashcalc -f /bin/ls");
        println!("  hashcalc -s 'password123'");
        println!("  echo 'data' | hashcalc --stdin");
        println!("  hashcalc -f file.txt -A  # All algorithms");
    }

    println!();
    println!("[*] B09 Complete!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_string() {
        let result = hash_string("hello", &HashAlgorithm::Md5);
        assert_eq!(result.hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha256_string() {
        let result = hash_string("hello", &HashAlgorithm::Sha256);
        assert_eq!(
            result.hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha1_string() {
        let result = hash_string("hello", &HashAlgorithm::Sha1);
        assert_eq!(result.hash, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    #[test]
    fn test_empty_string() {
        let result = hash_string("", &HashAlgorithm::Sha256);
        assert_eq!(
            result.hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
```

---

## Usage Examples

```bash
# Hash a single file
hashcalc -f /bin/ls

# Hash with specific algorithm
hashcalc -f malware.exe -a sha256

# Hash multiple files
hashcalc -f file1.txt -f file2.txt

# All algorithms
hashcalc -f suspicious.bin -A

# Hash a string
hashcalc -s "password123"

# Verify hash
hashcalc -f download.iso -c "expected_hash_here"

# Pipe from stdin
cat file.bin | hashcalc --stdin

# JSON output for automation
hashcalc -f /bin/ls -o json
```

---

## Red Team Perspective

### Operational Uses

1. **Verify Downloaded Tools**
   ```bash
   # Verify Cobalt Strike, etc.
   hashcalc -f cs-beacon.exe -c "known_good_hash"
   ```

2. **Avoid Duplicate Files**
   ```bash
   # Hash exfiltrated data to avoid duplicates
   hashcalc -f *.docx -o json | jq 'group_by(.hash)'
   ```

3. **Identify Known Files**
   ```bash
   # Quick identification of common binaries
   hashcalc -f mystery.exe | grep -f known_hashes.txt
   ```

---

## Blue Team Perspective

### Detection and Response

1. **File Integrity Monitoring**
   ```bash
   # Create baseline
   find /etc -type f -exec hashcalc -f {} -o json \; > baseline.json

   # Check for changes
   find /etc -type f -exec hashcalc -f {} -o json \; | diff baseline.json -
   ```

2. **IOC Matching**
   ```bash
   # Check against threat intel
   hashcalc -f suspect.exe | grep -f malware_hashes.ioc
   ```

3. **Evidence Verification**
   ```bash
   # Document evidence hashes for chain of custody
   hashcalc -f evidence/*.img -A -o json > evidence_manifest.json
   ```

---

## Exercises

1. Add BLAKE3 support using the `blake3` crate
2. Implement recursive directory hashing
3. Add progress bar for large files using `indicatif`
4. Implement parallel hashing for multiple files

---

[← B08 Base64](../B08_Base64/README.md) | [Next: B10 Directory Walker →](../B10_Directory_Walker/README.md)
