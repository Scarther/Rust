//! # B09: Hash Calculator
//!
//! Compute cryptographic hashes for files and strings.
//! Supports MD5, SHA-1, SHA-256, and SHA-512.

use clap::{Parser, ValueEnum};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::PathBuf;

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

    /// Hash algorithm
    #[arg(short, long, default_value = "sha256")]
    algorithm: HashAlgorithm,

    /// Calculate all algorithms
    #[arg(short = 'A', long)]
    all: bool,

    /// Verify against expected hash
    #[arg(short = 'c', long)]
    check: Option<String>,
}

#[derive(Debug, Clone, ValueEnum)]
enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

fn hash_bytes(data: &[u8], algo: &HashAlgorithm) -> String {
    match algo {
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
    }
}

fn hash_file(path: &PathBuf, algo: &HashAlgorithm) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(hash_bytes(&buffer, algo))
}

fn algo_name(algo: &HashAlgorithm) -> &'static str {
    match algo {
        HashAlgorithm::Md5 => "MD5",
        HashAlgorithm::Sha1 => "SHA1",
        HashAlgorithm::Sha256 => "SHA256",
        HashAlgorithm::Sha512 => "SHA512",
    }
}

fn main() {
    let args = Args::parse();

    println!("╔════════════════════════════════════════╗");
    println!("║        HASH CALCULATOR v1.0.0          ║");
    println!("╚════════════════════════════════════════╝\n");

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

    if let Some(files) = &args.file {
        for file in files {
            println!("[*] File: {}", file.display());
            for algo in &algorithms {
                match hash_file(file, algo) {
                    Ok(hash) => {
                        println!("    {}: {}", algo_name(algo), hash);

                        if let Some(ref expected) = args.check {
                            if hash.to_lowercase() == expected.to_lowercase() {
                                println!("    [+] MATCH");
                            } else {
                                println!("    [-] MISMATCH");
                            }
                        }
                    }
                    Err(e) => eprintln!("    [-] Error: {}", e),
                }
            }
            println!();
        }
    }

    if let Some(ref string) = args.string {
        println!("[*] String: \"{}\"", string);
        for algo in &algorithms {
            let hash = hash_bytes(string.as_bytes(), algo);
            println!("    {}: {}", algo_name(algo), hash);
        }
        println!();
    }

    if args.file.is_none() && args.string.is_none() {
        println!("[*] Usage: hashcalc -f <file> or -s <string>");
        println!("[*] Use --help for more options");
    }

    println!("[*] B09 Complete!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let hash = hash_bytes(b"hello", &HashAlgorithm::Md5);
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha256() {
        let hash = hash_bytes(b"hello", &HashAlgorithm::Sha256);
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
}
