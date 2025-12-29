//! # Password Hash Cracker
//!
//! A dictionary-based password cracker supporting multiple hash algorithms.
//!
//! ## Rust Concepts Demonstrated:
//! - **Trait Objects**: Using `dyn Digest` for runtime polymorphism
//! - **Generics**: Generic functions that work with any hash algorithm
//! - **Arc<AtomicBool>**: Lock-free shared state for thread signaling
//! - **Memory Mapping**: Efficient reading of large dictionary files
//! - **Parallel Iteration**: Rayon for multi-core password cracking
//! - **Enum with Data**: HashType enum with associated functionality

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use digest::Digest;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Password Hash Cracker - Dictionary-based attack tool
///
/// # INTERMEDIATE RUST CONCEPTS:
///
/// 1. **Trait Objects (dyn Trait)**:
///    Allow runtime polymorphism when we don't know the concrete type at compile time.
///    Used here for handling different hash algorithms dynamically.
///
/// 2. **Generics with Trait Bounds**:
///    `fn hash<D: Digest>()` - Generic over any type implementing Digest trait.
///    Provides zero-cost abstraction - no runtime overhead.
///
/// 3. **Atomic Types**:
///    AtomicBool, AtomicU64 provide lock-free concurrent access.
///    More efficient than Mutex for simple counters and flags.
///
/// 4. **Memory Mapping**:
///    Maps file directly into memory address space.
///    More efficient than reading large files line by line.
#[derive(Parser)]
#[command(name = "password_cracker")]
#[command(author = "Security Researcher")]
#[command(version = "1.0")]
#[command(about = "Dictionary-based password hash cracker")]
struct Cli {
    /// Hash to crack
    #[arg(short = 'H', long)]
    hash: String,

    /// Hash algorithm type
    #[arg(short, long, value_enum, default_value = "md5")]
    algorithm: HashType,

    /// Path to dictionary file (one word per line)
    #[arg(short, long)]
    dictionary: PathBuf,

    /// Number of threads (0 = auto-detect)
    #[arg(short, long, default_value = "0")]
    threads: usize,

    /// Apply common mutations (l33t speak, capitalization, etc.)
    #[arg(short, long)]
    mutate: bool,

    /// Append numbers 0-999 to each word
    #[arg(long)]
    append_numbers: bool,

    /// Show progress bar
    #[arg(long, default_value = "true")]
    progress: bool,

    /// Crack multiple hashes from file
    #[arg(long)]
    hash_file: Option<PathBuf>,

    /// Output results to JSON file
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Supported hash algorithms
///
/// # RUST CONCEPT - Enum with Derive Macros:
/// ValueEnum derives the ability to parse from CLI strings.
/// Clone, Copy allow value semantics (cheap copies).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Serialize, Deserialize)]
enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Bcrypt,
}

impl HashType {
    /// Get the expected hash length in hex characters
    ///
    /// # RUST CONCEPT - Match Expression:
    /// Match is exhaustive - compiler ensures all variants are handled.
    fn expected_length(&self) -> Option<usize> {
        match self {
            HashType::Md5 => Some(32),
            HashType::Sha1 => Some(40),
            HashType::Sha256 => Some(64),
            HashType::Sha512 => Some(128),
            HashType::Bcrypt => None, // Variable length
        }
    }

    /// Get human-readable name
    fn name(&self) -> &'static str {
        match self {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA-1",
            HashType::Sha256 => "SHA-256",
            HashType::Sha512 => "SHA-512",
            HashType::Bcrypt => "bcrypt",
        }
    }
}

/// Result of a cracking attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CrackResult {
    hash: String,
    algorithm: HashType,
    password: Option<String>,
    attempts: u64,
    duration_ms: u64,
    cracked: bool,
}

/// Hash computation trait implementation
///
/// # GENERICS WITH TRAIT BOUNDS:
/// This function is generic over type D, which must implement the Digest trait.
/// The compiler generates specialized code for each hash algorithm used.
///
/// ```rust
/// fn compute_hash<D: Digest>(data: &[u8]) -> Vec<u8> {
///     D::digest(data).to_vec()
/// }
/// ```
///
/// # ZERO-COST ABSTRACTION:
/// Despite being generic, there's no runtime overhead - the compiler
/// monomorphizes the function for each concrete type.
fn compute_hash<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

/// Compute hash for any algorithm at runtime
///
/// # RUNTIME DISPATCH:
/// Unlike the generic version above, this uses match for runtime algorithm selection.
/// Less efficient but necessary when algorithm is determined at runtime.
fn compute_hash_runtime(data: &[u8], algorithm: HashType) -> Option<String> {
    let hash_bytes = match algorithm {
        HashType::Md5 => compute_hash::<md5::Md5>(data),
        HashType::Sha1 => compute_hash::<sha1::Sha1>(data),
        HashType::Sha256 => compute_hash::<sha2::Sha256>(data),
        HashType::Sha512 => compute_hash::<sha2::Sha512>(data),
        HashType::Bcrypt => return None, // Bcrypt uses different verification
    };

    Some(hex::encode(hash_bytes))
}

/// Verify bcrypt hash
///
/// Bcrypt is special - it includes salt in the hash, so we verify differently.
fn verify_bcrypt(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Password Cracker implementation
///
/// # STRUCT WITH CONFIGURATION:
/// Holds all configuration for a cracking session.
/// Fields use owned types (String, PathBuf) for simplicity.
struct PasswordCracker {
    target_hash: String,
    algorithm: HashType,
    dictionary_path: PathBuf,
    use_mutations: bool,
    append_numbers: bool,
    thread_count: usize,
}

impl PasswordCracker {
    /// Create new cracker instance
    fn new(
        target_hash: String,
        algorithm: HashType,
        dictionary_path: PathBuf,
        use_mutations: bool,
        append_numbers: bool,
        thread_count: usize,
    ) -> Self {
        Self {
            target_hash: target_hash.to_lowercase(),
            algorithm,
            dictionary_path,
            use_mutations,
            append_numbers,
            thread_count,
        }
    }

    /// Load dictionary from file
    ///
    /// # MEMORY MAPPING:
    /// For large files, memory mapping is more efficient than reading
    /// the entire file into memory. The OS handles paging.
    fn load_dictionary(&self) -> Result<Vec<String>> {
        println!(
            "{} Loading dictionary from {}",
            "[*]".blue(),
            self.dictionary_path.display()
        );

        let file = File::open(&self.dictionary_path)
            .context("Failed to open dictionary file")?;

        // Use memory mapping for efficient access
        // SAFETY: We ensure the file isn't modified during execution
        let mmap = unsafe { Mmap::map(&file)? };

        // Parse lines from memory-mapped content
        let content = std::str::from_utf8(&mmap)
            .context("Dictionary file is not valid UTF-8")?;

        let words: Vec<String> = content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect();

        println!("{} Loaded {} words", "[+]".green(), words.len());

        Ok(words)
    }

    /// Generate password mutations
    ///
    /// # ITERATOR CHAINS:
    /// Rust iterators are lazy - no intermediate collections are created.
    /// Each transformation is applied on-demand during iteration.
    fn generate_mutations(&self, word: &str) -> Vec<String> {
        let mut mutations = vec![word.to_string()];

        if !self.use_mutations {
            return mutations;
        }

        // Capitalization variants
        mutations.push(word.to_lowercase());
        mutations.push(word.to_uppercase());

        // Capitalize first letter
        if let Some(first) = word.chars().next() {
            let capitalized: String = first.to_uppercase()
                .chain(word.chars().skip(1).map(|c| c.to_lowercase().next().unwrap_or(c)))
                .collect();
            mutations.push(capitalized);
        }

        // L33t speak substitutions
        let leet = word
            .replace('a', "4")
            .replace('e', "3")
            .replace('i', "1")
            .replace('o', "0")
            .replace('s', "5")
            .replace('t', "7");
        mutations.push(leet);

        // Common suffixes
        for suffix in &["!", "1", "123", "!", "@", "#", "1!", "12", "2023", "2024"] {
            mutations.push(format!("{}{}", word, suffix));
        }

        // Common prefixes
        for prefix in &["!", "@", "#", "1", "123"] {
            mutations.push(format!("{}{}", prefix, word));
        }

        // Number appending (0-999)
        if self.append_numbers {
            for n in 0..1000 {
                mutations.push(format!("{}{}", word, n));
            }
        }

        mutations
    }

    /// Crack the password hash
    ///
    /// # ATOMIC OPERATIONS:
    /// AtomicBool is used for the "found" flag - no mutex needed.
    /// Ordering::SeqCst ensures sequential consistency across threads.
    ///
    /// # PARALLEL ITERATION:
    /// Rayon's par_iter() distributes work across all CPU cores.
    /// find_map_any stops early when password is found.
    fn crack(&self) -> Result<CrackResult> {
        let start_time = Instant::now();
        let words = self.load_dictionary()?;

        // Validate hash format
        if let Some(expected_len) = self.algorithm.expected_length() {
            if self.target_hash.len() != expected_len {
                anyhow::bail!(
                    "Invalid hash length: expected {} characters for {}, got {}",
                    expected_len,
                    self.algorithm.name(),
                    self.target_hash.len()
                );
            }
        }

        println!(
            "{} Cracking {} hash: {}",
            "[*]".blue(),
            self.algorithm.name(),
            &self.target_hash[..self.target_hash.len().min(32)]
        );

        // Configure thread pool
        if self.thread_count > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.thread_count)
                .build_global()
                .ok();
        }

        // ATOMIC TYPES FOR LOCK-FREE COORDINATION:
        // AtomicBool - flag to signal when password is found
        // AtomicU64 - counter for number of attempts
        let found = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicU64::new(0));

        // Calculate total candidates for progress bar
        let mutation_multiplier = if self.use_mutations { 20 } else { 1 };
        let number_multiplier = if self.append_numbers { 1000 } else { 1 };
        let total_candidates = words.len() as u64 * mutation_multiplier * number_multiplier;

        let progress = ProgressBar::new(total_candidates);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) ETA: {eta}")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Clone references for parallel iteration
        let found_clone = Arc::clone(&found);
        let attempts_clone = Arc::clone(&attempts);
        let target = self.target_hash.clone();
        let algorithm = self.algorithm;

        // PARALLEL PASSWORD CRACKING:
        // par_iter() distributes words across CPU cores
        // find_map_any() returns first match found by any thread
        let result: Option<String> = words.par_iter().find_map_any(|word| {
            // Check if another thread already found the password
            if found_clone.load(Ordering::Relaxed) {
                return None;
            }

            // Generate mutations for this word
            let mutations = self.generate_mutations(word);

            for candidate in mutations {
                // Increment attempt counter atomically
                attempts_clone.fetch_add(1, Ordering::Relaxed);
                progress.inc(1);

                // Check if already found by another thread
                if found_clone.load(Ordering::Relaxed) {
                    return None;
                }

                // Test this candidate
                let matches = match algorithm {
                    HashType::Bcrypt => verify_bcrypt(&candidate, &target),
                    _ => {
                        if let Some(computed) = compute_hash_runtime(candidate.as_bytes(), algorithm) {
                            computed == target
                        } else {
                            false
                        }
                    }
                };

                if matches {
                    // Signal other threads to stop
                    found_clone.store(true, Ordering::SeqCst);
                    progress.finish_with_message("Cracked!");
                    return Some(candidate);
                }
            }

            None
        });

        progress.finish_and_clear();

        let duration = start_time.elapsed();
        let total_attempts = attempts.load(Ordering::Relaxed);

        Ok(CrackResult {
            hash: self.target_hash.clone(),
            algorithm: self.algorithm,
            password: result,
            attempts: total_attempts,
            duration_ms: duration.as_millis() as u64,
            cracked: found.load(Ordering::Relaxed),
        })
    }
}

/// Display cracking results
fn display_result(result: &CrackResult) {
    println!("\n{}", "═".repeat(60).cyan());

    if result.cracked {
        println!("{}", " PASSWORD CRACKED! ".green().bold());
        println!("{}", "═".repeat(60).cyan());
        println!(
            "\n{} Hash:     {}",
            "[+]".green(),
            &result.hash[..result.hash.len().min(40)]
        );
        println!(
            "{} Password: {}",
            "[+]".green(),
            result.password.as_deref().unwrap_or("N/A").white().bold()
        );
    } else {
        println!("{}", " PASSWORD NOT FOUND ".red().bold());
        println!("{}", "═".repeat(60).cyan());
        println!(
            "\n{} Hash: {}",
            "[-]".red(),
            &result.hash[..result.hash.len().min(40)]
        );
    }

    println!("\n{} Statistics:", "[*]".blue());
    println!("    Algorithm: {}", result.algorithm.name());
    println!("    Attempts:  {}", format_number(result.attempts));
    println!("    Duration:  {}", format_duration(result.duration_ms));

    if result.duration_ms > 0 {
        let rate = result.attempts as f64 / (result.duration_ms as f64 / 1000.0);
        println!("    Speed:     {}/sec", format_number(rate as u64));
    }

    println!("{}\n", "═".repeat(60).cyan());
}

/// Format large numbers with commas
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

/// Format duration in human-readable format
fn format_duration(ms: u64) -> String {
    let duration = Duration::from_millis(ms);
    let secs = duration.as_secs();

    if secs >= 3600 {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{}.{:03}s", secs, duration.subsec_millis())
    } else {
        format!("{}ms", ms)
    }
}

/// Create a sample dictionary for testing
fn create_sample_dictionary() -> Result<PathBuf> {
    let path = std::env::temp_dir().join("sample_dictionary.txt");

    let common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "shadow", "123123", "654321", "superman",
        "qazwsx", "michael", "football", "password1", "password123",
        "batman", "login", "admin", "welcome", "hello",
        "charlie", "donald", "password!", "admin123", "root",
        "toor", "pass", "test", "guest", "master123",
    ];

    std::fs::write(&path, common_passwords.join("\n"))?;
    Ok(path)
}

/// Crack multiple hashes from a file
fn crack_multiple_hashes(
    hash_file: &PathBuf,
    algorithm: HashType,
    dictionary: &PathBuf,
    use_mutations: bool,
    append_numbers: bool,
    threads: usize,
) -> Result<Vec<CrackResult>> {
    let file = File::open(hash_file)?;
    let reader = BufReader::new(file);
    let hashes: Vec<String> = reader
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .collect();

    println!(
        "{} Cracking {} hashes from {}",
        "[*]".blue(),
        hashes.len(),
        hash_file.display()
    );

    let mut results = Vec::new();

    for (i, hash) in hashes.iter().enumerate() {
        println!(
            "\n{} Processing hash {}/{}: {}...",
            "[*]".blue(),
            i + 1,
            hashes.len(),
            &hash[..hash.len().min(20)]
        );

        let cracker = PasswordCracker::new(
            hash.clone(),
            algorithm,
            dictionary.clone(),
            use_mutations,
            append_numbers,
            threads,
        );

        match cracker.crack() {
            Ok(result) => {
                display_result(&result);
                results.push(result);
            }
            Err(e) => {
                eprintln!("{} Failed to crack hash: {}", "[!]".red(), e);
            }
        }
    }

    Ok(results)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle hash file mode
    if let Some(hash_file) = cli.hash_file {
        let results = crack_multiple_hashes(
            &hash_file,
            cli.algorithm,
            &cli.dictionary,
            cli.mutate,
            cli.append_numbers,
            cli.threads,
        )?;

        // Summary
        let cracked = results.iter().filter(|r| r.cracked).count();
        println!(
            "\n{} Summary: {}/{} hashes cracked",
            "[*]".blue(),
            cracked,
            results.len()
        );

        // Save results
        if let Some(output) = cli.output {
            let json = serde_json::to_string_pretty(&results)?;
            std::fs::write(&output, json)?;
            println!("{} Results saved to {}", "[+]".green(), output.display());
        }

        return Ok(());
    }

    // Single hash mode
    let cracker = PasswordCracker::new(
        cli.hash.clone(),
        cli.algorithm,
        cli.dictionary.clone(),
        cli.mutate,
        cli.append_numbers,
        cli.threads,
    );

    let result = cracker.crack()?;
    display_result(&result);

    // Save result
    if let Some(output) = cli.output {
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(&output, json)?;
        println!("{} Result saved to {}", "[+]".green(), output.display());
    }

    Ok(())
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test MD5 hash computation
    #[test]
    fn test_md5_hash() {
        let hash = compute_hash::<md5::Md5>(b"password");
        let hex = hex::encode(hash);
        assert_eq!(hex, "5f4dcc3b5aa765d61d8327deb882cf99");
    }

    /// Test SHA1 hash computation
    #[test]
    fn test_sha1_hash() {
        let hash = compute_hash::<sha1::Sha1>(b"password");
        let hex = hex::encode(hash);
        assert_eq!(hex, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
    }

    /// Test SHA256 hash computation
    #[test]
    fn test_sha256_hash() {
        let hash = compute_hash::<sha2::Sha256>(b"password");
        let hex = hex::encode(hash);
        assert_eq!(
            hex,
            "5e884898da28047d9171a5cf6d5edba9bc1b1c83c8dcba7fc6b0f81f4a84db22"
        );
    }

    /// Test runtime hash computation
    #[test]
    fn test_runtime_hash() {
        let hash = compute_hash_runtime(b"test", HashType::Md5).unwrap();
        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
    }

    /// Test hash type expected lengths
    #[test]
    fn test_hash_lengths() {
        assert_eq!(HashType::Md5.expected_length(), Some(32));
        assert_eq!(HashType::Sha1.expected_length(), Some(40));
        assert_eq!(HashType::Sha256.expected_length(), Some(64));
        assert_eq!(HashType::Sha512.expected_length(), Some(128));
        assert_eq!(HashType::Bcrypt.expected_length(), None);
    }

    /// Test number formatting
    #[test]
    fn test_format_number() {
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1000000), "1,000,000");
        assert_eq!(format_number(123), "123");
    }

    /// Test duration formatting
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(1500), "1.500s");
        assert_eq!(format_duration(65000), "1m 5s");
    }

    /// Test atomic operations pattern
    #[test]
    fn test_atomic_pattern() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        use std::thread;

        let found = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let found = Arc::clone(&found);
                let counter = Arc::clone(&counter);

                thread::spawn(move || {
                    for _ in 0..100 {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    if counter.load(Ordering::Relaxed) >= 500 {
                        found.store(true, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(counter.load(Ordering::Relaxed), 1000);
        assert!(found.load(Ordering::Relaxed));
    }

    /// Test mutation generation
    #[test]
    fn test_mutations() {
        let cracker = PasswordCracker::new(
            "test".to_string(),
            HashType::Md5,
            PathBuf::new(),
            true,
            false,
            1,
        );

        let mutations = cracker.generate_mutations("password");

        // Should include original, lowercase, uppercase, capitalized, leet
        assert!(mutations.contains(&"password".to_string()));
        assert!(mutations.contains(&"PASSWORD".to_string()));
        assert!(mutations.contains(&"Password".to_string()));
        assert!(mutations.contains(&"p455w0rd".to_string())); // leet
    }

    /// Test bcrypt verification
    #[test]
    fn test_bcrypt() {
        let hash = bcrypt::hash("secret", 4).unwrap();
        assert!(verify_bcrypt("secret", &hash));
        assert!(!verify_bcrypt("wrong", &hash));
    }

    /// Test generic hash function
    #[test]
    fn test_generic_hash() {
        // This demonstrates compile-time polymorphism
        fn hash_with_algorithm<D: Digest>(data: &[u8]) -> String {
            hex::encode(compute_hash::<D>(data))
        }

        let md5 = hash_with_algorithm::<md5::Md5>(b"test");
        let sha1 = hash_with_algorithm::<sha1::Sha1>(b"test");

        assert_ne!(md5, sha1);
        assert_eq!(md5.len(), 32);
        assert_eq!(sha1.len(), 40);
    }
}
