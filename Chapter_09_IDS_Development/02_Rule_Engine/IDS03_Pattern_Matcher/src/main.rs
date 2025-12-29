//! IDS03_Pattern_Matcher - High-Performance Pattern Matching Engine
//!
//! This module implements multiple pattern matching algorithms optimized for
//! intrusion detection systems. It supports:
//!
//! - **Aho-Corasick**: Multi-pattern string matching (O(n) time complexity)
//! - **Boyer-Moore-Horspool**: Fast single pattern matching with skip tables
//! - **Regex/PCRE**: Perl-compatible regular expressions for complex patterns
//! - **Byte Matching**: Binary pattern matching with wildcards and masks
//!
//! # IDS Pattern Matching Concepts
//!
//! Pattern matching is the core of any IDS. Efficient matching is critical
//! because an IDS must inspect every packet at line speed. The Aho-Corasick
//! algorithm is particularly important because it can match thousands of
//! patterns simultaneously in a single pass through the data.
//!
//! ## Performance Considerations
//! - Use Aho-Corasick for multiple fixed patterns
//! - Use regex sparingly (expensive)
//! - Consider pattern ordering (most specific first)
//! - Use anchors (startswith/endswith) when possible

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use clap::{Parser, Subcommand};
use colored::*;
use memchr::{memchr, memmem};
use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, info, warn};

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum MatcherError {
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),

    #[error("Pattern compilation failed: {0}")]
    CompilationError(String),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

// =============================================================================
// Pattern Types
// =============================================================================

/// Modifiers that affect how a pattern is matched
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternModifiers {
    /// Case-insensitive matching
    pub nocase: bool,
    /// Offset from start of data to begin matching
    pub offset: Option<usize>,
    /// Maximum depth to search
    pub depth: Option<usize>,
    /// Distance from previous match
    pub distance: Option<i32>,
    /// Search within N bytes of previous match
    pub within: Option<usize>,
    /// Pattern must be at start of data
    pub startswith: bool,
    /// Pattern must be at end of data
    pub endswith: bool,
    /// This is a fast pattern (used for prefiltering)
    pub fast_pattern: bool,
    /// Negate the match (alert if NOT found)
    pub negated: bool,
}

/// Types of patterns supported by the matcher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    /// Fixed byte sequence
    Fixed(Vec<u8>),
    /// Regular expression
    Regex(String),
    /// Hex pattern with wildcards (e.g., |48 65 ?? 6c 6f|)
    HexWildcard(Vec<HexByte>),
    /// Byte test (compare bytes at offset)
    ByteTest {
        num_bytes: usize,
        operator: CompareOp,
        value: u64,
        offset: i32,
        relative: bool,
        endian: Endianness,
    },
    /// Byte jump (move cursor by bytes at offset)
    ByteJump {
        num_bytes: usize,
        offset: i32,
        relative: bool,
        multiplier: u32,
        endian: Endianness,
        from_beginning: bool,
        post_offset: i32,
    },
}

/// Hex byte that can be a specific value or wildcard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HexByte {
    /// Specific byte value
    Exact(u8),
    /// Wildcard (matches any byte)
    Any,
    /// Nibble wildcard (e.g., 4? matches 0x40-0x4F)
    HighNibble(u8),
    LowNibble(u8),
}

/// Comparison operators for byte tests
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompareOp {
    Less,
    Greater,
    LessEqual,
    GreaterEqual,
    Equal,
    NotEqual,
    BitwiseAnd,
    BitwiseOr,
}

/// Endianness for multi-byte values
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Endianness {
    Big,
    Little,
}

/// A pattern with its identifier and modifiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Unique pattern identifier
    pub id: usize,
    /// Pattern name/description
    pub name: String,
    /// The pattern type and data
    pub pattern_type: PatternType,
    /// Pattern modifiers
    pub modifiers: PatternModifiers,
    /// Associated rule SID (if any)
    pub sid: Option<u32>,
}

// =============================================================================
// Match Result
// =============================================================================

/// Result of a pattern match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Pattern ID that matched
    pub pattern_id: usize,
    /// Pattern name
    pub pattern_name: String,
    /// Start offset in data
    pub start: usize,
    /// End offset in data
    pub end: usize,
    /// Matched bytes
    pub matched_data: Vec<u8>,
    /// Associated rule SID
    pub sid: Option<u32>,
}

impl fmt::Display for MatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pattern '{}' (id={}) matched at offset {}-{}: {:?}",
            self.pattern_name,
            self.pattern_id,
            self.start,
            self.end,
            String::from_utf8_lossy(&self.matched_data)
        )
    }
}

// =============================================================================
// Pattern Compiler
// =============================================================================

/// Compiles patterns for efficient matching
pub struct PatternCompiler {
    patterns: Vec<Pattern>,
    next_id: usize,
}

impl PatternCompiler {
    pub fn new() -> Self {
        PatternCompiler {
            patterns: Vec::new(),
            next_id: 0,
        }
    }

    /// Add a fixed string pattern
    pub fn add_string(&mut self, name: &str, pattern: &str, modifiers: PatternModifiers) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        let bytes = if modifiers.nocase {
            pattern.to_lowercase().into_bytes()
        } else {
            pattern.as_bytes().to_vec()
        };

        self.patterns.push(Pattern {
            id,
            name: name.to_string(),
            pattern_type: PatternType::Fixed(bytes),
            modifiers,
            sid: None,
        });

        id
    }

    /// Add a byte pattern
    pub fn add_bytes(&mut self, name: &str, bytes: Vec<u8>, modifiers: PatternModifiers) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        self.patterns.push(Pattern {
            id,
            name: name.to_string(),
            pattern_type: PatternType::Fixed(bytes),
            modifiers,
            sid: None,
        });

        id
    }

    /// Add a hex pattern with wildcards (e.g., "48 65 ?? 6c 6f")
    pub fn add_hex_pattern(
        &mut self,
        name: &str,
        hex_str: &str,
        modifiers: PatternModifiers,
    ) -> Result<usize, MatcherError> {
        let id = self.next_id;
        self.next_id += 1;

        let hex_bytes = self.parse_hex_pattern(hex_str)?;

        self.patterns.push(Pattern {
            id,
            name: name.to_string(),
            pattern_type: PatternType::HexWildcard(hex_bytes),
            modifiers,
            sid: None,
        });

        Ok(id)
    }

    /// Add a regex pattern
    pub fn add_regex(&mut self, name: &str, pattern: &str, modifiers: PatternModifiers) -> Result<usize, MatcherError> {
        // Validate the regex
        RegexBuilder::new(pattern)
            .case_insensitive(modifiers.nocase)
            .build()?;

        let id = self.next_id;
        self.next_id += 1;

        self.patterns.push(Pattern {
            id,
            name: name.to_string(),
            pattern_type: PatternType::Regex(pattern.to_string()),
            modifiers,
            sid: None,
        });

        Ok(id)
    }

    /// Add a byte test pattern
    pub fn add_byte_test(
        &mut self,
        name: &str,
        num_bytes: usize,
        operator: CompareOp,
        value: u64,
        offset: i32,
        relative: bool,
        endian: Endianness,
        modifiers: PatternModifiers,
    ) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        self.patterns.push(Pattern {
            id,
            name: name.to_string(),
            pattern_type: PatternType::ByteTest {
                num_bytes,
                operator,
                value,
                offset,
                relative,
                endian,
            },
            modifiers,
            sid: None,
        });

        id
    }

    /// Parse hex pattern string into HexBytes
    fn parse_hex_pattern(&self, s: &str) -> Result<Vec<HexByte>, MatcherError> {
        let mut result = Vec::new();
        let tokens: Vec<&str> = s.split_whitespace().collect();

        for token in tokens {
            if token == "??" {
                result.push(HexByte::Any);
            } else if token.starts_with('?') && token.len() == 2 {
                let nibble = u8::from_str_radix(&token[1..], 16)
                    .map_err(|_| MatcherError::InvalidPattern(token.to_string()))?;
                result.push(HexByte::LowNibble(nibble));
            } else if token.ends_with('?') && token.len() == 2 {
                let nibble = u8::from_str_radix(&token[..1], 16)
                    .map_err(|_| MatcherError::InvalidPattern(token.to_string()))?;
                result.push(HexByte::HighNibble(nibble << 4));
            } else if token.len() == 2 {
                let byte = u8::from_str_radix(token, 16)
                    .map_err(|_| MatcherError::InvalidPattern(token.to_string()))?;
                result.push(HexByte::Exact(byte));
            } else {
                return Err(MatcherError::InvalidPattern(token.to_string()));
            }
        }

        Ok(result)
    }

    /// Get all patterns
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Build a matcher from compiled patterns
    pub fn build(&self) -> Result<PatternMatcher, MatcherError> {
        PatternMatcher::new(self.patterns.clone())
    }
}

impl Default for PatternCompiler {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Pattern Matcher Engine
// =============================================================================

/// High-performance multi-pattern matcher
pub struct PatternMatcher {
    /// All patterns
    patterns: Vec<Pattern>,
    /// Aho-Corasick automaton for fixed patterns
    aho_corasick: Option<AhoCorasick>,
    /// Mapping from AC pattern index to our pattern ID
    ac_pattern_map: HashMap<usize, usize>,
    /// Compiled regex patterns
    regex_patterns: Vec<(usize, Regex)>,
    /// Fast pattern searcher using memmem
    fast_searchers: Vec<(usize, memmem::Finder<'static>)>,
    /// Statistics
    stats: MatcherStats,
}

/// Matching statistics
#[derive(Debug, Default, Clone)]
pub struct MatcherStats {
    pub bytes_scanned: u64,
    pub patterns_matched: u64,
    pub ac_matches: u64,
    pub regex_matches: u64,
    pub hex_matches: u64,
    pub scan_time_ns: u64,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new(patterns: Vec<Pattern>) -> Result<Self, MatcherError> {
        let mut fixed_patterns: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut regex_patterns: Vec<(usize, Regex)> = Vec::new();
        let mut ac_pattern_map = HashMap::new();

        // Separate patterns by type
        for pattern in &patterns {
            match &pattern.pattern_type {
                PatternType::Fixed(bytes) => {
                    let ac_idx = fixed_patterns.len();
                    ac_pattern_map.insert(ac_idx, pattern.id);
                    fixed_patterns.push((pattern.id, bytes.clone()));
                }
                PatternType::Regex(regex_str) => {
                    let regex = RegexBuilder::new(regex_str)
                        .case_insensitive(pattern.modifiers.nocase)
                        .dot_matches_new_line(true)
                        .build()
                        .map_err(|e| MatcherError::CompilationError(e.to_string()))?;
                    regex_patterns.push((pattern.id, regex));
                }
                _ => {}
            }
        }

        // Build Aho-Corasick automaton
        let aho_corasick = if !fixed_patterns.is_empty() {
            let patterns_only: Vec<&[u8]> = fixed_patterns.iter()
                .map(|(_, p)| p.as_slice())
                .collect();

            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(patterns_only)
                    .map_err(|e| MatcherError::CompilationError(e.to_string()))?
            )
        } else {
            None
        };

        // Build fast searchers for patterns marked as fast_pattern
        let fast_searchers: Vec<(usize, memmem::Finder<'static>)> = patterns
            .iter()
            .filter(|p| p.modifiers.fast_pattern)
            .filter_map(|p| {
                if let PatternType::Fixed(bytes) = &p.pattern_type {
                    // Leak the bytes to get a 'static lifetime
                    let static_bytes: &'static [u8] = Box::leak(bytes.clone().into_boxed_slice());
                    Some((p.id, memmem::Finder::new(static_bytes)))
                } else {
                    None
                }
            })
            .collect();

        info!("Built matcher with {} patterns ({} AC, {} regex)",
            patterns.len(), fixed_patterns.len(), regex_patterns.len());

        Ok(PatternMatcher {
            patterns,
            aho_corasick,
            ac_pattern_map,
            regex_patterns,
            fast_searchers,
            stats: MatcherStats::default(),
        })
    }

    /// Scan data for all patterns
    pub fn scan(&mut self, data: &[u8]) -> Vec<MatchResult> {
        let start_time = Instant::now();
        let mut results = Vec::new();

        self.stats.bytes_scanned += data.len() as u64;

        // Phase 1: Fast pattern prefiltering
        if !self.fast_searchers.is_empty() {
            let mut any_fast_match = false;
            for (_, searcher) in &self.fast_searchers {
                if searcher.find(data).is_some() {
                    any_fast_match = true;
                    break;
                }
            }

            // Skip full scan if no fast patterns matched
            if !any_fast_match && self.fast_searchers.len() == self.patterns.len() {
                return results;
            }
        }

        // Phase 2: Aho-Corasick multi-pattern matching
        if let Some(ref ac) = self.aho_corasick {
            for mat in ac.find_iter(data) {
                if let Some(&pattern_id) = self.ac_pattern_map.get(&mat.pattern().as_usize()) {
                    if let Some(pattern) = self.patterns.iter().find(|p| p.id == pattern_id) {
                        // Apply modifiers
                        if self.check_modifiers(pattern, data, mat.start(), mat.end(), None) {
                            results.push(MatchResult {
                                pattern_id,
                                pattern_name: pattern.name.clone(),
                                start: mat.start(),
                                end: mat.end(),
                                matched_data: data[mat.start()..mat.end()].to_vec(),
                                sid: pattern.sid,
                            });
                            self.stats.ac_matches += 1;
                        }
                    }
                }
            }
        }

        // Phase 3: Regex matching
        for (pattern_id, regex) in &self.regex_patterns {
            if let Some(pattern) = self.patterns.iter().find(|p| p.id == *pattern_id) {
                for mat in regex.find_iter(data) {
                    if self.check_modifiers(pattern, data, mat.start(), mat.end(), None) {
                        results.push(MatchResult {
                            pattern_id: *pattern_id,
                            pattern_name: pattern.name.clone(),
                            start: mat.start(),
                            end: mat.end(),
                            matched_data: mat.as_bytes().to_vec(),
                            sid: pattern.sid,
                        });
                        self.stats.regex_matches += 1;
                    }
                }
            }
        }

        // Phase 4: Hex wildcard matching
        for pattern in &self.patterns {
            if let PatternType::HexWildcard(ref hex_bytes) = pattern.pattern_type {
                let matches = self.scan_hex_pattern(data, hex_bytes);
                for (start, end) in matches {
                    if self.check_modifiers(pattern, data, start, end, None) {
                        results.push(MatchResult {
                            pattern_id: pattern.id,
                            pattern_name: pattern.name.clone(),
                            start,
                            end,
                            matched_data: data[start..end].to_vec(),
                            sid: pattern.sid,
                        });
                        self.stats.hex_matches += 1;
                    }
                }
            }
        }

        // Phase 5: Byte tests (require previous match position)
        for pattern in &self.patterns {
            if let PatternType::ByteTest { num_bytes, operator, value, offset, relative: _, endian } = &pattern.pattern_type {
                // Non-relative byte test
                let test_offset = *offset as usize;
                if test_offset + num_bytes <= data.len() {
                    let test_value = self.read_bytes(data, test_offset, *num_bytes, *endian);
                    if self.compare_values(test_value, *value, *operator) {
                        results.push(MatchResult {
                            pattern_id: pattern.id,
                            pattern_name: pattern.name.clone(),
                            start: test_offset,
                            end: test_offset + num_bytes,
                            matched_data: data[test_offset..test_offset + num_bytes].to_vec(),
                            sid: pattern.sid,
                        });
                    }
                }
            }
        }

        self.stats.patterns_matched += results.len() as u64;
        self.stats.scan_time_ns += start_time.elapsed().as_nanos() as u64;

        // Handle negated patterns
        results = self.apply_negation(results);

        results
    }

    /// Check if match satisfies pattern modifiers
    fn check_modifiers(
        &self,
        pattern: &Pattern,
        data: &[u8],
        start: usize,
        end: usize,
        previous_match_end: Option<usize>,
    ) -> bool {
        let mods = &pattern.modifiers;

        // Check offset
        if let Some(offset) = mods.offset {
            if start < offset {
                return false;
            }
        }

        // Check depth
        if let Some(depth) = mods.depth {
            if end > depth {
                return false;
            }
        }

        // Check distance from previous match
        if let Some(distance) = mods.distance {
            if let Some(prev_end) = previous_match_end {
                let actual_distance = start as i32 - prev_end as i32;
                if actual_distance < distance {
                    return false;
                }
            }
        }

        // Check within
        if let Some(within) = mods.within {
            if let Some(prev_end) = previous_match_end {
                if start > prev_end + within {
                    return false;
                }
            }
        }

        // Check startswith
        if mods.startswith && start != 0 {
            return false;
        }

        // Check endswith
        if mods.endswith && end != data.len() {
            return false;
        }

        true
    }

    /// Scan for hex pattern with wildcards
    fn scan_hex_pattern(&self, data: &[u8], hex_bytes: &[HexByte]) -> Vec<(usize, usize)> {
        let mut results = Vec::new();
        let pattern_len = hex_bytes.len();

        if data.len() < pattern_len {
            return results;
        }

        // Find first exact byte for quick skip
        let first_exact = hex_bytes.iter().find_map(|b| {
            if let HexByte::Exact(v) = b { Some(*v) } else { None }
        });

        let mut pos = 0;
        while pos <= data.len() - pattern_len {
            // Use memchr for fast skipping if we have an exact first byte
            if let Some(first_byte) = first_exact {
                if let Some(found) = memchr(first_byte, &data[pos..]) {
                    pos += found;
                    if pos > data.len() - pattern_len {
                        break;
                    }
                } else {
                    break;
                }
            }

            // Check full pattern
            if self.match_hex_pattern(&data[pos..pos + pattern_len], hex_bytes) {
                results.push((pos, pos + pattern_len));
                pos += 1; // Overlapping matches
            } else {
                pos += 1;
            }
        }

        results
    }

    /// Check if data matches hex pattern
    fn match_hex_pattern(&self, data: &[u8], hex_bytes: &[HexByte]) -> bool {
        if data.len() != hex_bytes.len() {
            return false;
        }

        for (i, hex_byte) in hex_bytes.iter().enumerate() {
            let matches = match hex_byte {
                HexByte::Exact(v) => data[i] == *v,
                HexByte::Any => true,
                HexByte::HighNibble(v) => (data[i] & 0xF0) == *v,
                HexByte::LowNibble(v) => (data[i] & 0x0F) == *v,
            };

            if !matches {
                return false;
            }
        }

        true
    }

    /// Read bytes from data with specified endianness
    fn read_bytes(&self, data: &[u8], offset: usize, num_bytes: usize, endian: Endianness) -> u64 {
        let slice = &data[offset..offset + num_bytes];

        match (num_bytes, endian) {
            (1, _) => slice[0] as u64,
            (2, Endianness::Big) => BigEndian::read_u16(slice) as u64,
            (2, Endianness::Little) => LittleEndian::read_u16(slice) as u64,
            (4, Endianness::Big) => BigEndian::read_u32(slice) as u64,
            (4, Endianness::Little) => LittleEndian::read_u32(slice) as u64,
            (8, Endianness::Big) => BigEndian::read_u64(slice),
            (8, Endianness::Little) => LittleEndian::read_u64(slice),
            _ => 0,
        }
    }

    /// Compare values with operator
    fn compare_values(&self, actual: u64, expected: u64, op: CompareOp) -> bool {
        match op {
            CompareOp::Less => actual < expected,
            CompareOp::Greater => actual > expected,
            CompareOp::LessEqual => actual <= expected,
            CompareOp::GreaterEqual => actual >= expected,
            CompareOp::Equal => actual == expected,
            CompareOp::NotEqual => actual != expected,
            CompareOp::BitwiseAnd => (actual & expected) != 0,
            CompareOp::BitwiseOr => (actual | expected) != 0,
        }
    }

    /// Apply negation logic to results
    fn apply_negation(&self, mut results: Vec<MatchResult>) -> Vec<MatchResult> {
        // For negated patterns, we need to add a "match" if pattern was NOT found
        for pattern in &self.patterns {
            if pattern.modifiers.negated {
                let found = results.iter().any(|r| r.pattern_id == pattern.id);
                if !found {
                    results.push(MatchResult {
                        pattern_id: pattern.id,
                        pattern_name: format!("NOT({})", pattern.name),
                        start: 0,
                        end: 0,
                        matched_data: Vec::new(),
                        sid: pattern.sid,
                    });
                } else {
                    // Remove the match for negated pattern that was found
                    results.retain(|r| r.pattern_id != pattern.id);
                }
            }
        }

        results
    }

    /// Get matching statistics
    pub fn stats(&self) -> &MatcherStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = MatcherStats::default();
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// =============================================================================
// Streaming Matcher
// =============================================================================

/// Matcher for streaming data (handles data that arrives in chunks)
pub struct StreamingMatcher {
    matcher: PatternMatcher,
    buffer: Vec<u8>,
    /// Maximum buffer size
    max_buffer: usize,
    /// Overlap size to handle patterns spanning chunks
    overlap: usize,
}

impl StreamingMatcher {
    /// Create a new streaming matcher
    pub fn new(matcher: PatternMatcher, max_buffer: usize) -> Self {
        // Calculate overlap as max pattern length or reasonable default
        let overlap = 1024.min(max_buffer / 4);

        StreamingMatcher {
            matcher,
            buffer: Vec::with_capacity(max_buffer),
            max_buffer,
            overlap,
        }
    }

    /// Process a chunk of streaming data
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Vec<MatchResult> {
        // Add chunk to buffer
        self.buffer.extend_from_slice(chunk);

        // If buffer exceeds max, scan and trim
        if self.buffer.len() > self.max_buffer {
            let results = self.matcher.scan(&self.buffer);

            // Keep overlap at end of buffer
            let keep_from = self.buffer.len().saturating_sub(self.overlap);
            self.buffer = self.buffer[keep_from..].to_vec();

            // Adjust match offsets
            results
                .into_iter()
                .filter(|r| r.end <= self.buffer.len())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Flush remaining buffer and get final matches
    pub fn flush(&mut self) -> Vec<MatchResult> {
        let results = self.matcher.scan(&self.buffer);
        self.buffer.clear();
        results
    }
}

// =============================================================================
// Pattern Set Management
// =============================================================================

/// A set of patterns that can be loaded/saved
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternSet {
    pub name: String,
    pub version: String,
    pub patterns: Vec<PatternDefinition>,
}

/// Pattern definition for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDefinition {
    pub name: String,
    pub pattern: String,
    pub pattern_type: String, // "fixed", "regex", "hex"
    pub modifiers: PatternModifiers,
    pub sid: Option<u32>,
}

impl PatternSet {
    /// Load pattern set from JSON file
    pub fn load(path: &PathBuf) -> Result<Self, MatcherError> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| MatcherError::InvalidPattern(e.to_string()))
    }

    /// Save pattern set to JSON file
    pub fn save(&self, path: &PathBuf) -> Result<(), MatcherError> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| MatcherError::InvalidPattern(e.to_string()))?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Build a matcher from this pattern set
    pub fn build_matcher(&self) -> Result<PatternMatcher, MatcherError> {
        let mut compiler = PatternCompiler::new();

        for def in &self.patterns {
            match def.pattern_type.as_str() {
                "fixed" | "string" => {
                    compiler.add_string(&def.name, &def.pattern, def.modifiers.clone());
                }
                "regex" | "pcre" => {
                    compiler.add_regex(&def.name, &def.pattern, def.modifiers.clone())?;
                }
                "hex" => {
                    compiler.add_hex_pattern(&def.name, &def.pattern, def.modifiers.clone())?;
                }
                _ => {
                    warn!("Unknown pattern type: {}", def.pattern_type);
                }
            }
        }

        compiler.build()
    }
}

// =============================================================================
// Built-in Pattern Libraries
// =============================================================================

/// Generate common attack pattern set
pub fn common_attack_patterns() -> PatternSet {
    PatternSet {
        name: "Common Attack Patterns".to_string(),
        version: "1.0".to_string(),
        patterns: vec![
            // SQL Injection patterns
            PatternDefinition {
                name: "SQL UNION SELECT".to_string(),
                pattern: r"(?i)union\s+select".to_string(),
                pattern_type: "regex".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(2000001),
            },
            PatternDefinition {
                name: "SQL OR 1=1".to_string(),
                pattern: r"(?i)or\s+1\s*=\s*1".to_string(),
                pattern_type: "regex".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(2000002),
            },
            // XSS patterns
            PatternDefinition {
                name: "XSS Script Tag".to_string(),
                pattern: r"(?i)<script[^>]*>".to_string(),
                pattern_type: "regex".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(2000010),
            },
            PatternDefinition {
                name: "XSS Event Handler".to_string(),
                pattern: r"(?i)on(error|load|click|mouseover)\s*=".to_string(),
                pattern_type: "regex".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(2000011),
            },
            // Shell injection
            PatternDefinition {
                name: "Shell Pipe Injection".to_string(),
                pattern: "; /bin/".to_string(),
                pattern_type: "fixed".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(2000020),
            },
            PatternDefinition {
                name: "Backtick Command".to_string(),
                pattern: r"`[^`]+`".to_string(),
                pattern_type: "regex".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(2000021),
            },
            // Directory traversal
            PatternDefinition {
                name: "Path Traversal".to_string(),
                pattern: "../".to_string(),
                pattern_type: "fixed".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(2000030),
            },
            // Malware signatures
            PatternDefinition {
                name: "EXE Header".to_string(),
                pattern: "4D 5A 90 00".to_string(),
                pattern_type: "hex".to_string(),
                modifiers: PatternModifiers { startswith: true, ..Default::default() },
                sid: Some(2000040),
            },
            PatternDefinition {
                name: "ELF Header".to_string(),
                pattern: "7F 45 4C 46".to_string(),
                pattern_type: "hex".to_string(),
                modifiers: PatternModifiers { startswith: true, ..Default::default() },
                sid: Some(2000041),
            },
        ],
    }
}

/// Generate protocol patterns
pub fn protocol_patterns() -> PatternSet {
    PatternSet {
        name: "Protocol Detection Patterns".to_string(),
        version: "1.0".to_string(),
        patterns: vec![
            // HTTP
            PatternDefinition {
                name: "HTTP GET Request".to_string(),
                pattern: "GET ".to_string(),
                pattern_type: "fixed".to_string(),
                modifiers: PatternModifiers { startswith: true, ..Default::default() },
                sid: Some(3000001),
            },
            PatternDefinition {
                name: "HTTP POST Request".to_string(),
                pattern: "POST ".to_string(),
                pattern_type: "fixed".to_string(),
                modifiers: PatternModifiers { startswith: true, ..Default::default() },
                sid: Some(3000002),
            },
            // TLS/SSL
            PatternDefinition {
                name: "TLS ClientHello".to_string(),
                pattern: "16 03 01 ?? ?? 01".to_string(),
                pattern_type: "hex".to_string(),
                modifiers: PatternModifiers { startswith: true, ..Default::default() },
                sid: Some(3000010),
            },
            // SSH
            PatternDefinition {
                name: "SSH Protocol".to_string(),
                pattern: "SSH-".to_string(),
                pattern_type: "fixed".to_string(),
                modifiers: PatternModifiers { startswith: true, ..Default::default() },
                sid: Some(3000020),
            },
            // DNS
            PatternDefinition {
                name: "DNS Query".to_string(),
                pattern: "?? ?? 01 00 00 01".to_string(),
                pattern_type: "hex".to_string(),
                modifiers: PatternModifiers::default(),
                sid: Some(3000030),
            },
        ],
    }
}

// =============================================================================
// CLI Interface
// =============================================================================

#[derive(Parser)]
#[command(name = "ids03_pattern_matcher")]
#[command(about = "High-performance pattern matching engine for IDS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan file for patterns
    Scan {
        /// File to scan
        file: PathBuf,
        /// Pattern set file (JSON)
        #[arg(short, long)]
        patterns: Option<PathBuf>,
        /// Use built-in attack patterns
        #[arg(long)]
        attacks: bool,
        /// Use built-in protocol patterns
        #[arg(long)]
        protocols: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Scan hex string
    ScanHex {
        /// Hex string to scan
        hex: String,
        /// Pattern to search for
        #[arg(short, long)]
        pattern: String,
    },
    /// Generate pattern set file
    Generate {
        /// Output file
        output: PathBuf,
        /// Pattern type: attacks, protocols
        #[arg(short, long, default_value = "attacks")]
        pattern_type: String,
    },
    /// Benchmark pattern matching
    Benchmark {
        /// File to scan
        file: PathBuf,
        /// Number of iterations
        #[arg(short, long, default_value = "100")]
        iterations: usize,
    },
    /// Test a specific pattern
    Test {
        /// Pattern to test
        pattern: String,
        /// Test data
        data: String,
        /// Pattern type: fixed, regex, hex
        #[arg(short, long, default_value = "fixed")]
        pattern_type: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { file, patterns, attacks, protocols, json } => {
            println!("{}", "Pattern Matcher - Scanning".cyan().bold());
            println!("{}", "=".repeat(60));

            // Load data
            let data = fs::read(&file)?;
            println!("  File: {} ({} bytes)", file.display(), data.len());

            // Build pattern set
            let mut all_patterns = Vec::new();

            if let Some(pattern_file) = patterns {
                let set = PatternSet::load(&pattern_file)?;
                println!("  Loaded {} patterns from {}", set.patterns.len(), pattern_file.display());
                all_patterns.extend(set.patterns);
            }

            if attacks {
                let set = common_attack_patterns();
                println!("  Loaded {} attack patterns", set.patterns.len());
                all_patterns.extend(set.patterns);
            }

            if protocols {
                let set = protocol_patterns();
                println!("  Loaded {} protocol patterns", set.patterns.len());
                all_patterns.extend(set.patterns);
            }

            if all_patterns.is_empty() {
                // Default to attack patterns
                let set = common_attack_patterns();
                all_patterns.extend(set.patterns);
            }

            // Build matcher
            let pattern_set = PatternSet {
                name: "Combined".to_string(),
                version: "1.0".to_string(),
                patterns: all_patterns,
            };

            let mut matcher = pattern_set.build_matcher()?;
            println!("  Patterns loaded: {}", matcher.pattern_count());
            println!();

            // Scan
            let start = Instant::now();
            let results = matcher.scan(&data);
            let elapsed = start.elapsed();

            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                println!("{}", "Results".green().bold());
                println!("{}", "-".repeat(60));

                if results.is_empty() {
                    println!("  No patterns matched");
                } else {
                    for result in &results {
                        println!("  {} {} (SID: {:?})",
                            "[MATCH]".red().bold(),
                            result.pattern_name.yellow(),
                            result.sid);
                        println!("    Offset: {} - {}", result.start, result.end);
                        println!("    Data: {:?}",
                            String::from_utf8_lossy(&result.matched_data));
                    }
                }

                println!("\n{}", "Statistics".cyan().bold());
                println!("  Bytes scanned: {}", matcher.stats().bytes_scanned);
                println!("  Patterns matched: {}", results.len());
                println!("  Time: {:?}", elapsed);
                println!("  Throughput: {:.2} MB/s",
                    (data.len() as f64 / 1_000_000.0) / elapsed.as_secs_f64());
            }
        }

        Commands::ScanHex { hex, pattern } => {
            // Parse hex data
            let data = hex::decode(hex.replace(' ', ""))?;

            // Build matcher with single pattern
            let mut compiler = PatternCompiler::new();
            compiler.add_string("pattern", &pattern, PatternModifiers::default());
            let mut matcher = compiler.build()?;

            let results = matcher.scan(&data);

            for result in &results {
                println!("{} at offset {}: {:?}",
                    "[MATCH]".green().bold(),
                    result.start,
                    String::from_utf8_lossy(&result.matched_data));
            }
        }

        Commands::Generate { output, pattern_type } => {
            let set = match pattern_type.as_str() {
                "attacks" => common_attack_patterns(),
                "protocols" => protocol_patterns(),
                _ => {
                    eprintln!("{}: Unknown pattern type '{}'", "Error".red().bold(), pattern_type);
                    std::process::exit(1);
                }
            };

            set.save(&output)?;
            println!("{} pattern set with {} patterns to {}",
                "Generated".green().bold(),
                set.patterns.len(),
                output.display());
        }

        Commands::Benchmark { file, iterations } => {
            println!("{}", "Pattern Matcher Benchmark".cyan().bold());
            println!("{}", "=".repeat(60));

            let data = fs::read(&file)?;
            let set = common_attack_patterns();
            let mut matcher = set.build_matcher()?;

            println!("  File: {} ({} bytes)", file.display(), data.len());
            println!("  Patterns: {}", matcher.pattern_count());
            println!("  Iterations: {}", iterations);
            println!();

            let start = Instant::now();
            let mut total_matches = 0;

            for _ in 0..iterations {
                let results = matcher.scan(&data);
                total_matches += results.len();
            }

            let elapsed = start.elapsed();
            let total_bytes = data.len() * iterations;

            println!("{}", "Results".green().bold());
            println!("  Total time: {:?}", elapsed);
            println!("  Avg per scan: {:?}", elapsed / iterations as u32);
            println!("  Total matches: {}", total_matches);
            println!("  Throughput: {:.2} MB/s",
                (total_bytes as f64 / 1_000_000.0) / elapsed.as_secs_f64());
        }

        Commands::Test { pattern, data, pattern_type } => {
            println!("{}", "Pattern Test".cyan().bold());
            println!("  Pattern: {}", pattern.yellow());
            println!("  Data: {}", data);
            println!("  Type: {}", pattern_type);
            println!();

            let mut compiler = PatternCompiler::new();

            match pattern_type.as_str() {
                "fixed" => {
                    compiler.add_string("test", &pattern, PatternModifiers::default());
                }
                "regex" => {
                    compiler.add_regex("test", &pattern, PatternModifiers::default())?;
                }
                "hex" => {
                    compiler.add_hex_pattern("test", &pattern, PatternModifiers::default())?;
                }
                _ => {
                    eprintln!("Unknown pattern type: {}", pattern_type);
                    std::process::exit(1);
                }
            }

            let mut matcher = compiler.build()?;
            let results = matcher.scan(data.as_bytes());

            if results.is_empty() {
                println!("{}", "No match".yellow());
            } else {
                for result in &results {
                    println!("{} at offset {}-{}: {:?}",
                        "MATCH".green().bold(),
                        result.start,
                        result.end,
                        String::from_utf8_lossy(&result.matched_data));
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_pattern_matching() {
        let mut compiler = PatternCompiler::new();
        compiler.add_string("test", "hello", PatternModifiers::default());
        let mut matcher = compiler.build().unwrap();

        let results = matcher.scan(b"hello world");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].start, 0);
        assert_eq!(results[0].end, 5);
    }

    #[test]
    fn test_multiple_patterns() {
        let mut compiler = PatternCompiler::new();
        compiler.add_string("hello", "hello", PatternModifiers::default());
        compiler.add_string("world", "world", PatternModifiers::default());
        let mut matcher = compiler.build().unwrap();

        let results = matcher.scan(b"hello world");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_regex_pattern() {
        let mut compiler = PatternCompiler::new();
        compiler.add_regex("numbers", r"\d+", PatternModifiers::default()).unwrap();
        let mut matcher = compiler.build().unwrap();

        let results = matcher.scan(b"test 123 and 456");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_hex_pattern() {
        let mut compiler = PatternCompiler::new();
        compiler.add_hex_pattern("magic", "48 65 6c 6c 6f", PatternModifiers::default()).unwrap();
        let mut matcher = compiler.build().unwrap();

        let results = matcher.scan(b"Hello world");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_hex_wildcard() {
        let mut compiler = PatternCompiler::new();
        compiler.add_hex_pattern("wildcard", "48 ?? 6c 6c 6f", PatternModifiers::default()).unwrap();
        let mut matcher = compiler.build().unwrap();

        // Should match "Hello" (48 65 6c 6c 6f)
        let results = matcher.scan(b"Hello");
        assert_eq!(results.len(), 1);

        // Should also match "Hxllo" (48 78 6c 6c 6f)
        let results = matcher.scan(b"Hxllo");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_nocase_modifier() {
        let mut compiler = PatternCompiler::new();
        compiler.add_string("test", "hello", PatternModifiers { nocase: true, ..Default::default() });
        let mut matcher = compiler.build().unwrap();

        let results = matcher.scan(b"HELLO world");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_startswith_modifier() {
        let mut compiler = PatternCompiler::new();
        compiler.add_string("start", "hello", PatternModifiers { startswith: true, ..Default::default() });
        let mut matcher = compiler.build().unwrap();

        // Should match at start
        let results = matcher.scan(b"hello world");
        assert_eq!(results.len(), 1);

        // Should not match in middle
        let results = matcher.scan(b"say hello");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_offset_depth() {
        let mut compiler = PatternCompiler::new();
        compiler.add_string("test", "world", PatternModifiers {
            offset: Some(5),
            depth: Some(15),
            ..Default::default()
        });
        let mut matcher = compiler.build().unwrap();

        let results = matcher.scan(b"hello world here");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_byte_test() {
        let mut compiler = PatternCompiler::new();
        compiler.add_byte_test(
            "port_80",
            2,
            CompareOp::Equal,
            80,
            0,
            false,
            Endianness::Big,
            PatternModifiers::default(),
        );
        let mut matcher = compiler.build().unwrap();

        // Port 80 in big endian is 0x00 0x50
        let results = matcher.scan(&[0x00, 0x50, 0x01, 0x02]);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_negated_pattern() {
        let mut compiler = PatternCompiler::new();
        compiler.add_string("not_found", "xyz", PatternModifiers { negated: true, ..Default::default() });
        let mut matcher = compiler.build().unwrap();

        // Pattern NOT in data, should "match"
        let results = matcher.scan(b"hello world");
        assert_eq!(results.len(), 1);

        // Pattern IS in data, should not "match"
        let results = matcher.scan(b"hello xyz world");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_attack_patterns() {
        let set = common_attack_patterns();
        let mut matcher = set.build_matcher().unwrap();

        // SQL injection
        let results = matcher.scan(b"SELECT * FROM users WHERE id=1 UNION SELECT * FROM admins");
        assert!(results.iter().any(|r| r.pattern_name.contains("UNION")));

        // XSS
        let results = matcher.scan(b"<script>alert('xss')</script>");
        assert!(results.iter().any(|r| r.pattern_name.contains("XSS")));

        // Path traversal
        let results = matcher.scan(b"GET /../../../etc/passwd HTTP/1.1");
        assert!(results.iter().any(|r| r.pattern_name.contains("Traversal")));
    }

    #[test]
    fn test_streaming_matcher() {
        let mut compiler = PatternCompiler::new();
        compiler.add_string("hello", "hello", PatternModifiers::default());
        let matcher = compiler.build().unwrap();

        let mut stream = StreamingMatcher::new(matcher, 1024);

        // Send data in chunks
        let _ = stream.process_chunk(b"hel");
        let _ = stream.process_chunk(b"lo w");
        let _ = stream.process_chunk(b"orld");

        let results = stream.flush();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_pattern_set_serialization() {
        let set = common_attack_patterns();
        let json = serde_json::to_string(&set).unwrap();
        let restored: PatternSet = serde_json::from_str(&json).unwrap();

        assert_eq!(set.patterns.len(), restored.patterns.len());
    }
}
