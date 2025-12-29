//! # Timestamp Parser - Security Log Analysis Tool
//!
//! Parses and converts various timestamp formats commonly found in logs.
//! Security use cases include:
//! - Correlating events across different log sources
//! - Converting timestamps for incident timelines
//! - Parsing timestamps from various system logs
//! - Timeline analysis for forensic investigations
//!
//! ## Rust Concepts Covered:
//! - Date/time handling with chrono
//! - Timezone conversions
//! - Regular expressions for format detection
//! - Enums with associated data
//! - Error handling and custom error types
//! - Serialization with serde
//! - Pattern matching with complex types

use chrono::{DateTime, FixedOffset, Local, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Timestamp Parser - Multi-format timestamp parsing and conversion tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
///
/// Demonstrates Rust's enum-based subcommand pattern
#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse a timestamp and display in multiple formats
    Parse {
        /// The timestamp string to parse
        timestamp: String,

        /// Input format hint (auto-detect if not specified)
        #[arg(short, long)]
        format: Option<TimestampFormat>,

        /// Timezone for interpretation (e.g., "America/New_York", "UTC")
        #[arg(short, long, default_value = "UTC")]
        timezone: String,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Convert timestamp between formats
    Convert {
        /// The timestamp to convert
        timestamp: String,

        /// Output format
        #[arg(short, long)]
        to: TimestampFormat,

        /// Source timezone
        #[arg(long, default_value = "UTC")]
        from_tz: String,

        /// Target timezone
        #[arg(long, default_value = "UTC")]
        to_tz: String,
    },

    /// Get current time in various formats
    Now {
        /// Output format
        #[arg(short, long, default_value = "iso8601")]
        format: TimestampFormat,

        /// Timezone (default: local)
        #[arg(short, long)]
        timezone: Option<String>,
    },

    /// Calculate time difference between two timestamps
    Diff {
        /// First timestamp
        start: String,

        /// Second timestamp
        end: String,

        /// Output format (seconds, minutes, hours, days, human)
        #[arg(short, long, default_value = "human")]
        unit: TimeUnit,
    },

    /// Add or subtract time from a timestamp
    Adjust {
        /// Base timestamp
        timestamp: String,

        /// Adjustment (e.g., "+1h", "-30m", "+7d")
        adjustment: String,

        /// Output format
        #[arg(short, long, default_value = "iso8601")]
        format: TimestampFormat,
    },

    /// Detect timestamp format from input
    Detect {
        /// The timestamp string to analyze
        timestamp: String,
    },
}

/// Supported timestamp formats
///
/// This enum demonstrates ValueEnum for CLI argument parsing
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum TimestampFormat {
    /// Unix epoch seconds
    Unix,
    /// Unix epoch milliseconds
    UnixMs,
    /// ISO 8601 format
    Iso8601,
    /// RFC 2822 format (email)
    Rfc2822,
    /// RFC 3339 format
    Rfc3339,
    /// Common log format
    CommonLog,
    /// Apache log format
    Apache,
    /// Syslog format
    Syslog,
    /// Windows file time
    WindowsFiletime,
    /// MySQL datetime
    Mysql,
    /// Human readable
    Human,
}

impl TimestampFormat {
    /// Returns the format string for parsing/formatting
    fn format_string(&self) -> &'static str {
        match self {
            TimestampFormat::Unix => "%s",
            TimestampFormat::UnixMs => "%s%.3f",
            TimestampFormat::Iso8601 => "%Y-%m-%dT%H:%M:%S%z",
            TimestampFormat::Rfc2822 => "%a, %d %b %Y %H:%M:%S %z",
            TimestampFormat::Rfc3339 => "%Y-%m-%dT%H:%M:%S%.fZ",
            TimestampFormat::CommonLog => "%d/%b/%Y:%H:%M:%S %z",
            TimestampFormat::Apache => "%d/%b/%Y:%H:%M:%S %z",
            TimestampFormat::Syslog => "%b %d %H:%M:%S",
            TimestampFormat::WindowsFiletime => "%Y-%m-%d %H:%M:%S",
            TimestampFormat::Mysql => "%Y-%m-%d %H:%M:%S",
            TimestampFormat::Human => "%B %d, %Y at %I:%M:%S %p",
        }
    }

    /// Returns a human-readable description
    fn description(&self) -> &'static str {
        match self {
            TimestampFormat::Unix => "Unix timestamp (seconds since epoch)",
            TimestampFormat::UnixMs => "Unix timestamp (milliseconds)",
            TimestampFormat::Iso8601 => "ISO 8601 format",
            TimestampFormat::Rfc2822 => "RFC 2822 (email format)",
            TimestampFormat::Rfc3339 => "RFC 3339 format",
            TimestampFormat::CommonLog => "Common Log Format",
            TimestampFormat::Apache => "Apache Log Format",
            TimestampFormat::Syslog => "Syslog format",
            TimestampFormat::WindowsFiletime => "Windows file time",
            TimestampFormat::Mysql => "MySQL datetime",
            TimestampFormat::Human => "Human readable",
        }
    }
}

/// Time units for difference calculation
#[derive(Debug, Clone, Copy, ValueEnum)]
enum TimeUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
    Human,
}

/// Result of parsing a timestamp
#[derive(Debug, Serialize)]
struct ParsedTimestamp {
    original: String,
    detected_format: String,
    utc: String,
    local: String,
    unix: i64,
    unix_ms: i64,
    iso8601: String,
    rfc2822: String,
    rfc3339: String,
    day_of_week: String,
    timezone: String,
}

/// Custom error type for timestamp parsing
///
/// Demonstrates creating custom error types in Rust
#[derive(Debug)]
enum TimestampError {
    ParseError(String),
    InvalidFormat(String),
    TimezoneError(String),
    AdjustmentError(String),
}

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            TimestampError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            TimestampError::TimezoneError(msg) => write!(f, "Timezone error: {}", msg),
            TimestampError::AdjustmentError(msg) => write!(f, "Adjustment error: {}", msg),
        }
    }
}

impl std::error::Error for TimestampError {}

/// Attempts to detect the format of a timestamp string
///
/// Uses regex patterns to identify common timestamp formats
fn detect_format(input: &str) -> Option<TimestampFormat> {
    // Define patterns for each format
    let patterns: Vec<(TimestampFormat, Regex)> = vec![
        // Unix timestamp (10 digits)
        (TimestampFormat::Unix, Regex::new(r"^\d{10}$").unwrap()),
        // Unix timestamp milliseconds (13 digits)
        (TimestampFormat::UnixMs, Regex::new(r"^\d{13}$").unwrap()),
        // ISO 8601 with timezone
        (TimestampFormat::Iso8601, Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$").unwrap()),
        // RFC 3339 with Z
        (TimestampFormat::Rfc3339, Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$").unwrap()),
        // RFC 2822
        (TimestampFormat::Rfc2822, Regex::new(r"^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}$").unwrap()),
        // Common/Apache log format
        (TimestampFormat::CommonLog, Regex::new(r"^\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}$").unwrap()),
        // Syslog format
        (TimestampFormat::Syslog, Regex::new(r"^[A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}$").unwrap()),
        // MySQL datetime
        (TimestampFormat::Mysql, Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$").unwrap()),
    ];

    // Try each pattern
    for (format, pattern) in patterns {
        if pattern.is_match(input) {
            return Some(format);
        }
    }

    None
}

/// Parses a timestamp string into a DateTime<Utc>
///
/// This function demonstrates:
/// - Pattern matching with Option and Result
/// - Multiple parsing strategies
/// - Error propagation with custom errors
fn parse_timestamp(
    input: &str,
    format_hint: Option<TimestampFormat>,
    timezone: &str,
) -> Result<DateTime<Utc>, TimestampError> {
    // Try format hint first if provided
    if let Some(format) = format_hint {
        return parse_with_format(input, format, timezone);
    }

    // Try to detect format
    if let Some(detected) = detect_format(input) {
        return parse_with_format(input, detected, timezone);
    }

    // Try common parsers
    // 1. Try parsing as Unix timestamp
    if let Ok(unix) = input.parse::<i64>() {
        if unix > 1_000_000_000_000 {
            // Milliseconds
            let secs = unix / 1000;
            let nsecs = ((unix % 1000) * 1_000_000) as u32;
            return DateTime::from_timestamp(secs, nsecs)
                .ok_or_else(|| TimestampError::ParseError("Invalid unix timestamp".to_string()));
        } else {
            // Seconds
            return DateTime::from_timestamp(unix, 0)
                .ok_or_else(|| TimestampError::ParseError("Invalid unix timestamp".to_string()));
        }
    }

    // 2. Try RFC 3339
    if let Ok(dt) = DateTime::parse_from_rfc3339(input) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 3. Try RFC 2822
    if let Ok(dt) = DateTime::parse_from_rfc2822(input) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 4. Try MySQL format
    if let Ok(naive) = NaiveDateTime::parse_from_str(input, "%Y-%m-%d %H:%M:%S") {
        let tz = parse_timezone(timezone)?;
        return Ok(tz.from_local_datetime(&naive)
            .single()
            .ok_or_else(|| TimestampError::ParseError("Ambiguous time".to_string()))?
            .with_timezone(&Utc));
    }

    Err(TimestampError::ParseError(format!(
        "Could not parse timestamp: {}",
        input
    )))
}

/// Parses a timestamp with a specific format
fn parse_with_format(
    input: &str,
    format: TimestampFormat,
    timezone: &str,
) -> Result<DateTime<Utc>, TimestampError> {
    match format {
        TimestampFormat::Unix => {
            let unix: i64 = input.parse()
                .map_err(|_| TimestampError::ParseError("Invalid unix timestamp".to_string()))?;
            DateTime::from_timestamp(unix, 0)
                .ok_or_else(|| TimestampError::ParseError("Invalid unix timestamp".to_string()))
        }
        TimestampFormat::UnixMs => {
            let unix_ms: i64 = input.parse()
                .map_err(|_| TimestampError::ParseError("Invalid unix timestamp".to_string()))?;
            let secs = unix_ms / 1000;
            let nsecs = ((unix_ms % 1000) * 1_000_000) as u32;
            DateTime::from_timestamp(secs, nsecs)
                .ok_or_else(|| TimestampError::ParseError("Invalid unix timestamp".to_string()))
        }
        TimestampFormat::Iso8601 | TimestampFormat::Rfc3339 => {
            DateTime::parse_from_rfc3339(input)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| TimestampError::ParseError(e.to_string()))
        }
        TimestampFormat::Rfc2822 => {
            DateTime::parse_from_rfc2822(input)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| TimestampError::ParseError(e.to_string()))
        }
        TimestampFormat::CommonLog | TimestampFormat::Apache => {
            DateTime::parse_from_str(input, "%d/%b/%Y:%H:%M:%S %z")
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| TimestampError::ParseError(e.to_string()))
        }
        TimestampFormat::Mysql | TimestampFormat::WindowsFiletime => {
            let naive = NaiveDateTime::parse_from_str(input, "%Y-%m-%d %H:%M:%S")
                .map_err(|e| TimestampError::ParseError(e.to_string()))?;
            let tz = parse_timezone(timezone)?;
            tz.from_local_datetime(&naive)
                .single()
                .ok_or_else(|| TimestampError::ParseError("Ambiguous time".to_string()))
                .map(|dt| dt.with_timezone(&Utc))
        }
        TimestampFormat::Syslog => {
            // Syslog doesn't have year, assume current year
            let current_year = Utc::now().format("%Y").to_string();
            let with_year = format!("{} {}", current_year, input);
            let naive = NaiveDateTime::parse_from_str(&with_year, "%Y %b %d %H:%M:%S")
                .map_err(|e| TimestampError::ParseError(e.to_string()))?;
            let tz = parse_timezone(timezone)?;
            tz.from_local_datetime(&naive)
                .single()
                .ok_or_else(|| TimestampError::ParseError("Ambiguous time".to_string()))
                .map(|dt| dt.with_timezone(&Utc))
        }
        TimestampFormat::Human => {
            // Try to parse human-readable format
            Err(TimestampError::ParseError(
                "Human format is output-only".to_string()
            ))
        }
    }
}

/// Parses a timezone string into a Tz
fn parse_timezone(tz_str: &str) -> Result<Tz, TimestampError> {
    if tz_str.eq_ignore_ascii_case("UTC") || tz_str.eq_ignore_ascii_case("Z") {
        return Ok(chrono_tz::UTC);
    }

    if tz_str.eq_ignore_ascii_case("local") {
        // Get local timezone - this is a simplified approach
        return Ok(chrono_tz::UTC); // Fallback to UTC
    }

    Tz::from_str(tz_str).map_err(|_| {
        TimestampError::TimezoneError(format!("Unknown timezone: {}", tz_str))
    })
}

/// Formats a DateTime in the specified format
fn format_timestamp(dt: DateTime<Utc>, format: TimestampFormat) -> String {
    match format {
        TimestampFormat::Unix => dt.timestamp().to_string(),
        TimestampFormat::UnixMs => (dt.timestamp() * 1000 + dt.timestamp_subsec_millis() as i64).to_string(),
        TimestampFormat::Iso8601 => dt.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        TimestampFormat::Rfc2822 => dt.to_rfc2822(),
        TimestampFormat::Rfc3339 => dt.to_rfc3339(),
        TimestampFormat::CommonLog | TimestampFormat::Apache => {
            dt.format("%d/%b/%Y:%H:%M:%S +0000").to_string()
        }
        TimestampFormat::Syslog => dt.format("%b %d %H:%M:%S").to_string(),
        TimestampFormat::Mysql | TimestampFormat::WindowsFiletime => {
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        TimestampFormat::Human => dt.format("%B %d, %Y at %I:%M:%S %p UTC").to_string(),
    }
}

/// Creates a ParsedTimestamp from a DateTime
fn create_parsed_result(dt: DateTime<Utc>, original: &str, format_name: &str) -> ParsedTimestamp {
    let local: DateTime<Local> = dt.with_timezone(&Local);

    ParsedTimestamp {
        original: original.to_string(),
        detected_format: format_name.to_string(),
        utc: dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        local: local.format("%Y-%m-%d %H:%M:%S %Z").to_string(),
        unix: dt.timestamp(),
        unix_ms: dt.timestamp_millis(),
        iso8601: dt.to_rfc3339(),
        rfc2822: dt.to_rfc2822(),
        rfc3339: dt.to_rfc3339(),
        day_of_week: dt.format("%A").to_string(),
        timezone: "UTC".to_string(),
    }
}

/// Parses an adjustment string (e.g., "+1h", "-30m", "+7d")
fn parse_adjustment(adj: &str) -> Result<chrono::Duration, TimestampError> {
    let pattern = Regex::new(r"^([+-])(\d+)([smhdwMy])$").unwrap();

    if let Some(caps) = pattern.captures(adj) {
        let sign = if &caps[1] == "-" { -1i64 } else { 1i64 };
        let amount: i64 = caps[2].parse()
            .map_err(|_| TimestampError::AdjustmentError("Invalid number".to_string()))?;
        let unit = &caps[3];

        let duration = match unit {
            "s" => chrono::Duration::seconds(amount * sign),
            "m" => chrono::Duration::minutes(amount * sign),
            "h" => chrono::Duration::hours(amount * sign),
            "d" => chrono::Duration::days(amount * sign),
            "w" => chrono::Duration::weeks(amount * sign),
            "M" => chrono::Duration::days(amount * sign * 30), // Approximate
            "y" => chrono::Duration::days(amount * sign * 365), // Approximate
            _ => return Err(TimestampError::AdjustmentError("Invalid unit".to_string())),
        };

        Ok(duration)
    } else {
        Err(TimestampError::AdjustmentError(format!(
            "Invalid adjustment format: {}. Use +1h, -30m, +7d, etc.",
            adj
        )))
    }
}

/// Formats a duration in human-readable format
fn format_duration(duration: chrono::Duration) -> String {
    let total_secs = duration.num_seconds().abs();

    if total_secs < 60 {
        format!("{} seconds", total_secs)
    } else if total_secs < 3600 {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{} minutes, {} seconds", mins, secs)
    } else if total_secs < 86400 {
        let hours = total_secs / 3600;
        let mins = (total_secs % 3600) / 60;
        format!("{} hours, {} minutes", hours, mins)
    } else {
        let days = total_secs / 86400;
        let hours = (total_secs % 86400) / 3600;
        format!("{} days, {} hours", days, hours)
    }
}

fn main() {
    let args = Args::parse();

    let result = match args.command {
        Commands::Parse { timestamp, format, timezone, json } => {
            handle_parse(&timestamp, format, &timezone, json)
        }
        Commands::Convert { timestamp, to, from_tz, to_tz } => {
            handle_convert(&timestamp, to, &from_tz, &to_tz)
        }
        Commands::Now { format, timezone } => {
            handle_now(format, timezone.as_deref())
        }
        Commands::Diff { start, end, unit } => {
            handle_diff(&start, &end, unit)
        }
        Commands::Adjust { timestamp, adjustment, format } => {
            handle_adjust(&timestamp, &adjustment, format)
        }
        Commands::Detect { timestamp } => {
            handle_detect(&timestamp)
        }
    };

    if let Err(e) = result {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

/// Handles the parse subcommand
fn handle_parse(
    timestamp: &str,
    format: Option<TimestampFormat>,
    timezone: &str,
    json: bool,
) -> Result<(), TimestampError> {
    let dt = parse_timestamp(timestamp, format, timezone)?;
    let format_name = format.map(|f| f.description()).unwrap_or("Auto-detected");
    let result = create_parsed_result(dt, timestamp, format_name);

    if json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        println!("{}", "Parsed Timestamp".bold().green());
        println!("{}", "=".repeat(50).dimmed());
        println!("  Original:     {}", result.original.cyan());
        println!("  Format:       {}", result.detected_format.yellow());
        println!("  UTC:          {}", result.utc.white());
        println!("  Local:        {}", result.local.white());
        println!("  Unix:         {}", result.unix.to_string().cyan());
        println!("  Unix (ms):    {}", result.unix_ms.to_string().cyan());
        println!("  ISO 8601:     {}", result.iso8601);
        println!("  RFC 2822:     {}", result.rfc2822);
        println!("  Day of Week:  {}", result.day_of_week);
    }

    Ok(())
}

/// Handles the convert subcommand
fn handle_convert(
    timestamp: &str,
    to: TimestampFormat,
    from_tz: &str,
    to_tz: &str,
) -> Result<(), TimestampError> {
    let dt = parse_timestamp(timestamp, None, from_tz)?;

    // Convert to target timezone
    let target_tz = parse_timezone(to_tz)?;
    let dt_target = dt.with_timezone(&target_tz);

    // Format in target format
    let result = format_timestamp(dt_target.with_timezone(&Utc), to);

    println!("{}", result);
    Ok(())
}

/// Handles the now subcommand
fn handle_now(format: TimestampFormat, timezone: Option<&str>) -> Result<(), TimestampError> {
    let now = Utc::now();

    if let Some(tz_str) = timezone {
        let tz = parse_timezone(tz_str)?;
        let dt_tz = now.with_timezone(&tz);
        println!("{}", format_timestamp(dt_tz.with_timezone(&Utc), format));
    } else {
        println!("{}", format_timestamp(now, format));
    }

    Ok(())
}

/// Handles the diff subcommand
fn handle_diff(start: &str, end: &str, unit: TimeUnit) -> Result<(), TimestampError> {
    let dt_start = parse_timestamp(start, None, "UTC")?;
    let dt_end = parse_timestamp(end, None, "UTC")?;

    let duration = dt_end.signed_duration_since(dt_start);

    let result = match unit {
        TimeUnit::Seconds => format!("{} seconds", duration.num_seconds()),
        TimeUnit::Minutes => format!("{:.2} minutes", duration.num_seconds() as f64 / 60.0),
        TimeUnit::Hours => format!("{:.2} hours", duration.num_seconds() as f64 / 3600.0),
        TimeUnit::Days => format!("{:.2} days", duration.num_seconds() as f64 / 86400.0),
        TimeUnit::Human => format_duration(duration),
    };

    println!("{}", "Time Difference".bold().green());
    println!("  Start: {}", dt_start.to_rfc3339().cyan());
    println!("  End:   {}", dt_end.to_rfc3339().cyan());
    println!("  Diff:  {}", result.yellow().bold());

    Ok(())
}

/// Handles the adjust subcommand
fn handle_adjust(
    timestamp: &str,
    adjustment: &str,
    format: TimestampFormat,
) -> Result<(), TimestampError> {
    let dt = parse_timestamp(timestamp, None, "UTC")?;
    let duration = parse_adjustment(adjustment)?;
    let adjusted = dt + duration;

    println!("{}", "Time Adjustment".bold().green());
    println!("  Original:   {}", dt.to_rfc3339().cyan());
    println!("  Adjustment: {}", adjustment.yellow());
    println!("  Result:     {}", format_timestamp(adjusted, format).green().bold());

    Ok(())
}

/// Handles the detect subcommand
fn handle_detect(timestamp: &str) -> Result<(), TimestampError> {
    println!("{}", "Format Detection".bold().green());
    println!("  Input: {}", timestamp.cyan());

    if let Some(format) = detect_format(timestamp) {
        println!("  Detected: {}", format.description().green().bold());

        // Try to parse it
        if let Ok(dt) = parse_timestamp(timestamp, Some(format), "UTC") {
            println!("  Parsed as: {}", dt.to_rfc3339().yellow());
        }
    } else {
        // Try auto-parse
        if let Ok(dt) = parse_timestamp(timestamp, None, "UTC") {
            println!("  Detected: {} (auto-parsed)", "Unknown format".yellow());
            println!("  Parsed as: {}", dt.to_rfc3339().green());
        } else {
            println!("  Detected: {}", "Could not determine format".red());
        }
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_unix_format() {
        assert_eq!(detect_format("1609459200"), Some(TimestampFormat::Unix));
        assert_eq!(detect_format("1609459200000"), Some(TimestampFormat::UnixMs));
    }

    #[test]
    fn test_detect_iso_format() {
        assert_eq!(
            detect_format("2021-01-01T00:00:00Z"),
            Some(TimestampFormat::Rfc3339)
        );
        assert_eq!(
            detect_format("2021-01-01T00:00:00+00:00"),
            Some(TimestampFormat::Iso8601)
        );
    }

    #[test]
    fn test_detect_mysql_format() {
        assert_eq!(
            detect_format("2021-01-01 12:30:45"),
            Some(TimestampFormat::Mysql)
        );
    }

    #[test]
    fn test_parse_unix() {
        let dt = parse_timestamp("1609459200", Some(TimestampFormat::Unix), "UTC").unwrap();
        assert_eq!(dt.timestamp(), 1609459200);
    }

    #[test]
    fn test_parse_unix_ms() {
        let dt = parse_timestamp("1609459200000", Some(TimestampFormat::UnixMs), "UTC").unwrap();
        assert_eq!(dt.timestamp(), 1609459200);
    }

    #[test]
    fn test_parse_rfc3339() {
        let dt = parse_timestamp("2021-01-01T00:00:00Z", None, "UTC").unwrap();
        assert_eq!(dt.timestamp(), 1609459200);
    }

    #[test]
    fn test_format_timestamp() {
        let dt = DateTime::from_timestamp(1609459200, 0).unwrap();

        assert_eq!(format_timestamp(dt, TimestampFormat::Unix), "1609459200");
        assert!(format_timestamp(dt, TimestampFormat::Iso8601).contains("2021-01-01"));
    }

    #[test]
    fn test_parse_adjustment() {
        let dur = parse_adjustment("+1h").unwrap();
        assert_eq!(dur.num_hours(), 1);

        let dur = parse_adjustment("-30m").unwrap();
        assert_eq!(dur.num_minutes(), -30);

        let dur = parse_adjustment("+7d").unwrap();
        assert_eq!(dur.num_days(), 7);
    }

    #[test]
    fn test_format_duration() {
        let dur = chrono::Duration::seconds(3661);
        let result = format_duration(dur);
        assert!(result.contains("hour"));
        assert!(result.contains("minute"));
    }

    #[test]
    fn test_invalid_format() {
        let result = parse_timestamp("not-a-timestamp", None, "UTC");
        assert!(result.is_err());
    }

    #[test]
    fn test_timezone_parsing() {
        let tz = parse_timezone("America/New_York").unwrap();
        assert_eq!(tz.to_string(), "America/New_York");

        let tz = parse_timezone("UTC").unwrap();
        assert_eq!(tz.to_string(), "UTC");
    }

    #[test]
    fn test_invalid_timezone() {
        let result = parse_timezone("Invalid/Zone");
        assert!(result.is_err());
    }

    #[test]
    fn test_syslog_format_detection() {
        assert_eq!(
            detect_format("Jan  5 14:32:10"),
            Some(TimestampFormat::Syslog)
        );
    }

    #[test]
    fn test_common_log_format_detection() {
        assert_eq!(
            detect_format("10/Oct/2024:13:55:36 -0700"),
            Some(TimestampFormat::CommonLog)
        );
    }
}
