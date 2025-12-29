//! Output formatting for scan results

use crate::scanner::{Finding, ScanStats};
use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::path::Path;
use std::time::Duration;

/// Output format enum
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
    Markdown,
}

/// Print scan results in the specified format
pub fn print_scan_results(
    findings: &[Finding],
    stats: &ScanStats,
    duration: Duration,
    format: OutputFormat,
    output_path: Option<&Path>,
) -> Result<()> {
    let output = match format {
        OutputFormat::Text => format_text(findings, stats, duration),
        OutputFormat::Json => format_json(findings, stats, duration)?,
        OutputFormat::Csv => format_csv(findings),
        OutputFormat::Markdown => format_markdown(findings, stats, duration),
    };

    match output_path {
        Some(path) => std::fs::write(path, &output)?,
        None => print!("{}", output),
    }

    Ok(())
}

/// Format as human-readable text
fn format_text(findings: &[Finding], stats: &ScanStats, duration: Duration) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "\n{}\n",
        "IOC SCAN RESULTS".bold().underline()
    ));
    output.push_str(&format!("Duration: {:.2}s\n", duration.as_secs_f64()));
    output.push_str(&format!("Files Scanned: {}\n", stats.files_scanned));
    output.push_str(&format!(
        "Data Scanned: {}\n",
        format_bytes(stats.bytes_scanned)
    ));
    output.push_str(&format!("Errors: {}\n", stats.errors));
    output.push('\n');

    if findings.is_empty() {
        output.push_str(&format!("{}\n", "No threats detected.".green()));
    } else {
        output.push_str(&format!(
            "{} {} FINDINGS:\n\n",
            "[!]".red().bold(),
            findings.len()
        ));

        for (i, finding) in findings.iter().enumerate() {
            output.push_str(&format!(
                "{}. {} [{}]\n",
                i + 1,
                severity_icon(&finding.severity),
                finding.severity.to_uppercase()
            ));
            output.push_str(&format!("   File: {}\n", finding.file_path.cyan()));
            output.push_str(&format!("   Type: {}\n", finding.ioc_type));
            output.push_str(&format!("   IOC: {}\n", finding.ioc_value.red()));

            if !finding.description.is_empty() {
                output.push_str(&format!("   Description: {}\n", finding.description));
            }

            if let Some(line) = finding.line_number {
                output.push_str(&format!("   Line: {}\n", line));
            }

            if let Some(context) = &finding.context {
                output.push_str(&format!("   Context: {}\n", context.dimmed()));
            }

            output.push('\n');
        }
    }

    output
}

/// Format as JSON
fn format_json(findings: &[Finding], stats: &ScanStats, duration: Duration) -> Result<String> {
    #[derive(Serialize)]
    struct Report {
        scan_stats: Stats,
        findings: Vec<Finding>,
    }

    #[derive(Serialize)]
    struct Stats {
        files_scanned: usize,
        bytes_scanned: u64,
        errors: usize,
        duration_seconds: f64,
        findings_count: usize,
    }

    let report = Report {
        scan_stats: Stats {
            files_scanned: stats.files_scanned,
            bytes_scanned: stats.bytes_scanned,
            errors: stats.errors,
            duration_seconds: duration.as_secs_f64(),
            findings_count: findings.len(),
        },
        findings: findings.to_vec(),
    };

    Ok(serde_json::to_string_pretty(&report)?)
}

/// Format as CSV
fn format_csv(findings: &[Finding]) -> String {
    let mut output =
        String::from("file_path,ioc_type,ioc_value,severity,description,line_number\n");

    for finding in findings {
        output.push_str(&format!(
            "\"{}\",{},{},{},\"{}\",{}\n",
            finding.file_path.replace('"', "\"\""),
            finding.ioc_type,
            finding.ioc_value,
            finding.severity,
            finding.description.replace('"', "\"\""),
            finding.line_number.map(|n| n.to_string()).unwrap_or_default()
        ));
    }

    output
}

/// Format as Markdown
fn format_markdown(findings: &[Finding], stats: &ScanStats, duration: Duration) -> String {
    let mut output = String::new();

    output.push_str("# IOC Scan Report\n\n");
    output.push_str("## Summary\n\n");
    output.push_str("| Metric | Value |\n");
    output.push_str("|--------|-------|\n");
    output.push_str(&format!(
        "| Duration | {:.2}s |\n",
        duration.as_secs_f64()
    ));
    output.push_str(&format!("| Files Scanned | {} |\n", stats.files_scanned));
    output.push_str(&format!(
        "| Data Scanned | {} |\n",
        format_bytes(stats.bytes_scanned)
    ));
    output.push_str(&format!("| Findings | {} |\n", findings.len()));
    output.push_str(&format!("| Errors | {} |\n", stats.errors));
    output.push('\n');

    if !findings.is_empty() {
        output.push_str("## Findings\n\n");
        output.push_str("| Severity | Type | File | IOC | Description |\n");
        output.push_str("|----------|------|------|-----|-------------|\n");

        for finding in findings {
            output.push_str(&format!(
                "| {} | {} | {} | `{}` | {} |\n",
                finding.severity.to_uppercase(),
                finding.ioc_type,
                truncate(&finding.file_path, 30),
                truncate(&finding.ioc_value, 20),
                truncate(&finding.description, 30)
            ));
        }
    } else {
        output.push_str("## Result\n\n");
        output.push_str("No threats detected.\n");
    }

    output
}

/// Get severity icon
fn severity_icon(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "[!!!]".red().bold().to_string(),
        "high" => "[!!]".red().to_string(),
        "medium" => "[!]".yellow().to_string(),
        "low" => "[*]".green().to_string(),
        _ => "[?]".to_string(),
    }
}

/// Format bytes as human-readable
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Truncate string for display
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1_048_576), "1.00 MB");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a very long string", 10), "this is...");
    }
}
