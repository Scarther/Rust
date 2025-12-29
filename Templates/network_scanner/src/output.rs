//! Output formatting for network scan results

use anyhow::Result;
use colored::Colorize;

use crate::{HostResult, PortResult, ScanResults};

/// Print port scan results in the specified format
pub fn print_port_results(results: &ScanResults, format: &str) -> Result<()> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(results)?);
        }
        "csv" => {
            println!("port,state,service,banner");
            for port in &results.ports {
                println!(
                    "{},{},{},{}",
                    port.port,
                    port.state,
                    port.service.as_deref().unwrap_or("unknown"),
                    port.banner.as_deref().unwrap_or("").replace(',', ";")
                );
            }
        }
        _ => {
            // Text format
            println!("\n{}", "PORT SCAN RESULTS".bold().underline());
            println!("Target: {}", results.target.cyan());
            println!("Time: {}", results.timestamp);
            println!("Duration: {}ms", results.duration_ms);
            println!();

            if results.ports.is_empty() {
                println!("{}", "No open ports found".yellow());
            } else {
                println!(
                    "{:<8} {:<10} {:<15} {}",
                    "PORT".bold(),
                    "STATE".bold(),
                    "SERVICE".bold(),
                    "BANNER".bold()
                );
                println!("{}", "-".repeat(60));

                for port in &results.ports {
                    let service = port.service.as_deref().unwrap_or("unknown");
                    let banner = port
                        .banner
                        .as_ref()
                        .map(|b| truncate(b, 30))
                        .unwrap_or_default();

                    println!(
                        "{:<8} {:<10} {:<15} {}",
                        port.port.to_string().green(),
                        port.state.green(),
                        service,
                        banner.dimmed()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Print host sweep results in the specified format
pub fn print_host_results(results: &[HostResult], format: &str) -> Result<()> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(results)?);
        }
        "csv" => {
            println!("ip,alive,latency_ms");
            for host in results {
                println!(
                    "{},{},{}",
                    host.ip,
                    host.alive,
                    host.latency_ms.map(|l| l.to_string()).unwrap_or_default()
                );
            }
        }
        _ => {
            // Text format
            println!("\n{}", "HOST SWEEP RESULTS".bold().underline());
            println!();

            if results.is_empty() {
                println!("{}", "No live hosts found".yellow());
            } else {
                println!(
                    "{:<20} {:<10} {}",
                    "IP ADDRESS".bold(),
                    "STATUS".bold(),
                    "LATENCY".bold()
                );
                println!("{}", "-".repeat(45));

                for host in results {
                    let latency = host
                        .latency_ms
                        .map(|l| format!("{}ms", l))
                        .unwrap_or_default();

                    println!(
                        "{:<20} {:<10} {}",
                        host.ip.cyan(),
                        "alive".green(),
                        latency
                    );
                }
            }

            println!("\n{} live hosts", results.len());
        }
    }

    Ok(())
}

/// Truncate a string to a maximum length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Format bytes as human-readable size
#[allow(dead_code)]
pub fn format_bytes(bytes: u64) -> String {
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

/// Format a duration in a human-readable way
#[allow(dead_code)]
pub fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{}m {}s", mins, secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(1500), "1.5s");
        assert_eq!(format_duration(90000), "1m 30s");
    }
}
