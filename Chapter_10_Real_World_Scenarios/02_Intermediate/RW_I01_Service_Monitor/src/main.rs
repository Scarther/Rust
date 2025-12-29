//! Service Health and Uptime Monitor
//!
//! A comprehensive service monitoring tool for security operations.
//! Monitors HTTP/HTTPS endpoints, TCP services, and tracks uptime metrics.
//!
//! Features:
//! - Multi-protocol monitoring (HTTP, HTTPS, TCP)
//! - Configurable health checks with custom intervals
//! - Response time tracking and alerting
//! - Uptime percentage calculation
//! - Alert notifications via multiple channels
//! - Historical data and trend analysis

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Service Monitor CLI
#[derive(Parser)]
#[command(name = "service-monitor")]
#[command(about = "Monitor service health and uptime for security operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start monitoring services from config file
    Monitor {
        /// Configuration file path
        #[arg(short, long)]
        config: PathBuf,

        /// Check interval in seconds
        #[arg(short, long, default_value = "30")]
        interval: u64,

        /// Run once and exit
        #[arg(long)]
        once: bool,
    },
    /// Check a single service
    Check {
        /// Service URL or host:port
        #[arg(short, long)]
        target: String,

        /// Service type (http, https, tcp)
        #[arg(short = 'T', long, default_value = "https")]
        service_type: String,

        /// Expected status code for HTTP services
        #[arg(short, long, default_value = "200")]
        expected_status: u16,

        /// Timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
    /// Generate sample configuration
    GenerateConfig {
        /// Output file path
        #[arg(short, long, default_value = "services.json")]
        output: PathBuf,
    },
    /// Show monitoring statistics
    Stats {
        /// Stats file path
        #[arg(short, long, default_value = "monitor_stats.json")]
        stats_file: PathBuf,
    },
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceConfig {
    name: String,
    target: String,
    service_type: ServiceType,
    #[serde(default = "default_interval")]
    check_interval_secs: u64,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    expected_status: Option<u16>,
    #[serde(default)]
    expected_content: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    critical: bool,
    #[serde(default)]
    tags: Vec<String>,
}

fn default_interval() -> u64 { 30 }
fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ServiceType {
    Http,
    Https,
    Tcp,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitorConfig {
    services: Vec<ServiceConfig>,
    #[serde(default)]
    alert_config: AlertConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AlertConfig {
    #[serde(default)]
    slack_webhook: Option<String>,
    #[serde(default)]
    email_to: Option<String>,
    #[serde(default)]
    consecutive_failures_threshold: Option<u32>,
    #[serde(default)]
    response_time_threshold_ms: Option<u64>,
}

/// Check result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    service_name: String,
    target: String,
    timestamp: DateTime<Utc>,
    success: bool,
    response_time_ms: u64,
    status_code: Option<u16>,
    error_message: Option<String>,
    content_matched: Option<bool>,
}

/// Service statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceStats {
    service_name: String,
    total_checks: u64,
    successful_checks: u64,
    failed_checks: u64,
    uptime_percentage: f64,
    avg_response_time_ms: f64,
    min_response_time_ms: u64,
    max_response_time_ms: u64,
    last_check: Option<DateTime<Utc>>,
    last_success: Option<DateTime<Utc>>,
    last_failure: Option<DateTime<Utc>>,
    consecutive_failures: u32,
    response_times: Vec<u64>,
}

impl Default for ServiceStats {
    fn default() -> Self {
        Self {
            service_name: String::new(),
            total_checks: 0,
            successful_checks: 0,
            failed_checks: 0,
            uptime_percentage: 100.0,
            avg_response_time_ms: 0.0,
            min_response_time_ms: u64::MAX,
            max_response_time_ms: 0,
            last_check: None,
            last_success: None,
            last_failure: None,
            consecutive_failures: 0,
            response_times: Vec::new(),
        }
    }
}

/// Service monitor
struct ServiceMonitor {
    client: Client,
    stats: Arc<RwLock<HashMap<String, ServiceStats>>>,
    alert_config: AlertConfig,
}

impl ServiceMonitor {
    fn new(alert_config: AlertConfig) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(StdDuration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            stats: Arc::new(RwLock::new(HashMap::new())),
            alert_config,
        })
    }

    /// Check a service
    async fn check_service(&self, config: &ServiceConfig) -> CheckResult {
        let start = Instant::now();
        let timestamp = Utc::now();

        let result = match config.service_type {
            ServiceType::Http | ServiceType::Https => {
                self.check_http_service(config).await
            }
            ServiceType::Tcp => {
                self.check_tcp_service(config).await
            }
        };

        let response_time_ms = start.elapsed().as_millis() as u64;

        let (success, status_code, error_message, content_matched) = match result {
            Ok((status, content_ok)) => (true, Some(status), None, Some(content_ok)),
            Err(e) => (false, None, Some(e.to_string()), None),
        };

        let check_result = CheckResult {
            service_name: config.name.clone(),
            target: config.target.clone(),
            timestamp,
            success,
            response_time_ms,
            status_code,
            error_message,
            content_matched,
        };

        // Update statistics
        self.update_stats(&check_result).await;

        check_result
    }

    /// Check HTTP/HTTPS service
    async fn check_http_service(&self, config: &ServiceConfig) -> Result<(u16, bool)> {
        let mut request = self.client
            .get(&config.target)
            .timeout(StdDuration::from_secs(config.timeout_secs));

        for (key, value) in &config.headers {
            request = request.header(key, value);
        }

        let response = request.send().await
            .context("Failed to send HTTP request")?;

        let status = response.status().as_u16();

        // Check expected status
        if let Some(expected) = config.expected_status {
            if status != expected {
                anyhow::bail!("Unexpected status code: {} (expected {})", status, expected);
            }
        }

        // Check content if specified
        let content_matched = if let Some(ref expected_content) = config.expected_content {
            let body = response.text().await
                .context("Failed to read response body")?;
            body.contains(expected_content)
        } else {
            true
        };

        if !content_matched {
            anyhow::bail!("Expected content not found in response");
        }

        Ok((status, content_matched))
    }

    /// Check TCP service
    async fn check_tcp_service(&self, config: &ServiceConfig) -> Result<(u16, bool)> {
        let target = config.target.clone();
        let timeout = config.timeout_secs;

        // Run TCP check in blocking task
        tokio::task::spawn_blocking(move || {
            let stream = TcpStream::connect_timeout(
                &target.parse().context("Invalid address")?,
                StdDuration::from_secs(timeout),
            ).context("TCP connection failed")?;

            // Verify connection is alive
            stream.peer_addr().context("Failed to get peer address")?;

            Ok((0u16, true)) // TCP doesn't have status codes
        }).await?
    }

    /// Update statistics for a service
    async fn update_stats(&self, result: &CheckResult) {
        let mut stats = self.stats.write().await;

        let entry = stats.entry(result.service_name.clone())
            .or_insert_with(|| ServiceStats {
                service_name: result.service_name.clone(),
                ..Default::default()
            });

        entry.total_checks += 1;
        entry.last_check = Some(result.timestamp);

        if result.success {
            entry.successful_checks += 1;
            entry.last_success = Some(result.timestamp);
            entry.consecutive_failures = 0;

            // Update response time stats
            entry.response_times.push(result.response_time_ms);
            if entry.response_times.len() > 1000 {
                entry.response_times.remove(0);
            }

            entry.min_response_time_ms = entry.min_response_time_ms.min(result.response_time_ms);
            entry.max_response_time_ms = entry.max_response_time_ms.max(result.response_time_ms);
            entry.avg_response_time_ms = entry.response_times.iter().sum::<u64>() as f64
                / entry.response_times.len() as f64;
        } else {
            entry.failed_checks += 1;
            entry.last_failure = Some(result.timestamp);
            entry.consecutive_failures += 1;
        }

        entry.uptime_percentage = (entry.successful_checks as f64 / entry.total_checks as f64) * 100.0;

        // Check if we need to alert
        if let Some(threshold) = self.alert_config.consecutive_failures_threshold {
            if entry.consecutive_failures >= threshold {
                warn!(
                    "Service {} has {} consecutive failures (threshold: {})",
                    result.service_name, entry.consecutive_failures, threshold
                );
            }
        }

        if let Some(threshold) = self.alert_config.response_time_threshold_ms {
            if result.success && result.response_time_ms > threshold {
                warn!(
                    "Service {} response time {}ms exceeds threshold {}ms",
                    result.service_name, result.response_time_ms, threshold
                );
            }
        }
    }

    /// Get current statistics
    async fn get_stats(&self) -> HashMap<String, ServiceStats> {
        self.stats.read().await.clone()
    }

    /// Display check result
    fn display_result(&self, result: &CheckResult, config: &ServiceConfig) {
        let status_icon = if result.success { "✓".green() } else { "✗".red() };
        let critical_indicator = if config.critical { "[CRITICAL]".red().bold() } else { "".normal() };

        println!(
            "{} {} {} {} - {}ms {}",
            result.timestamp.format("%Y-%m-%d %H:%M:%S"),
            status_icon,
            result.service_name.bold(),
            critical_indicator,
            result.response_time_ms,
            if let Some(status) = result.status_code {
                format!("(HTTP {})", status)
            } else {
                String::new()
            }
        );

        if let Some(ref error) = result.error_message {
            println!("  {} {}", "Error:".red(), error);
        }
    }

    /// Run monitoring loop
    async fn run_monitoring(&self, config: MonitorConfig, check_interval: u64, once: bool) -> Result<()> {
        info!("Starting service monitoring with {} services", config.services.len());

        println!("\n{}", "=".repeat(70).cyan());
        println!("{}", "Service Health Monitor".bold().cyan());
        println!("{}", "=".repeat(70).cyan());
        println!("Monitoring {} services every {} seconds\n",
            config.services.len().to_string().yellow(),
            check_interval.to_string().yellow()
        );

        loop {
            println!("\n{} {}",
                "Check cycle started:".blue(),
                Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!("{}", "-".repeat(50));

            for service in &config.services {
                let result = self.check_service(service).await;
                self.display_result(&result, service);

                // Send alert if needed
                if !result.success && service.critical {
                    self.send_alert(&result, service).await;
                }
            }

            // Display summary
            self.display_summary().await;

            if once {
                break;
            }

            // Wait for next check cycle
            tokio::time::sleep(tokio::time::Duration::from_secs(check_interval)).await;
        }

        Ok(())
    }

    /// Display monitoring summary
    async fn display_summary(&self) {
        let stats = self.stats.read().await;

        println!("\n{}", "Summary:".bold());

        let mut healthy = 0;
        let mut degraded = 0;
        let mut down = 0;

        for (name, stat) in stats.iter() {
            if stat.consecutive_failures == 0 {
                healthy += 1;
            } else if stat.consecutive_failures < 3 {
                degraded += 1;
            } else {
                down += 1;
            }
        }

        println!("  {} Healthy: {}", "●".green(), healthy.to_string().green());
        println!("  {} Degraded: {}", "●".yellow(), degraded.to_string().yellow());
        println!("  {} Down: {}", "●".red(), down.to_string().red());
    }

    /// Send alert for failed service
    async fn send_alert(&self, result: &CheckResult, config: &ServiceConfig) {
        warn!(
            "ALERT: Critical service {} is DOWN! Error: {:?}",
            config.name,
            result.error_message
        );

        // Slack webhook notification
        if let Some(ref webhook_url) = self.alert_config.slack_webhook {
            let payload = serde_json::json!({
                "text": format!(
                    "🚨 *ALERT*: Service `{}` is DOWN!\n*Target*: {}\n*Error*: {}\n*Time*: {}",
                    config.name,
                    config.target,
                    result.error_message.as_deref().unwrap_or("Unknown error"),
                    result.timestamp
                )
            });

            if let Err(e) = self.client
                .post(webhook_url)
                .json(&payload)
                .send()
                .await
            {
                error!("Failed to send Slack alert: {}", e);
            }
        }
    }
}

/// Check a single service
async fn check_single_service(
    target: String,
    service_type: String,
    expected_status: u16,
    timeout: u64,
) -> Result<()> {
    let svc_type = match service_type.to_lowercase().as_str() {
        "http" => ServiceType::Http,
        "https" => ServiceType::Https,
        "tcp" => ServiceType::Tcp,
        _ => anyhow::bail!("Unknown service type: {}", service_type),
    };

    let config = ServiceConfig {
        name: "Single Check".to_string(),
        target: target.clone(),
        service_type: svc_type,
        check_interval_secs: 30,
        timeout_secs: timeout,
        expected_status: Some(expected_status),
        expected_content: None,
        headers: HashMap::new(),
        critical: false,
        tags: Vec::new(),
    };

    let monitor = ServiceMonitor::new(AlertConfig::default())?;
    let result = monitor.check_service(&config).await;

    println!("\n{}", "=".repeat(50).cyan());
    println!("{}", "Service Check Result".bold().cyan());
    println!("{}", "=".repeat(50).cyan());

    monitor.display_result(&result, &config);

    if result.success {
        println!("\n{}", "Service is healthy!".green().bold());
    } else {
        println!("\n{}", "Service check failed!".red().bold());
    }

    Ok(())
}

/// Generate sample configuration
fn generate_sample_config(output: PathBuf) -> Result<()> {
    let config = MonitorConfig {
        services: vec![
            ServiceConfig {
                name: "Production API".to_string(),
                target: "https://api.example.com/health".to_string(),
                service_type: ServiceType::Https,
                check_interval_secs: 30,
                timeout_secs: 10,
                expected_status: Some(200),
                expected_content: Some("ok".to_string()),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("Authorization".to_string(), "Bearer token123".to_string());
                    h
                },
                critical: true,
                tags: vec!["production".to_string(), "api".to_string()],
            },
            ServiceConfig {
                name: "Database Server".to_string(),
                target: "192.168.1.100:5432".to_string(),
                service_type: ServiceType::Tcp,
                check_interval_secs: 60,
                timeout_secs: 5,
                expected_status: None,
                expected_content: None,
                headers: HashMap::new(),
                critical: true,
                tags: vec!["database".to_string(), "infrastructure".to_string()],
            },
            ServiceConfig {
                name: "Web Frontend".to_string(),
                target: "https://www.example.com".to_string(),
                service_type: ServiceType::Https,
                check_interval_secs: 60,
                timeout_secs: 15,
                expected_status: Some(200),
                expected_content: Some("<!DOCTYPE html>".to_string()),
                headers: HashMap::new(),
                critical: false,
                tags: vec!["frontend".to_string(), "web".to_string()],
            },
            ServiceConfig {
                name: "Redis Cache".to_string(),
                target: "127.0.0.1:6379".to_string(),
                service_type: ServiceType::Tcp,
                check_interval_secs: 30,
                timeout_secs: 5,
                expected_status: None,
                expected_content: None,
                headers: HashMap::new(),
                critical: true,
                tags: vec!["cache".to_string(), "infrastructure".to_string()],
            },
        ],
        alert_config: AlertConfig {
            slack_webhook: Some("https://hooks.slack.com/services/XXX/YYY/ZZZ".to_string()),
            email_to: Some("oncall@example.com".to_string()),
            consecutive_failures_threshold: Some(3),
            response_time_threshold_ms: Some(5000),
        },
    };

    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(&output, content)?;

    println!("{} Sample configuration written to: {}",
        "✓".green(),
        output.display().to_string().cyan()
    );

    Ok(())
}

/// Show monitoring statistics
fn show_stats(stats_file: PathBuf) -> Result<()> {
    if !stats_file.exists() {
        println!("{} Stats file not found. Run monitoring first to generate statistics.",
            "!".yellow()
        );
        return Ok(());
    }

    let content = std::fs::read_to_string(&stats_file)?;
    let stats: HashMap<String, ServiceStats> = serde_json::from_str(&content)?;

    println!("\n{}", "=".repeat(70).cyan());
    println!("{}", "Service Monitoring Statistics".bold().cyan());
    println!("{}", "=".repeat(70).cyan());

    for (name, stat) in &stats {
        let uptime_color = if stat.uptime_percentage >= 99.9 {
            stat.uptime_percentage.to_string().green()
        } else if stat.uptime_percentage >= 99.0 {
            stat.uptime_percentage.to_string().yellow()
        } else {
            stat.uptime_percentage.to_string().red()
        };

        println!("\n{}", name.bold());
        println!("  Uptime: {}%", uptime_color);
        println!("  Total Checks: {}", stat.total_checks);
        println!("  Successful: {} | Failed: {}",
            stat.successful_checks.to_string().green(),
            stat.failed_checks.to_string().red()
        );
        println!("  Response Time: avg={:.1}ms, min={}ms, max={}ms",
            stat.avg_response_time_ms,
            if stat.min_response_time_ms == u64::MAX { 0 } else { stat.min_response_time_ms },
            stat.max_response_time_ms
        );

        if let Some(last_success) = stat.last_success {
            println!("  Last Success: {}", last_success.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        if let Some(last_failure) = stat.last_failure {
            println!("  Last Failure: {}", last_failure.format("%Y-%m-%d %H:%M:%S UTC").to_string().red());
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Monitor { config, interval, once } => {
            let content = std::fs::read_to_string(&config)
                .context(format!("Failed to read config file: {}", config.display()))?;

            let monitor_config: MonitorConfig = serde_json::from_str(&content)
                .context("Failed to parse configuration file")?;

            let monitor = ServiceMonitor::new(monitor_config.alert_config.clone())?;
            monitor.run_monitoring(monitor_config, interval, once).await?;
        }
        Commands::Check { target, service_type, expected_status, timeout } => {
            check_single_service(target, service_type, expected_status, timeout).await?;
        }
        Commands::GenerateConfig { output } => {
            generate_sample_config(output)?;
        }
        Commands::Stats { stats_file } => {
            show_stats(stats_file)?;
        }
    }

    Ok(())
}
