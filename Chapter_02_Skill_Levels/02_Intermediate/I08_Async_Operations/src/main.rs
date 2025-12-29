//! # Async Operations - Rust Security Bible
//!
//! This project demonstrates async/await patterns for concurrent security operations.
//! It covers essential async concepts including:
//! - Tokio runtime and spawning tasks
//! - Concurrent execution with join! and select!
//! - Channels for inter-task communication
//! - Timeouts and cancellation
//! - Semaphores for rate limiting
//! - Async traits and error handling
//!
//! ## Security Applications
//! - Concurrent port scanning
//! - Parallel HTTP requests for reconnaissance
//! - Async file processing
//! - Rate-limited API queries

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use colored::*;
use futures::future::{join_all, select_all};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tokio::time::{sleep, timeout};

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Custom error types for async operations
/// Using thiserror for ergonomic error handling
#[derive(Error, Debug)]
pub enum AsyncError {
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),

    #[error("Task failed: {0}")]
    TaskFailed(String),

    #[error("Channel send error: {0}")]
    ChannelSend(String),

    #[error("Channel receive error")]
    ChannelReceive,

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Task cancelled")]
    Cancelled,
}

/// Result type alias for async operations
pub type AsyncResult<T> = Result<T, AsyncError>;

// =============================================================================
// CLI INTERFACE
// =============================================================================

/// Async Operations Demo - Security-focused async patterns
#[derive(Parser, Debug)]
#[command(name = "async_ops")]
#[command(author = "Security Developer")]
#[command(version = "1.0")]
#[command(about = "Demonstrates async/await patterns for security operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run concurrent port check simulation
    PortCheck {
        /// Number of ports to check
        #[arg(short, long, default_value = "100")]
        count: usize,

        /// Maximum concurrent tasks
        #[arg(short, long, default_value = "10")]
        max_concurrent: usize,
    },

    /// Run parallel HTTP requests
    HttpFetch {
        /// URLs to fetch (comma-separated)
        #[arg(short, long, default_value = "https://httpbin.org/get,https://httpbin.org/ip")]
        urls: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout_secs: u64,
    },

    /// Demonstrate channel communication
    Channels {
        /// Number of producer tasks
        #[arg(short, long, default_value = "3")]
        producers: usize,

        /// Messages per producer
        #[arg(short, long, default_value = "5")]
        messages: usize,
    },

    /// Demonstrate rate limiting with semaphores
    RateLimit {
        /// Total requests to make
        #[arg(short, long, default_value = "20")]
        requests: usize,

        /// Maximum concurrent requests
        #[arg(short, long, default_value = "3")]
        max_concurrent: usize,
    },

    /// Run all demos
    All,
}

// =============================================================================
// ASYNC TRAIT DEMONSTRATION
// =============================================================================

/// Trait for async security scanners
/// Using async-trait crate since Rust doesn't natively support async in traits yet
#[async_trait]
pub trait SecurityScanner: Send + Sync {
    /// The type of target being scanned
    type Target;
    /// The result type of scanning
    type Result;

    /// Perform an async scan on a target
    async fn scan(&self, target: Self::Target) -> AsyncResult<Self::Result>;

    /// Get the scanner's name
    fn name(&self) -> &str;
}

/// Port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub port: u16,
    pub is_open: bool,
    pub response_time_ms: u64,
    pub service: Option<String>,
}

/// Simulated port scanner implementing the SecurityScanner trait
pub struct SimulatedPortScanner {
    name: String,
    /// Simulated latency range in milliseconds
    latency_range: (u64, u64),
}

impl SimulatedPortScanner {
    pub fn new(name: &str, min_latency: u64, max_latency: u64) -> Self {
        Self {
            name: name.to_string(),
            latency_range: (min_latency, max_latency),
        }
    }
}

#[async_trait]
impl SecurityScanner for SimulatedPortScanner {
    type Target = u16;
    type Result = PortScanResult;

    async fn scan(&self, port: Self::Target) -> AsyncResult<Self::Result> {
        // Simulate network latency
        let mut rng = rand::thread_rng();
        let latency = rng.gen_range(self.latency_range.0..=self.latency_range.1);
        sleep(Duration::from_millis(latency)).await;

        // Simulate some ports being open (common ports more likely)
        let is_open = match port {
            22 | 80 | 443 | 8080 | 3306 | 5432 => rng.gen_bool(0.8),
            1..=1024 => rng.gen_bool(0.1),
            _ => rng.gen_bool(0.02),
        };

        // Determine service based on port
        let service = if is_open {
            Some(
                match port {
                    22 => "SSH",
                    80 => "HTTP",
                    443 => "HTTPS",
                    21 => "FTP",
                    23 => "Telnet",
                    25 => "SMTP",
                    53 => "DNS",
                    3306 => "MySQL",
                    5432 => "PostgreSQL",
                    8080 => "HTTP-Proxy",
                    _ => "Unknown",
                }
                .to_string(),
            )
        } else {
            None
        };

        Ok(PortScanResult {
            port,
            is_open,
            response_time_ms: latency,
            service,
        })
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// =============================================================================
// CONCURRENT PORT SCANNING
// =============================================================================

/// Demonstrates concurrent task execution with controlled parallelism
/// Uses a semaphore to limit the number of concurrent operations
pub async fn concurrent_port_check(port_count: usize, max_concurrent: usize) -> AsyncResult<()> {
    println!(
        "\n{}",
        "=== Concurrent Port Check Demo ===".bright_cyan().bold()
    );
    println!(
        "Checking {} ports with max {} concurrent tasks\n",
        port_count.to_string().yellow(),
        max_concurrent.to_string().yellow()
    );

    let start = Instant::now();
    let scanner = Arc::new(SimulatedPortScanner::new("PortScanner", 10, 100));

    // Semaphore limits concurrent operations
    // This is crucial for security tools to avoid overwhelming targets
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    // Atomic counter for progress tracking
    let completed = Arc::new(AtomicUsize::new(0));
    let open_ports = Arc::new(Mutex::new(Vec::new()));

    // Create tasks for each port
    let ports: Vec<u16> = (1..=port_count as u16).collect();
    let mut handles = Vec::new();

    for port in ports {
        let scanner = Arc::clone(&scanner);
        let sem = Arc::clone(&semaphore);
        let completed = Arc::clone(&completed);
        let open_ports = Arc::clone(&open_ports);

        // Spawn a task for each port
        // tokio::spawn returns a JoinHandle that can be awaited
        let handle = tokio::spawn(async move {
            // Acquire semaphore permit - this limits concurrency
            // The permit is automatically released when dropped
            let _permit = sem.acquire().await.expect("Semaphore closed");

            // Perform the scan
            let result = scanner.scan(port).await;

            // Update progress
            let done = completed.fetch_add(1, Ordering::SeqCst) + 1;
            if done % 20 == 0 || done == port as usize {
                print!("\rProgress: {}/{}", done, port);
            }

            // Store open ports
            if let Ok(ref scan_result) = result {
                if scan_result.is_open {
                    open_ports.lock().await.push(scan_result.clone());
                }
            }

            result
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    // join_all collects all results, including errors
    let results: Vec<_> = join_all(handles).await;

    println!("\n");

    // Process results
    let mut success_count = 0;
    let mut error_count = 0;

    for result in results {
        match result {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(e)) => {
                error_count += 1;
                eprintln!("{}: {:?}", "Scan error".red(), e);
            }
            Err(e) => {
                error_count += 1;
                eprintln!("{}: {:?}", "Task panic".red(), e);
            }
        }
    }

    // Display open ports
    let open = open_ports.lock().await;
    if !open.is_empty() {
        println!("{}", "Open Ports Found:".green().bold());
        for port_result in open.iter() {
            println!(
                "  Port {}: {} ({}ms)",
                port_result.port.to_string().cyan(),
                port_result
                    .service
                    .as_deref()
                    .unwrap_or("Unknown")
                    .yellow(),
                port_result.response_time_ms
            );
        }
    }

    let elapsed = start.elapsed();
    println!(
        "\n{}: {} successful, {} errors in {:?}",
        "Summary".bold(),
        success_count.to_string().green(),
        error_count.to_string().red(),
        elapsed
    );

    Ok(())
}

// =============================================================================
// PARALLEL HTTP FETCHING WITH TIMEOUTS
// =============================================================================

/// HTTP response data
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    pub url: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body_preview: String,
    pub elapsed_ms: u64,
}

/// Fetch a URL with timeout
/// Demonstrates timeout handling - crucial for security tools
pub async fn fetch_url_with_timeout(
    client: &reqwest::Client,
    url: &str,
    timeout_duration: Duration,
) -> AsyncResult<HttpResponse> {
    let start = Instant::now();

    // timeout wraps a future and returns Err if it doesn't complete in time
    let response = timeout(timeout_duration, client.get(url).send())
        .await
        .map_err(|_| AsyncError::Timeout(timeout_duration))?
        .map_err(AsyncError::Http)?;

    let status = response.status().as_u16();

    // Collect headers
    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Get body preview
    let body = response.text().await.map_err(AsyncError::Http)?;
    let body_preview = body.chars().take(200).collect::<String>();

    Ok(HttpResponse {
        url: url.to_string(),
        status,
        headers,
        body_preview,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Demonstrates parallel HTTP requests with timeouts
pub async fn parallel_http_fetch(urls: Vec<String>, timeout_secs: u64) -> AsyncResult<()> {
    println!(
        "\n{}",
        "=== Parallel HTTP Fetch Demo ===".bright_cyan().bold()
    );
    println!(
        "Fetching {} URLs with {}s timeout\n",
        urls.len().to_string().yellow(),
        timeout_secs.to_string().yellow()
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("RustSecurityScanner/1.0")
        .build()
        .map_err(AsyncError::Http)?;

    let timeout_duration = Duration::from_secs(timeout_secs);

    // Create futures for all URLs
    let futures: Vec<_> = urls
        .iter()
        .map(|url| fetch_url_with_timeout(&client, url, timeout_duration))
        .collect();

    // Execute all requests in parallel
    // join_all waits for all futures to complete
    let results = join_all(futures).await;

    // Display results
    for (url, result) in urls.iter().zip(results.iter()) {
        match result {
            Ok(response) => {
                let status_color = if response.status < 300 {
                    response.status.to_string().green()
                } else if response.status < 400 {
                    response.status.to_string().yellow()
                } else {
                    response.status.to_string().red()
                };

                println!("{}", url.cyan().bold());
                println!("  Status: {} ({}ms)", status_color, response.elapsed_ms);
                println!("  Headers: {} found", response.headers.len());
                if !response.body_preview.is_empty() {
                    println!(
                        "  Body: {}...",
                        response.body_preview.chars().take(50).collect::<String>()
                    );
                }
            }
            Err(e) => {
                println!("{}", url.cyan().bold());
                println!("  {}: {}", "Error".red(), e);
            }
        }
        println!();
    }

    Ok(())
}

// =============================================================================
// CHANNEL COMMUNICATION
// =============================================================================

/// Message type for channel demo
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub producer_id: usize,
    pub message_id: usize,
    pub event_type: String,
    pub data: String,
    pub timestamp: std::time::SystemTime,
}

/// Producer task that sends messages through a channel
async fn producer_task(
    id: usize,
    message_count: usize,
    tx: mpsc::Sender<SecurityEvent>,
) -> AsyncResult<()> {
    let event_types = ["scan", "alert", "info", "warning"];

    for i in 0..message_count {
        // Simulate some work
        let delay = rand::thread_rng().gen_range(50..200);
        sleep(Duration::from_millis(delay)).await;

        let event = SecurityEvent {
            producer_id: id,
            message_id: i,
            event_type: event_types[i % event_types.len()].to_string(),
            data: format!("Data from producer {} message {}", id, i),
            timestamp: std::time::SystemTime::now(),
        };

        // Send through channel
        // send() is async and waits if the channel is full
        tx.send(event)
            .await
            .map_err(|e| AsyncError::ChannelSend(e.to_string()))?;
    }

    Ok(())
}

/// Consumer task that receives and processes messages
async fn consumer_task(mut rx: mpsc::Receiver<SecurityEvent>) -> Vec<SecurityEvent> {
    let mut events = Vec::new();

    // recv() returns None when all senders are dropped
    while let Some(event) = rx.recv().await {
        println!(
            "  {} [Producer {}] {}: {}",
            "Received".green(),
            event.producer_id.to_string().cyan(),
            event.event_type.yellow(),
            event.data
        );
        events.push(event);
    }

    events
}

/// Demonstrates channel-based communication between tasks
pub async fn channel_demo(producer_count: usize, messages_per_producer: usize) -> AsyncResult<()> {
    println!(
        "\n{}",
        "=== Channel Communication Demo ===".bright_cyan().bold()
    );
    println!(
        "Starting {} producers, {} messages each\n",
        producer_count.to_string().yellow(),
        messages_per_producer.to_string().yellow()
    );

    // Create a bounded channel
    // Bounded channels provide backpressure when full
    let (tx, rx) = mpsc::channel::<SecurityEvent>(32);

    // Spawn producer tasks
    let mut producer_handles = Vec::new();
    for id in 0..producer_count {
        let tx_clone = tx.clone();
        let handle = tokio::spawn(async move {
            producer_task(id, messages_per_producer, tx_clone).await
        });
        producer_handles.push(handle);
    }

    // Drop the original sender so the consumer knows when all producers are done
    drop(tx);

    // Spawn consumer task
    let consumer_handle = tokio::spawn(consumer_task(rx));

    // Wait for all producers to finish
    for handle in producer_handles {
        handle.await.map_err(|e| AsyncError::TaskFailed(e.to_string()))??;
    }

    // Wait for consumer to finish
    let events = consumer_handle
        .await
        .map_err(|e| AsyncError::TaskFailed(e.to_string()))?;

    println!(
        "\n{}: Processed {} events from {} producers",
        "Summary".bold(),
        events.len().to_string().green(),
        producer_count.to_string().cyan()
    );

    Ok(())
}

// =============================================================================
// RATE LIMITING WITH SEMAPHORES
// =============================================================================

/// Demonstrates rate limiting using semaphores
/// Essential for security tools to avoid triggering rate limits or DoS
pub async fn rate_limit_demo(request_count: usize, max_concurrent: usize) -> AsyncResult<()> {
    println!(
        "\n{}",
        "=== Rate Limiting Demo ===".bright_cyan().bold()
    );
    println!(
        "Making {} requests with max {} concurrent\n",
        request_count.to_string().yellow(),
        max_concurrent.to_string().yellow()
    );

    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let request_counter = Arc::new(AtomicUsize::new(0));
    let active_counter = Arc::new(AtomicUsize::new(0));

    // RwLock for tracking timing statistics
    let timings = Arc::new(RwLock::new(Vec::new()));

    let mut handles = Vec::new();

    for i in 0..request_count {
        let sem = Arc::clone(&semaphore);
        let counter = Arc::clone(&request_counter);
        let active = Arc::clone(&active_counter);
        let timings = Arc::clone(&timings);

        let handle = tokio::spawn(async move {
            let start = Instant::now();

            // Acquire permit - this blocks if we're at capacity
            let _permit = sem.acquire().await.expect("Semaphore closed");

            // Track active requests
            let current_active = active.fetch_add(1, Ordering::SeqCst) + 1;
            let request_num = counter.fetch_add(1, Ordering::SeqCst) + 1;

            println!(
                "  {} Request {} (Active: {})",
                "Starting".cyan(),
                request_num,
                current_active.to_string().yellow()
            );

            // Simulate API request
            let work_time = rand::thread_rng().gen_range(100..300);
            sleep(Duration::from_millis(work_time)).await;

            active.fetch_sub(1, Ordering::SeqCst);
            let elapsed = start.elapsed();

            // Record timing
            timings.write().await.push(elapsed.as_millis() as u64);

            println!(
                "  {} Request {} ({:?})",
                "Completed".green(),
                request_num,
                elapsed
            );

            Ok::<_, AsyncError>(i)
        });

        handles.push(handle);
    }

    // Wait for all to complete
    let results = join_all(handles).await;

    let success_count = results.iter().filter(|r| r.is_ok()).count();
    let timings = timings.read().await;
    let avg_time: u64 = if !timings.is_empty() {
        timings.iter().sum::<u64>() / timings.len() as u64
    } else {
        0
    };

    println!(
        "\n{}: {} successful, avg response time: {}ms",
        "Summary".bold(),
        success_count.to_string().green(),
        avg_time.to_string().cyan()
    );

    Ok(())
}

// =============================================================================
// SELECT DEMONSTRATION
// =============================================================================

/// Demonstrates tokio::select! for racing multiple futures
pub async fn select_demo() -> AsyncResult<()> {
    println!(
        "\n{}",
        "=== Select (Racing Futures) Demo ===".bright_cyan().bold()
    );

    // Create multiple futures that complete at different times
    let fast_task = async {
        sleep(Duration::from_millis(100)).await;
        "fast"
    };

    let medium_task = async {
        sleep(Duration::from_millis(200)).await;
        "medium"
    };

    let slow_task = async {
        sleep(Duration::from_millis(300)).await;
        "slow"
    };

    // select! returns when the FIRST future completes
    // Other futures are cancelled
    println!("Racing three tasks...");
    tokio::select! {
        result = fast_task => {
            println!("  {} task won: {}", "Fast".green(), result);
        }
        result = medium_task => {
            println!("  {} task won: {}", "Medium".yellow(), result);
        }
        result = slow_task => {
            println!("  {} task won: {}", "Slow".red(), result);
        }
    }

    // select_all from futures crate - wait for first but keep others
    println!("\nUsing select_all (keeps other futures)...");
    let futures = vec![
        Box::pin(async {
            sleep(Duration::from_millis(150)).await;
            "Task A"
        }),
        Box::pin(async {
            sleep(Duration::from_millis(100)).await;
            "Task B"
        }),
        Box::pin(async {
            sleep(Duration::from_millis(200)).await;
            "Task C"
        }),
    ];

    let (result, index, remaining) = select_all(futures).await;
    println!(
        "  First completed: {} (index {}), {} remaining",
        result.green(),
        index,
        remaining.len()
    );

    Ok(())
}

// =============================================================================
// MAIN FUNCTION AND TESTS
// =============================================================================

#[tokio::main]
async fn main() -> AsyncResult<()> {
    let cli = Cli::parse();

    println!("{}", "Async Operations Demo".bright_white().bold());
    println!("{}", "=".repeat(50));

    match cli.command {
        Commands::PortCheck {
            count,
            max_concurrent,
        } => {
            concurrent_port_check(count, max_concurrent).await?;
        }
        Commands::HttpFetch { urls, timeout_secs } => {
            let url_list: Vec<String> = urls.split(',').map(|s| s.trim().to_string()).collect();
            parallel_http_fetch(url_list, timeout_secs).await?;
        }
        Commands::Channels {
            producers,
            messages,
        } => {
            channel_demo(producers, messages).await?;
        }
        Commands::RateLimit {
            requests,
            max_concurrent,
        } => {
            rate_limit_demo(requests, max_concurrent).await?;
        }
        Commands::All => {
            concurrent_port_check(50, 10).await?;
            select_demo().await?;
            channel_demo(3, 3).await?;
            rate_limit_demo(10, 3).await?;
            // Skip HTTP fetch in all demo to avoid external dependencies
            println!(
                "\n{}: HTTP fetch skipped in 'all' demo",
                "Note".yellow().bold()
            );
        }
    }

    println!("\n{}", "Demo completed successfully!".green().bold());
    Ok(())
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the simulated port scanner
    #[tokio::test]
    async fn test_port_scanner() {
        let scanner = SimulatedPortScanner::new("TestScanner", 1, 10);
        let result = scanner.scan(80).await;
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(scan_result.port, 80);
    }

    /// Test timeout functionality
    #[tokio::test]
    async fn test_timeout() {
        let slow_future = async {
            sleep(Duration::from_secs(10)).await;
            "done"
        };

        let result = timeout(Duration::from_millis(100), slow_future).await;
        assert!(result.is_err()); // Should timeout
    }

    /// Test channel communication
    #[tokio::test]
    async fn test_channel() {
        let (tx, mut rx) = mpsc::channel::<i32>(10);

        tokio::spawn(async move {
            for i in 0..5 {
                tx.send(i).await.unwrap();
            }
        });

        let mut received = Vec::new();
        while let Some(val) = rx.recv().await {
            received.push(val);
        }

        assert_eq!(received, vec![0, 1, 2, 3, 4]);
    }

    /// Test semaphore rate limiting
    #[tokio::test]
    async fn test_semaphore() {
        let semaphore = Arc::new(Semaphore::new(2));
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let sem = Arc::clone(&semaphore);
            let cnt = Arc::clone(&counter);

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                cnt.fetch_add(1, Ordering::SeqCst);
                sleep(Duration::from_millis(10)).await;
            }));
        }

        join_all(handles).await;
        assert_eq!(counter.load(Ordering::SeqCst), 4);
    }

    /// Test select behavior
    #[tokio::test]
    async fn test_select() {
        let fast = async {
            sleep(Duration::from_millis(10)).await;
            1
        };

        let slow = async {
            sleep(Duration::from_millis(100)).await;
            2
        };

        let result = tokio::select! {
            v = fast => v,
            v = slow => v,
        };

        assert_eq!(result, 1); // Fast should win
    }

    /// Test RwLock for concurrent reads
    #[tokio::test]
    async fn test_rwlock() {
        let lock = Arc::new(RwLock::new(vec![1, 2, 3]));

        // Multiple readers can access simultaneously
        let lock1 = Arc::clone(&lock);
        let lock2 = Arc::clone(&lock);

        let (r1, r2) = tokio::join!(
            async move {
                let guard = lock1.read().await;
                guard.len()
            },
            async move {
                let guard = lock2.read().await;
                guard.iter().sum::<i32>()
            }
        );

        assert_eq!(r1, 3);
        assert_eq!(r2, 6);
    }

    /// Test async trait implementation
    #[tokio::test]
    async fn test_async_trait() {
        let scanner = SimulatedPortScanner::new("Test", 1, 5);
        assert_eq!(scanner.name(), "Test");

        let result = scanner.scan(443).await;
        assert!(result.is_ok());
    }

    /// Test join_all with mixed results
    #[tokio::test]
    async fn test_join_all() {
        let futures = vec![
            async { Ok::<_, &str>(1) },
            async { Ok::<_, &str>(2) },
            async { Ok::<_, &str>(3) },
        ];

        let results: Vec<Result<i32, &str>> = join_all(futures).await;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }
}
