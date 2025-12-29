# Async Rust & Tokio Cheatsheet

## Quick Reference for Async Programming

---

## Setup

### Cargo.toml
```toml
[dependencies]
tokio = { version = "1.35", features = ["full"] }
futures = "0.3"
async-trait = "0.1"
```

---

## Basic Async Patterns

### Main Function
```rust
#[tokio::main]
async fn main() {
    println!("Async main!");
}

// With custom runtime
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Uses 4 worker threads
}

// Single-threaded runtime
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Single thread only
}
```

### Async Functions
```rust
async fn fetch_data(url: &str) -> Result<String, reqwest::Error> {
    let response = reqwest::get(url).await?;
    response.text().await
}

// Calling async functions
async fn main() {
    let result = fetch_data("https://example.com").await;
}
```

### Spawning Tasks
```rust
use tokio::task;

// Spawn a task (runs concurrently)
let handle = tokio::spawn(async {
    // Task code here
    42
});

// Wait for result
let result = handle.await.unwrap();

// Spawn blocking task (for CPU-intensive work)
let result = task::spawn_blocking(|| {
    // CPU-intensive work
    heavy_computation()
}).await.unwrap();
```

---

## Concurrency

### Running Multiple Futures
```rust
use tokio::join;

// Run multiple futures concurrently, wait for all
let (a, b, c) = tokio::join!(
    fetch_data("url1"),
    fetch_data("url2"),
    fetch_data("url3")
);

// Run until first completes
use tokio::select;

select! {
    result = fetch_data("url1") => println!("First: {:?}", result),
    result = fetch_data("url2") => println!("Second: {:?}", result),
}
```

### JoinSet for Dynamic Tasks
```rust
use tokio::task::JoinSet;

async fn scan_all(targets: Vec<String>) -> Vec<ScanResult> {
    let mut set = JoinSet::new();

    for target in targets {
        set.spawn(async move {
            scan_target(&target).await
        });
    }

    let mut results = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(result) = res {
            results.push(result);
        }
    }
    results
}
```

### Semaphore for Rate Limiting
```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

async fn rate_limited_scan(targets: Vec<String>, max_concurrent: usize) {
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::new();

    for target in targets {
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        handles.push(tokio::spawn(async move {
            let result = scan_target(&target).await;
            drop(permit); // Release permit
            result
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
}
```

---

## Timeouts

### Basic Timeout
```rust
use tokio::time::{timeout, Duration};

async fn with_timeout() {
    match timeout(Duration::from_secs(5), slow_operation()).await {
        Ok(result) => println!("Completed: {:?}", result),
        Err(_) => println!("Operation timed out"),
    }
}
```

### Sleep
```rust
use tokio::time::{sleep, Duration};

async fn delayed_action() {
    println!("Starting...");
    sleep(Duration::from_secs(1)).await;
    println!("Done after 1 second");
}
```

### Interval
```rust
use tokio::time::{interval, Duration};

async fn periodic_task() {
    let mut interval = interval(Duration::from_secs(10));

    loop {
        interval.tick().await;
        println!("Tick!");
        // Do periodic work
    }
}
```

---

## Channels

### MPSC (Multiple Producer, Single Consumer)
```rust
use tokio::sync::mpsc;

async fn channel_example() {
    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Spawn producer
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        tx_clone.send("Hello".to_string()).await.unwrap();
    });

    tokio::spawn(async move {
        tx.send("World".to_string()).await.unwrap();
    });

    // Receive
    while let Some(msg) = rx.recv().await {
        println!("Received: {}", msg);
    }
}
```

### Broadcast Channel
```rust
use tokio::sync::broadcast;

async fn broadcast_example() {
    let (tx, mut rx1) = broadcast::channel::<String>(16);
    let mut rx2 = tx.subscribe();

    tx.send("Hello everyone!".to_string()).unwrap();

    // Both receivers get the message
    println!("rx1: {}", rx1.recv().await.unwrap());
    println!("rx2: {}", rx2.recv().await.unwrap());
}
```

### Watch Channel (Single value, multiple observers)
```rust
use tokio::sync::watch;

async fn watch_example() {
    let (tx, mut rx) = watch::channel("initial");

    tokio::spawn(async move {
        loop {
            rx.changed().await.unwrap();
            println!("Value changed to: {}", *rx.borrow());
        }
    });

    tx.send("updated").unwrap();
    tx.send("again").unwrap();
}
```

---

## TCP Networking

### TCP Client
```rust
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn tcp_client(addr: &str) -> tokio::io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;

    // Write
    stream.write_all(b"Hello, server!").await?;

    // Read
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));

    Ok(())
}
```

### TCP Server
```rust
use tokio::net::TcpListener;

async fn tcp_server(addr: &str) -> tokio::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        println!("Connection from: {}", peer_addr);

        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];

            loop {
                let n = match socket.read(&mut buffer).await {
                    Ok(0) => return, // Connection closed
                    Ok(n) => n,
                    Err(_) => return,
                };

                // Echo back
                if socket.write_all(&buffer[..n]).await.is_err() {
                    return;
                }
            }
        });
    }
}
```

### TCP with Timeout
```rust
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

async fn connect_with_timeout(addr: &str) -> Result<TcpStream, &'static str> {
    match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err("Connection failed"),
        Err(_) => Err("Connection timed out"),
    }
}
```

---

## UDP Networking

### UDP Socket
```rust
use tokio::net::UdpSocket;

async fn udp_example() -> tokio::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Send
    socket.send_to(b"Hello", "8.8.8.8:53").await?;

    // Receive
    let mut buf = [0u8; 1024];
    let (len, addr) = socket.recv_from(&mut buf).await?;
    println!("Received {} bytes from {}", len, addr);

    Ok(())
}
```

---

## File I/O

### Async File Operations
```rust
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

async fn file_operations() -> tokio::io::Result<()> {
    // Read entire file
    let content = fs::read_to_string("file.txt").await?;

    // Write file
    fs::write("output.txt", "content").await?;

    // Buffered reading
    let file = File::open("large.txt").await?;
    let mut reader = BufReader::new(file);
    let mut content = String::new();
    reader.read_to_string(&mut content).await?;

    // Create and write
    let mut file = File::create("new.txt").await?;
    file.write_all(b"Hello, async!").await?;
    file.flush().await?;

    Ok(())
}
```

---

## Synchronization

### Mutex
```rust
use std::sync::Arc;
use tokio::sync::Mutex;

async fn shared_state() {
    let counter = Arc::new(Mutex::new(0));

    let mut handles = vec![];

    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            let mut lock = counter.lock().await;
            *lock += 1;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    println!("Counter: {}", *counter.lock().await);
}
```

### RwLock
```rust
use tokio::sync::RwLock;

async fn read_write_lock() {
    let data = Arc::new(RwLock::new(vec![1, 2, 3]));

    // Multiple readers
    let reader = data.read().await;
    println!("Data: {:?}", *reader);
    drop(reader);

    // Single writer
    let mut writer = data.write().await;
    writer.push(4);
}
```

### Notify (Condition variable)
```rust
use std::sync::Arc;
use tokio::sync::Notify;

async fn notify_example() {
    let notify = Arc::new(Notify::new());
    let notify_clone = notify.clone();

    // Waiter
    let waiter = tokio::spawn(async move {
        println!("Waiting...");
        notify_clone.notified().await;
        println!("Notified!");
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    notify.notify_one();

    waiter.await.unwrap();
}
```

---

## Error Handling

### Async Result Pattern
```rust
use anyhow::Result;

async fn operation() -> Result<String> {
    let data = fetch_data().await?;
    let processed = process(data).await?;
    Ok(processed)
}

// With context
use anyhow::Context;

async fn operation_with_context() -> Result<String> {
    let data = fetch_data()
        .await
        .context("Failed to fetch data")?;
    Ok(data)
}
```

### Handling Multiple Errors
```rust
async fn try_multiple_sources() -> Result<String> {
    // Try first, fallback to second
    match fetch_from_primary().await {
        Ok(data) => Ok(data),
        Err(_) => fetch_from_secondary().await,
    }
}
```

---

## Common Patterns

### Graceful Shutdown
```rust
use tokio::signal;
use tokio::sync::broadcast;

async fn run_with_shutdown() {
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    let server = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        println!("Shutting down...");
                        break;
                    }
                    _ = do_work() => {
                        // Continue working
                    }
                }
            }
        })
    };

    // Wait for Ctrl+C
    signal::ctrl_c().await.unwrap();
    println!("Received shutdown signal");

    let _ = shutdown_tx.send(());
    server.await.unwrap();
}
```

### Retry with Backoff
```rust
use tokio::time::{sleep, Duration};

async fn retry_with_backoff<F, Fut, T, E>(
    mut f: F,
    max_retries: u32,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut delay = Duration::from_millis(100);

    for attempt in 0..max_retries {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) if attempt + 1 == max_retries => return Err(e),
            Err(_) => {
                sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }

    unreachable!()
}
```

### Connection Pool Pattern
```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

struct ConnectionPool {
    semaphore: Arc<Semaphore>,
    max_size: usize,
}

impl ConnectionPool {
    fn new(max_size: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_size)),
            max_size,
        }
    }

    async fn get_connection(&self) -> PooledConnection {
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();
        PooledConnection {
            _permit: permit,
            // ... actual connection
        }
    }
}
```

---

## Performance Tips

1. **Use `spawn_blocking` for CPU-intensive work**
2. **Prefer channels over mutexes when possible**
3. **Use `JoinSet` for dynamic task management**
4. **Set appropriate buffer sizes for channels**
5. **Use semaphores for rate limiting**
6. **Consider `current_thread` runtime for simple cases**

---

[← Back to Main](../README.md)
