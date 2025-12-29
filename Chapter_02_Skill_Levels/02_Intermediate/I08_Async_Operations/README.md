# I08 Async Operations

A comprehensive demonstration of async/await patterns for concurrent security operations in Rust.

## Overview

This project teaches essential async programming concepts through security-focused examples:

- **Tokio Runtime**: Understanding the async executor
- **Concurrent Execution**: Running multiple operations simultaneously
- **Channels**: Inter-task communication patterns
- **Timeouts**: Preventing operations from hanging indefinitely
- **Rate Limiting**: Controlling concurrency with semaphores
- **Async Traits**: Defining async interfaces

## Features

### 1. Concurrent Port Checking
Simulates scanning multiple ports with controlled parallelism using semaphores.

### 2. Parallel HTTP Fetching
Demonstrates fetching multiple URLs concurrently with timeout handling.

### 3. Channel Communication
Shows producer-consumer patterns using MPSC (multi-producer, single-consumer) channels.

### 4. Rate Limiting
Implements request throttling using semaphores to avoid overwhelming targets.

### 5. Select/Racing Futures
Demonstrates waiting for the first of multiple futures to complete.

## Usage

```bash
# Build the project
cargo build --release

# Run concurrent port check simulation
cargo run -- port-check --count 100 --max-concurrent 10

# Fetch URLs in parallel
cargo run -- http-fetch --urls "https://example.com,https://httpbin.org/get"

# Demonstrate channel communication
cargo run -- channels --producers 3 --messages 5

# Demonstrate rate limiting
cargo run -- rate-limit --requests 20 --max-concurrent 3

# Run all demos
cargo run -- all
```

## Key Concepts

### Async/Await Basics
```rust
async fn example() {
    // .await suspends execution until the future completes
    let result = some_async_operation().await;
}
```

### Spawning Tasks
```rust
let handle = tokio::spawn(async {
    // This runs concurrently
    do_work().await
});
let result = handle.await;
```

### Semaphores for Rate Limiting
```rust
let semaphore = Arc::new(Semaphore::new(max_concurrent));
let permit = semaphore.acquire().await?;
// permit is dropped when scope ends, releasing the slot
```

### Channels for Communication
```rust
let (tx, mut rx) = mpsc::channel(32);
tx.send(message).await?;
while let Some(msg) = rx.recv().await {
    process(msg);
}
```

### Timeouts
```rust
match timeout(Duration::from_secs(5), operation()).await {
    Ok(result) => println!("Completed: {:?}", result),
    Err(_) => println!("Timed out!"),
}
```

## Security Applications

- **Port Scanning**: Check multiple ports concurrently
- **Web Reconnaissance**: Parallel HTTP requests for information gathering
- **Log Processing**: Async file reading and analysis
- **API Enumeration**: Rate-limited queries to avoid detection

## Dependencies

- `tokio` - Async runtime
- `futures` - Future utilities
- `async-trait` - Async methods in traits
- `reqwest` - HTTP client
- `clap` - CLI parsing
- `thiserror` - Error handling

## Testing

```bash
cargo test
```

## License

MIT
