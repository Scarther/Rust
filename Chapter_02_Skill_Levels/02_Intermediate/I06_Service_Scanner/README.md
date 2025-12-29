# I06 - Service Scanner

An advanced network service detection tool with banner grabbing, version identification, and protocol-specific probing.

## Features

- **Port Scanning**: TCP connect scan with customizable timeout
- **Banner Grabbing**: Capture service banners for identification
- **Version Detection**: Match banners against known signatures
- **Protocol Probes**: Specialized probes for HTTP, SSH, FTP, etc.
- **Concurrent Scanning**: Async I/O with configurable parallelism
- **Multiple Outputs**: Text, JSON, CSV formats

## Rust Concepts Demonstrated

### Async/Await with Tokio
```rust
// Async function returns a Future
async fn scan_port(addr: SocketAddr) -> ScanResult {
    // await yields control while waiting for I/O
    let stream = TcpStream::connect(addr).await?;

    // Read doesn't block the thread
    let n = stream.read(&mut buffer).await?;

    ScanResult { ... }
}

// Spawn concurrent tasks
let handle = tokio::spawn(async move {
    scan_port(addr).await
});

// Await the result
let result = handle.await?;
```

### Semaphore for Concurrency Limiting
```rust
use tokio::sync::Semaphore;

// Create semaphore with N permits
let semaphore = Arc::new(Semaphore::new(100));

for addr in addresses {
    let sem = Arc::clone(&semaphore);

    tokio::spawn(async move {
        // Acquire permit before proceeding
        let _permit = sem.acquire().await.unwrap();

        // Only N tasks can be here concurrently
        scan_port(addr).await

        // Permit released when dropped
    });
}
```

### Type Aliases
```rust
// Simplify complex types
type ScanResults = Vec<(SocketAddr, ScanResult)>;
type Banner = Option<String>;

// Use like regular types
fn process(results: ScanResults) -> Banner {
    // ...
}
```

### Associated Types (Pattern)
```rust
// Trait with associated type
trait Probe {
    type Response;  // Implementation defines this type

    fn send(&self, data: &[u8]) -> Self::Response;
}

impl Probe for HttpProbe {
    type Response = HttpResponse;  // Concrete type

    fn send(&self, data: &[u8]) -> Self::Response {
        // ...
    }
}
```

### Async Timeout Pattern
```rust
use tokio::time::timeout;

// Wrap async operation with timeout
let result = timeout(
    Duration::from_secs(5),
    TcpStream::connect(addr)
).await;

match result {
    Ok(Ok(stream)) => { /* Connected */ }
    Ok(Err(e)) => { /* Connection refused */ }
    Err(_) => { /* Timeout */ }
}
```

## Usage

```bash
# Basic port scan
service_scanner scan -t 192.168.1.1 -p 22,80,443

# Scan with banner grabbing
service_scanner scan -t 10.0.0.1 -p 1-1000 --banner

# Full version detection
service_scanner scan -t 192.168.1.0/24 -p 22,80 --banner --version

# Custom concurrency and timeout
service_scanner scan -t 10.0.0.1 -p 1-65535 -c 500 --timeout 1000

# Export results to JSON
service_scanner scan -t 192.168.1.1 -p 1-1000 -o json -e results.json

# Probe specific protocol
service_scanner probe -t 192.168.1.1 -p 22 -P ssh

# Show known signatures
service_scanner signatures --name ssh
```

## Command Reference

### `scan` - Port Scanning
| Flag | Description |
|------|-------------|
| `-t, --target` | Target IP or CIDR network |
| `-p, --ports` | Ports to scan (comma-separated or range) |
| `--timeout` | Connection timeout in ms (default: 3000) |
| `-c, --concurrency` | Max concurrent connections (default: 100) |
| `-b, --banner` | Grab service banners |
| `-v, --version` | Detect service versions |
| `-o, --output` | Output format: text, json, csv |
| `-e, --export` | Export results to file |

### `probe` - Protocol Probing
| Flag | Description |
|------|-------------|
| `-t, --target` | Target host |
| `-p, --port` | Target port |
| `-P, --protocol` | Protocol to probe |
| `--timeout` | Timeout in ms (default: 5000) |

### `signatures` - View Signatures
| Flag | Description |
|------|-------------|
| `-p, --port` | Filter by port number |
| `-n, --name` | Filter by service name |

## Supported Protocols

| Protocol | Description |
|----------|-------------|
| HTTP | Web server detection |
| HTTPS | TLS-wrapped HTTP |
| SSH | Secure Shell |
| FTP | File Transfer Protocol |
| SMTP | Mail server |
| MySQL | MySQL database |
| PostgreSQL | PostgreSQL database |
| Redis | Redis cache |
| MongoDB | MongoDB database |

## Example Output

```
════════════════════════════════════════════════════════════════════════
Host: 192.168.1.1
════════════════════════════════════════════════════════════════════════

PORT     STATE        SERVICE         VERSION/BANNER
──────────────────────────────────────────────────────────────────────
22/tcp   open         ssh             OpenSSH 8.4p1
80/tcp   open         http            nginx 1.18.0
443/tcp  open         https           Apache 2.4.41
3306/tcp open         mysql           MySQL 8.0.25

════════════════════════════════════════════════════════════════════════
Total: 4 open ports found
```

## Performance Tips

1. **Increase concurrency** (`-c 500`) for faster scans
2. **Lower timeout** (`--timeout 1000`) for faster scans on LAN
3. **Disable banner grabbing** for pure port scanning
4. **Use CIDR notation** for efficient network scanning

## Building

```bash
cargo build --release
```

## Dependencies

- `tokio`: Async runtime
- `tokio-native-tls`: TLS support
- `clap`: CLI parsing
- `serde`/`serde_json`: Serialization
- `regex`: Banner pattern matching
- `lazy_static`: Compiled signature patterns
- `indicatif`: Progress bars

## Security Considerations

- Always obtain authorization before scanning
- High concurrency may trigger IDS/IPS
- Some networks block port scanning

## License

MIT License - Educational use only
