# I02 - Network Enumeration Tool

A comprehensive network enumeration tool demonstrating intermediate Rust concepts including Arc, Mutex, channels, and parallel iteration.

## Features

- **ARP Scanning**: Discover hosts on local network using ARP requests
- **Ping Sweep**: TCP-based host discovery (no root required)
- **Service Detection**: Identify services running on discovered hosts
- **Banner Grabbing**: Capture service banners for version detection
- **JSON Output**: Machine-readable output for automation

## Rust Concepts Demonstrated

### Arc (Atomic Reference Counting)
```rust
// Arc enables shared ownership across threads
let results: Arc<Mutex<Vec<Host>>> = Arc::new(Mutex::new(Vec::new()));

// Clone Arc to share with another thread (cheap atomic increment)
let results_clone = Arc::clone(&results);
```

### Mutex (Mutual Exclusion)
```rust
// Mutex provides interior mutability with thread safety
let data = Arc::new(Mutex::new(vec![]));

// Lock to get mutable access (blocks other threads)
let mut guard = data.lock().unwrap();
guard.push(item);
// Guard dropped here, releasing lock
```

### Channels (mpsc)
```rust
// Create channel - tx can be cloned, rx cannot
let (tx, rx) = channel();

// Worker threads send results
let tx_clone = tx.clone();
thread::spawn(move || {
    tx_clone.send(result).unwrap();
});

// Main thread receives
while let Ok(item) = rx.recv() {
    process(item);
}
```

### Rayon Parallel Iterators
```rust
// Automatic parallelization across CPU cores
targets.par_iter().for_each(|target| {
    // This runs in parallel
    scan(target);
});
```

## Usage

```bash
# List available network interfaces
network_enum interfaces

# ARP scan (requires root for raw sockets)
sudo network_enum arp -i eth0 -t 192.168.1.0/24

# Ping sweep (no root required - uses TCP)
network_enum ping -t 192.168.1.0/24 -T 100

# Service detection
network_enum services -t 192.168.1.1 -p 22,80,443,8080

# Scan port range
network_enum services -t 10.0.0.1 -p 1-1000
```

## Command Reference

### `arp` - ARP Scan
| Flag | Description |
|------|-------------|
| `-i, --interface` | Network interface (e.g., eth0) |
| `-t, --target` | Target network in CIDR notation |
| `--timeout` | Timeout per probe in ms (default: 1000) |

### `ping` - Ping Sweep
| Flag | Description |
|------|-------------|
| `-t, --target` | Target network in CIDR notation |
| `-T, --threads` | Number of concurrent threads (default: 50) |
| `--timeout` | Timeout in ms (default: 1000) |

### `services` - Service Detection
| Flag | Description |
|------|-------------|
| `-t, --target` | Target host IP |
| `-p, --ports` | Ports to scan (comma-separated or range) |
| `--timeout` | Connection timeout in ms (default: 500) |

## Building

```bash
cargo build --release
```

## Dependencies

- `clap`: CLI argument parsing
- `pnet`: Network packet crafting
- `tokio`: Async runtime
- `rayon`: Parallel iteration
- `indicatif`: Progress bars
- `colored`: Terminal colors
- `serde`/`serde_json`: Serialization

## Security Considerations

- ARP scanning requires root/admin privileges
- Always obtain authorization before scanning networks
- This tool is for educational and authorized testing only

## Example Output

```
[*] Scanning 5 ports on 192.168.1.1
════════════════════════════════════════════════════════════
 DISCOVERED SERVICES
════════════════════════════════════════════════════════════

[OPEN] 22/tcp  SSH             OpenSSH 8.4p1
[OPEN] 80/tcp  HTTP            nginx/1.18.0
[OPEN] 443/tcp HTTPS
```

## License

MIT License - Educational use only
