# I05 - File Integrity Monitor (FIM)

A security tool that monitors files for unauthorized changes using cryptographic hashes, providing real-time alerts and baseline comparison.

## Features

- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE3
- **Baseline Management**: Create, check, update baselines
- **Real-time Monitoring**: Watch files for changes with notifications
- **SQLite Storage**: Persistent baseline database
- **Parallel Processing**: Multi-threaded file scanning
- **Flexible Filtering**: By extension, path, hidden files

## Rust Concepts Demonstrated

### Interior Mutability (RefCell)
```rust
use std::cell::RefCell;

// RefCell allows mutation inside immutable struct
struct Cache {
    data: RefCell<HashMap<String, String>>,
}

impl Cache {
    fn get(&self, key: &str) -> Option<String> {
        // Borrow mutably at runtime, even though &self is immutable
        let mut data = self.data.borrow_mut();
        data.get(key).cloned()
    }
}
```

### RAII Pattern (Resource Acquisition Is Initialization)
```rust
struct Database {
    conn: Connection,  // Connection held for struct lifetime
}

impl Database {
    fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;  // Acquire resource
        Ok(Self { conn })
    }
    // No close() needed - Drop trait auto-closes when out of scope
}

impl Drop for Database {
    fn drop(&mut self) {
        // Custom cleanup if needed (Connection has its own Drop)
        println!("Database closed");
    }
}
```

### State Pattern with Enums
```rust
enum FileStatus {
    Unchanged,
    Modified { old_hash: String, new_hash: String },
    Deleted,
    Added,
    PermissionChanged { old_perms: u32, new_perms: u32 },
    Error(String),
}

// Compiler ensures all states are handled
fn severity(status: &FileStatus) -> &str {
    match status {
        FileStatus::Unchanged => "OK",
        FileStatus::Modified { .. } => "CRITICAL",
        FileStatus::Deleted => "CRITICAL",
        FileStatus::Added => "WARNING",
        FileStatus::PermissionChanged { .. } => "WARNING",
        FileStatus::Error(_) => "ERROR",
    }
}
```

### Channels for Filesystem Events
```rust
use notify::{Watcher, RecursiveMode};
use std::sync::mpsc::channel;

// Create channel for receiving events
let (tx, rx) = channel();

// Watcher sends events through channel
let mut watcher = RecommendedWatcher::new(move |res| {
    tx.send(res).unwrap();
})?;

watcher.watch(path, RecursiveMode::Recursive)?;

// Process events as they arrive
loop {
    match rx.recv() {
        Ok(event) => handle_event(event),
        Err(_) => break,
    }
}
```

## Usage

```bash
# Initialize baseline for directory
fim init -p /etc -p /usr/bin --algorithm sha256

# Initialize with extension filter
fim init -p /var/www --extensions "php,js,html"

# Check files against baseline
fim check -d fim.db

# Check with JSON output
fim check -d fim.db -o json -e report.json

# Watch files in real-time
fim watch -p /etc -d fim.db --alert-cmd "notify-send 'FIM Alert' '{path}'"

# Update baseline after approved changes
fim update -d fim.db

# Show baseline information
fim info -d fim.db
```

## Command Reference

### `init` - Create Baseline
| Flag | Description |
|------|-------------|
| `-p, --paths` | Paths to monitor (files or directories) |
| `-a, --algorithm` | Hash algorithm: sha256, sha512, blake3 |
| `-d, --database` | Database file path (default: fim.db) |
| `--hidden` | Include hidden files |
| `--extensions` | Filter by extensions (e.g., "exe,dll") |

### `check` - Verify Integrity
| Flag | Description |
|------|-------------|
| `-d, --database` | Database file path |
| `-o, --output` | Output format: text, json, csv |
| `-e, --export` | Export results to file |
| `--paths` | Only check specific paths |

### `watch` - Real-time Monitoring
| Flag | Description |
|------|-------------|
| `-p, --paths` | Paths to watch |
| `-d, --database` | Database file path |
| `--alert-cmd` | Command to execute on change |
| `--debounce` | Debounce time in ms (default: 500) |

### `update` - Update Baseline
| Flag | Description |
|------|-------------|
| `-d, --database` | Database file path |
| `--paths` | Only update specific paths |
| `-y, --yes` | Don't prompt for confirmation |

## File Status Types

| Status | Severity | Description |
|--------|----------|-------------|
| Unchanged | OK | File matches baseline |
| Modified | CRITICAL | File content changed |
| Deleted | CRITICAL | File no longer exists |
| Added | WARNING | New file not in baseline |
| PermissionChanged | WARNING | File permissions modified |
| SizeChanged | WARNING | File size differs |
| Error | ERROR | Could not access file |

## Example Output

```
════════════════════════════════════════════════════════════════════════════════
 FILE INTEGRITY CHECK RESULTS
════════════════════════════════════════════════════════════════════════════════

[!] 3 files changed, 247 unchanged

[CRITICAL] /etc/passwd
    Old hash: a1b2c3d4e5f6...
    New hash: 9876543210ab...

[CRITICAL] /etc/shadow
    File no longer exists

[WARNING] /etc/hosts
    Permissions: 644 -> 666

════════════════════════════════════════════════════════════════════════════════
```

## Real-time Watch Example

```
[*] Starting file watch...
    Watching: /etc
    Watching: /var/www

[*] Press Ctrl+C to stop watching

[!] 14:32:15 Modified: /etc/hosts
    Old: a1b2c3d4e5f6789012345678...
    New: fedcba987654321098765432...

[+] 14:33:01 New file: /etc/cron.d/suspicious
```

## Security Considerations

1. **Baseline Protection**: Store database on read-only media or remote system
2. **Hash Algorithm**: Use SHA-256 or BLAKE3 for security-critical files
3. **Monitoring Scope**: Include critical system files (/etc, /bin, /usr)
4. **Alert Response**: Configure immediate notification for changes

## Building

```bash
cargo build --release
```

## Dependencies

- `clap`: CLI parsing
- `sha2`, `blake3`: Hash algorithms
- `notify`: Filesystem events
- `rusqlite`: SQLite database
- `walkdir`: Directory traversal
- `rayon`: Parallel processing
- `chrono`: Date/time handling

## License

MIT License - Educational use only
