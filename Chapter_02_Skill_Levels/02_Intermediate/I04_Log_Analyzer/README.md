# I04 - Security Log Analyzer

A comprehensive security log parser and analyzer with pattern detection, threat identification, and statistical analysis.

## Features

- **Multi-Format Parsing**: Syslog, Apache, Nginx, JSON, custom formats
- **Security Event Detection**: Failed logins, brute force, privilege escalation
- **Pattern Search**: Regex-based log searching with context
- **Statistical Analysis**: Severity distribution, top IPs, top users
- **Threat Detection**: Brute force attack identification
- **Multiple Output Formats**: Text, JSON, CSV

## Rust Concepts Demonstrated

### Lazy Static (Compile-Once Patterns)
```rust
use lazy_static::lazy_static;

lazy_static! {
    // Compiled once at first access, then reused
    static ref SYSLOG_REGEX: Regex = Regex::new(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+..."
    ).unwrap();
}

// Usage - no recompilation
SYSLOG_REGEX.is_match(line);  // Uses cached regex
```

### Lifetime Annotations
```rust
// Lifetime 'a ties the struct's lifetime to its borrowed data
struct LogEntry<'a> {
    message: &'a str,   // Borrows from original log data
    hostname: &'a str,  // Cannot outlive source data
}

// The compiler ensures LogEntry doesn't outlive the source string
fn parse<'a>(line: &'a str) -> LogEntry<'a> {
    LogEntry { message: line, hostname: &line[0..5] }
}
```

### Builder Pattern
```rust
// Fluent API for constructing complex objects
let parser = LogParser::new()
    .with_format(LogFormat::Syslog)
    .with_min_severity(Severity::Warning)
    .with_ip_filter("192.168.1.0/24");

// Each method returns self for chaining
impl LogParser {
    fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self  // Return self for chaining
    }
}
```

### Closures with Environment Capture
```rust
let threshold = Severity::Warning;

// Closure captures `threshold` from surrounding scope
let filter = |entry: &LogEntry| entry.severity >= threshold;

// Three capture modes:
// |x| x + 1           - Borrow by reference (default)
// move |x| x + data   - Move/take ownership
// |x| *x = value      - Mutable borrow
```

## Usage

```bash
# Analyze syslog file
log_analyzer analyze -f /var/log/syslog --stats

# Analyze with severity filter
log_analyzer analyze -f /var/log/auth.log -s warning -F authlog

# Search for pattern with context
log_analyzer search -f /var/log/syslog -p "failed" -i -C 2

# Detect brute force attacks
log_analyzer detect -f /var/log/auth.log --login-threshold 5 --time-window 300

# Generate sample logs for testing
log_analyzer generate -o test.log -c 1000 --with-attacks

# Export results to JSON
log_analyzer analyze -f /var/log/syslog -o json -e results.json
```

## Command Reference

### `analyze` - Parse and Analyze Logs
| Flag | Description |
|------|-------------|
| `-f, --file` | Log file to analyze |
| `-F, --format` | Log format: syslog, apache, nginx, authlog, json |
| `-s, --severity` | Minimum severity: debug, info, notice, warning, error, critical |
| `--stats` | Show statistics summary |
| `-o, --output` | Output format: text, json, csv |
| `-e, --export` | Export results to file |

### `search` - Search Logs
| Flag | Description |
|------|-------------|
| `-f, --file` | Log file to search |
| `-p, --pattern` | Regex pattern to find |
| `-i, --ignore-case` | Case insensitive search |
| `-C, --context` | Lines of context around matches |

### `detect` - Threat Detection
| Flag | Description |
|------|-------------|
| `-f, --file` | Log file to analyze |
| `--login-threshold` | Failed logins to trigger alert (default: 5) |
| `--time-window` | Time window in seconds (default: 300) |
| `--port-scan` | Enable port scan detection |

## Security Events Detected

| Event Type | Description | Severity |
|------------|-------------|----------|
| FailedLogin | Authentication failure | Warning |
| SuccessfulLogin | Successful authentication | Info |
| PrivilegeEscalation | sudo/su usage | Warning |
| SuspiciousCommand | wget, curl, nc, etc. | Warning |
| BruteForce | Multiple failed logins | Critical |
| Malware | Known malicious patterns | Emergency |

## Example Output

```
════════════════════════════════════════════════════════════════════════════════
 LOG ANALYSIS RESULTS
════════════════════════════════════════════════════════════════════════════════

[!] Security Events:

Line 45 [Warning] [FailedLogin] Failed password for root from 192.168.1.254
    IPs: 192.168.1.254
    Users: root

Line 67 [Warning] [FailedLogin] Failed password for admin from 192.168.1.254
    IPs: 192.168.1.254
    Users: admin

──────────────────────────────────────────────────────────
 STATISTICS
──────────────────────────────────────────────────────────

[*] Overview:
    Total lines:    1000
    Parsed entries: 847

[*] Severity Distribution:
    Info: 650
    Warning: 150
    Error: 47

[*] Top IPs:
    192.168.1.254: 45
    10.0.0.50: 23
```

## Building

```bash
cargo build --release
```

## Dependencies

- `clap`: CLI argument parsing
- `regex`: Pattern matching
- `chrono`: Date/time handling
- `lazy_static`: Compile-once patterns
- `rayon`: Parallel processing
- `serde`/`serde_json`: Serialization
- `memmap2`: Memory-mapped file I/O

## Performance Tips

1. **Use memory mapping** for large log files
2. **Parallel processing** enabled by default with Rayon
3. **Lazy static regexes** avoid recompilation overhead
4. **Severity filtering** reduces processing for irrelevant entries

## License

MIT License - Educational use only
