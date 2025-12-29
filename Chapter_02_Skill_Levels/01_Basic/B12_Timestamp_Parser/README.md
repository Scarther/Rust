# B12 - Timestamp Parser

A comprehensive timestamp parsing and conversion tool for security log analysis and forensic investigations.

## Overview

This tool parses and converts timestamps between various formats commonly found in security logs, system files, and applications. Essential for:

- **Incident Response**: Correlating events across different log sources
- **Forensic Analysis**: Building accurate timelines of events
- **Log Analysis**: Normalizing timestamps from different systems
- **Security Monitoring**: Converting between timezone formats

## Features

- Parse multiple timestamp formats (Unix, ISO 8601, RFC 2822, etc.)
- Auto-detect timestamp format
- Convert between formats
- Timezone conversion
- Time difference calculation
- Time adjustment (add/subtract)
- JSON output support
- Built-in format descriptions

## Installation

```bash
cd B12_Timestamp_Parser
cargo build --release
```

## Usage

### Parse Timestamps

```bash
# Parse Unix timestamp
./target/release/timestamp_parser parse 1609459200

# Parse ISO 8601
./target/release/timestamp_parser parse "2021-01-01T00:00:00Z"

# Parse with format hint
./target/release/timestamp_parser parse "1609459200" --format unix

# Parse with timezone
./target/release/timestamp_parser parse "2021-01-01 12:00:00" -t "America/New_York"

# Output as JSON
./target/release/timestamp_parser parse 1609459200 --json
```

### Convert Between Formats

```bash
# Convert Unix to ISO 8601
./target/release/timestamp_parser convert 1609459200 --to iso8601

# Convert with timezone
./target/release/timestamp_parser convert "2021-01-01T00:00:00Z" --to mysql --to-tz "America/Los_Angeles"

# Convert to human readable
./target/release/timestamp_parser convert 1609459200 --to human
```

### Get Current Time

```bash
# Current time in Unix format
./target/release/timestamp_parser now --format unix

# Current time in ISO 8601
./target/release/timestamp_parser now --format iso8601

# Current time in specific timezone
./target/release/timestamp_parser now -t "Europe/London"
```

### Calculate Time Difference

```bash
# Difference between two timestamps
./target/release/timestamp_parser diff 1609459200 1609545600

# Difference in hours
./target/release/timestamp_parser diff "2021-01-01T00:00:00Z" "2021-01-02T12:00:00Z" --unit hours

# Human-readable difference
./target/release/timestamp_parser diff 1609459200 1609545600 --unit human
```

### Adjust Timestamps

```bash
# Add 1 hour
./target/release/timestamp_parser adjust 1609459200 "+1h"

# Subtract 30 minutes
./target/release/timestamp_parser adjust "2021-01-01T12:00:00Z" "-30m"

# Add 7 days
./target/release/timestamp_parser adjust 1609459200 "+7d"
```

### Detect Format

```bash
# Detect timestamp format
./target/release/timestamp_parser detect "1609459200"
./target/release/timestamp_parser detect "2021-01-01T00:00:00Z"
./target/release/timestamp_parser detect "Jan  5 14:32:10"
```

## Supported Formats

| Format | Example | Description |
|--------|---------|-------------|
| unix | 1609459200 | Unix timestamp (seconds) |
| unix-ms | 1609459200000 | Unix timestamp (milliseconds) |
| iso8601 | 2021-01-01T00:00:00+00:00 | ISO 8601 with timezone |
| rfc3339 | 2021-01-01T00:00:00Z | RFC 3339 format |
| rfc2822 | Fri, 01 Jan 2021 00:00:00 +0000 | Email format |
| common-log | 01/Jan/2021:00:00:00 +0000 | Apache/NCSA log format |
| syslog | Jan  1 00:00:00 | Syslog format |
| mysql | 2021-01-01 00:00:00 | MySQL datetime |
| human | January 01, 2021 at 12:00:00 AM | Human readable |

## Time Adjustment Units

| Unit | Symbol | Example |
|------|--------|---------|
| Seconds | s | +30s, -15s |
| Minutes | m | +5m, -10m |
| Hours | h | +1h, -2h |
| Days | d | +7d, -1d |
| Weeks | w | +2w, -1w |
| Months | M | +1M (approx 30 days) |
| Years | y | +1y (approx 365 days) |

## Common Security Log Formats

### Apache Access Log
```
192.168.1.1 - - [10/Oct/2024:13:55:36 -0700] "GET /admin HTTP/1.1" 404 274
```
Use: `--format common-log` or `--format apache`

### Syslog
```
Jan  5 14:32:10 hostname sshd[1234]: Failed password for root
```
Use: `--format syslog` (note: assumes current year)

### Windows Event Log
```
2024-10-10 13:55:36
```
Use: `--format mysql` or `--format windows-filetime`

## Rust Concepts Demonstrated

1. **Enums with Data**: TimestampFormat and Commands enums
2. **Custom Error Types**: TimestampError enum
3. **DateTime Handling**: chrono crate usage
4. **Timezone Support**: chrono-tz for IANA timezones
5. **Subcommands**: clap's Subcommand derive
6. **Serialization**: serde for JSON output
7. **Pattern Matching**: Complex match expressions
8. **Error Propagation**: The ? operator

## Example Output

```
$ ./timestamp_parser parse 1609459200

Parsed Timestamp
==================================================
  Original:     1609459200
  Format:       Unix timestamp (seconds since epoch)
  UTC:          2021-01-01 00:00:00 UTC
  Local:        2020-12-31 16:00:00 PST
  Unix:         1609459200
  Unix (ms):    1609459200000
  ISO 8601:     2021-01-01T00:00:00+00:00
  RFC 2822:     Fri, 01 Jan 2021 00:00:00 +0000
  Day of Week:  Friday
```

## Testing

```bash
cargo test
```

## Use Cases

### Incident Timeline
```bash
# Parse logs from different sources
./timestamp_parser parse "Jan  5 14:32:10" -t "America/New_York"
./timestamp_parser parse 1704480730
./timestamp_parser parse "2024-01-05T19:32:10Z"

# Compare to find sequence
./timestamp_parser diff 1704480730 1704480830 --unit seconds
```

### Log Normalization
```bash
# Convert all timestamps to UTC ISO 8601
./timestamp_parser convert "10/Oct/2024:13:55:36 -0700" --to iso8601 --to-tz UTC
```

### Time Window Analysis
```bash
# Check if event happened within 24 hours
./timestamp_parser diff "2024-01-05T10:00:00Z" "2024-01-06T09:00:00Z" --unit hours
```

## License

MIT License
