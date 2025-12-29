# B05 - Process Information Tool

A security-focused process information gathering and analysis utility.

## Overview

This project provides comprehensive process inspection for security analysis:

- **Process Listing**: View all running processes with filtering
- **Process Details**: Get detailed information about specific processes
- **Process Tree**: Visualize parent-child relationships
- **Security Audit**: Detect suspicious process activity
- **Real-time Monitoring**: Watch process resource usage

## Security Features

1. **Suspicious Process Detection**: Identifies known hacking tools
2. **Deleted Executable Detection**: Finds processes running from deleted files
3. **Temp Directory Execution**: Flags processes in /tmp
4. **Reverse Shell Detection**: Identifies potential reverse shell patterns
5. **Privilege Analysis**: Monitors root process execution

## Building

```bash
cargo build --release
```

## Usage

### Show Current Process

```bash
# Basic info
./process_info self

# Include environment variables
./process_info self -e
```

### List Processes

```bash
# List all processes
./process_info list

# Filter by name
./process_info list -n bash

# Filter by user
./process_info list -u root

# Sort by CPU usage
./process_info list -s cpu

# Limit output
./process_info list -l 20

# Show high CPU processes
./process_info list --high-cpu 50

# Show high memory processes (MB)
./process_info list --high-mem 100
```

### Process Details

```bash
# Get info about specific PID
./process_info info 1234

# Include environment
./process_info info 1234 -e
```

### Process Tree

```bash
# Show full tree
./process_info tree

# Start from specific PID
./process_info tree -r 1234

# Limit depth
./process_info tree -d 3
```

### System Summary

```bash
./process_info system
```

### Security Audit

```bash
# Full audit
./process_info audit

# Only high severity (7+)
./process_info audit -m 7
```

### Find Process

```bash
# Find by name
./process_info find nginx

# Case insensitive
./process_info find NGINX -i
```

### Monitor Process

```bash
# Monitor for 10 updates
./process_info monitor 1234

# Custom interval and count
./process_info monitor 1234 -i 2 -c 30

# Monitor indefinitely
./process_info monitor 1234 -c 0
```

## Key Rust Concepts Demonstrated

### System Information

```rust
use sysinfo::{System, Pid};

// Create and refresh system info
let mut sys = System::new_all();
sys.refresh_all();

// Get process info
if let Some(process) = sys.process(Pid::from_u32(pid)) {
    println!("Name: {}", process.name());
    println!("CPU: {}%", process.cpu_usage());
}
```

### Collections

```rust
use std::collections::HashMap;

// Build parent-child relationships
let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
for (pid, process) in sys.processes() {
    let ppid = process.parent().unwrap_or(0);
    children.entry(ppid).or_default().push(*pid);
}
```

### Error Handling with Custom Types

```rust
#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("Process not found: {0}")]
    NotFound(u32),
}

// Use in functions
fn get_process(pid: u32) -> Result<ProcessInfo, ProcessError> {
    sys.process(pid).ok_or(ProcessError::NotFound(pid))
}
```

## Security Audit Indicators

| Indicator | Severity | Description |
|-----------|----------|-------------|
| reverse_shell | 10 | Reverse shell patterns detected |
| deleted_exe | 9 | Executable deleted while running |
| known_tool | 7 | Known security/hacking tool |
| temp_execution | 6 | Running from /tmp directory |
| hidden_directory | 5 | Running from hidden directory |
| root_process | 4 | Non-system root process |
| base64_usage | 4 | Base64 in command line |
| high_cpu | 3 | CPU usage > 90% |

## Process Status Codes

| Code | Meaning |
|------|---------|
| R | Running |
| S | Sleeping |
| T | Stopped |
| Z | Zombie |
| I | Idle |
| D | Disk sleep |

## Security Considerations

1. **Accessing process info** may require elevated privileges
2. **Environment variables** can contain sensitive data
3. **Process listings** reveal system activity
4. **Zombie processes** may indicate issues
5. **Deleted executables** are often malware indicators

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

## Dependencies

- `clap` - Command-line argument parsing
- `anyhow` - Error handling with context
- `thiserror` - Custom error type derivation
- `colored` - Terminal color output
- `sysinfo` - Cross-platform system information
- `users` - User information lookup
- `serde` / `serde_json` - Serialization
