# B03 - File Operations

A security-focused file operations utility demonstrating proper file handling in Rust.

## Overview

This project covers essential file operations with an emphasis on security best practices:

- **Reading Files**: Secure file reading with path validation
- **Writing Files**: Atomic writes with backup support
- **Copying Files**: Permission-preserving file copies
- **Permission Management**: View and modify Unix file permissions
- **Security Auditing**: Detect potential security issues in files/directories

## Security Features

1. **Path Traversal Prevention**: Validates paths to prevent `../` attacks
2. **Symlink Detection**: Warns about symbolic links (potential attack vector)
3. **Permission Analysis**: Identifies world-writable files and SUID/SGID bits
4. **Null Byte Detection**: Catches null byte injection attempts

## Building

```bash
cargo build --release
```

## Usage

### Read a File

```bash
# Basic read
./file_ops read -p /path/to/file.txt

# With line numbers
./file_ops read -p /path/to/file.txt -n

# Read first 10 lines
./file_ops read -p /path/to/file.txt -l 10

# Hex dump (for binary files)
./file_ops read -p /path/to/binary -x
```

### Write to a File

```bash
# Write content directly
./file_ops write -p /path/to/file.txt -c "Hello, World!"

# Append to file
./file_ops write -p /path/to/file.txt -c "New line" -a

# Create backup before writing
./file_ops write -p /path/to/file.txt -c "New content" -b

# Read from stdin
echo "Content" | ./file_ops write -p /path/to/file.txt
```

### Copy Files

```bash
# Basic copy
./file_ops copy -s source.txt -d destination.txt

# Preserve permissions
./file_ops copy -s source.txt -d destination.txt -p

# Force overwrite
./file_ops copy -s source.txt -d destination.txt -f
```

### View/Set Permissions

```bash
# View permissions
./file_ops perms -p /path/to/file

# Set permissions (Unix only)
./file_ops perms -p /path/to/file -s 755
```

### Security Audit

```bash
# Audit a file
./file_ops audit -p /path/to/file

# Recursive directory audit
./file_ops audit -p /path/to/directory -r

# Verbose audit
./file_ops -v audit -p /path/to/directory -r
```

## Key Rust Concepts Demonstrated

### Error Handling

```rust
// Using thiserror for custom error types
#[derive(Error, Debug)]
pub enum FileOpsError {
    #[error("File not found: {0}")]
    NotFound(PathBuf),
}

// Using anyhow for context-rich errors
file.open(&path)
    .with_context(|| format!("Failed to open {:?}", path))?;
```

### File Operations

```rust
// Buffered reading for efficiency
let reader = BufReader::new(file);

// OpenOptions for fine-grained control
let file = OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .open(path)?;

// Ensure data is written to disk
file.sync_all()?;
```

### Path Handling

```rust
// Canonicalize to resolve symlinks and relative paths
let canonical = path.canonicalize()?;

// Platform-specific code with cfg
#[cfg(unix)]
fn unix_only_function() { }
```

## Security Considerations

1. **Always validate input paths** before performing operations
2. **Be cautious with symlinks** - they can point anywhere
3. **Check permissions** before and after file operations
4. **Use atomic operations** when possible to prevent race conditions
5. **Create backups** before modifying important files

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
- `tempfile` (dev) - Temporary file creation for tests
