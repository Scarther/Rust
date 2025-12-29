# I03 - Password Hash Cracker

A multi-threaded dictionary-based password hash cracker supporting MD5, SHA-1, SHA-256, SHA-512, and bcrypt.

## Features

- **Multiple Hash Algorithms**: MD5, SHA-1, SHA-256, SHA-512, bcrypt
- **Dictionary Attack**: Load wordlists from file
- **Password Mutations**: l33t speak, capitalization, common suffixes
- **Multi-threaded**: Parallel cracking using all CPU cores
- **Progress Tracking**: Real-time progress bar with speed stats
- **Batch Processing**: Crack multiple hashes from file
- **JSON Output**: Machine-readable results

## Rust Concepts Demonstrated

### Generics with Trait Bounds
```rust
// Generic function that works with any hash algorithm
fn compute_hash<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

// Usage - compiler generates specialized code for each type
let md5_hash = compute_hash::<md5::Md5>(b"password");
let sha_hash = compute_hash::<sha2::Sha256>(b"password");
```

### Atomic Types (Lock-Free Concurrency)
```rust
// AtomicBool - thread-safe boolean without mutex
let found = Arc::new(AtomicBool::new(false));

// Ordering determines memory synchronization
found.store(true, Ordering::SeqCst);   // Strong ordering
found.load(Ordering::Relaxed);          // Relaxed ordering

// AtomicU64 - thread-safe counter
let counter = Arc::new(AtomicU64::new(0));
counter.fetch_add(1, Ordering::Relaxed);  // Atomic increment
```

### Memory Mapping
```rust
// Map file directly into memory address space
let file = File::open("dictionary.txt")?;
let mmap = unsafe { Mmap::map(&file)? };

// Access file contents directly - OS handles paging
let content = std::str::from_utf8(&mmap)?;
```

### Parallel Early Exit
```rust
// find_map_any stops when ANY thread finds a match
words.par_iter().find_map_any(|word| {
    if hash(word) == target {
        Some(word.clone())
    } else {
        None
    }
})
```

## Usage

```bash
# Crack MD5 hash with dictionary
password_cracker -H 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -d wordlist.txt

# Crack SHA-256 hash with mutations enabled
password_cracker -H <hash> -a sha256 -d wordlist.txt --mutate

# Crack bcrypt hash
password_cracker -H '$2b$12$...' -a bcrypt -d wordlist.txt

# Use specific number of threads
password_cracker -H <hash> -a md5 -d wordlist.txt -t 8

# Append numbers 0-999 to each word
password_cracker -H <hash> -a md5 -d wordlist.txt --append-numbers

# Crack multiple hashes from file
password_cracker --hash-file hashes.txt -a md5 -d wordlist.txt -o results.json
```

## Command Reference

| Flag | Description |
|------|-------------|
| `-H, --hash` | Target hash to crack |
| `-a, --algorithm` | Hash type: md5, sha1, sha256, sha512, bcrypt |
| `-d, --dictionary` | Path to dictionary/wordlist file |
| `-t, --threads` | Number of threads (0 = auto) |
| `-m, --mutate` | Enable password mutations |
| `--append-numbers` | Append 0-999 to each word |
| `--hash-file` | File containing multiple hashes |
| `-o, --output` | Output results to JSON file |

## Password Mutations

When `--mutate` is enabled, the following transformations are applied:

- **Capitalization**: password, PASSWORD, Password
- **L33t Speak**: p455w0rd
- **Common Suffixes**: password!, password1, password123
- **Common Prefixes**: !password, @password, 123password

## Example Output

```
[*] Loading dictionary from wordlist.txt
[+] Loaded 10000 words
[*] Cracking MD5 hash: 5f4dcc3b5aa765d61d8327deb882cf99

════════════════════════════════════════════════════════════
 PASSWORD CRACKED!
════════════════════════════════════════════════════════════

[+] Hash:     5f4dcc3b5aa765d61d8327deb882cf99
[+] Password: password

[*] Statistics:
    Algorithm: MD5
    Attempts:  1,234
    Duration:  0.045s
    Speed:     27,422/sec
════════════════════════════════════════════════════════════
```

## Performance Tips

1. **Use SSD**: Dictionary loading is I/O bound
2. **More threads**: Set `-t` to number of CPU cores
3. **Order dictionary**: Put common passwords first
4. **Mutations**: Disable if dictionary already contains variants

## Building

```bash
cargo build --release
```

## Dependencies

- `clap`: CLI parsing
- `sha2`, `sha1`, `md-5`: Hash algorithms
- `bcrypt`: Bcrypt verification
- `rayon`: Parallel iteration
- `memmap2`: Memory-mapped file I/O
- `indicatif`: Progress bars

## Security Disclaimer

This tool is for educational purposes and authorized security testing only. Never use it to crack passwords without explicit permission.

## License

MIT License - Educational use only
