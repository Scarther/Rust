# Troubleshooting & FAQ

## Common Problems and Solutions

This guide covers the most common issues you'll encounter while learning Rust, with clear explanations and fixes.

---

## Installation Issues

### Problem: `rustc` or `cargo` not found

```
bash: rustc: command not found
bash: cargo: command not found
```

**Solution 1:** Restart your terminal or run:
```bash
source $HOME/.cargo/env
```

**Solution 2:** Add to your shell profile:
```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.cargo/bin:$PATH"
```

**Solution 3:** Reinstall Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

### Problem: Permission denied during installation

```
error: could not create directory '/usr/local/cargo'
```

**Solution:** Install to home directory (default):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Select option 1 for default installation (installs to `~/.cargo`).

---

## Compilation Errors

### Error E0382: Borrow of moved value

```rust
error[E0382]: borrow of moved value: `s`
 --> src/main.rs:4:20
  |
2 |     let s = String::from("hello");
  |         - move occurs because `s` has type `String`
3 |     let s2 = s;
  |              - value moved here
4 |     println!("{}", s);
  |                    ^ value borrowed here after move
```

**Why:** In Rust, assigning a `String` to another variable moves ownership.

**Fix 1:** Clone the value:
```rust
let s = String::from("hello");
let s2 = s.clone();  // Clone, not move
println!("{}", s);   // Now works!
```

**Fix 2:** Use a reference:
```rust
let s = String::from("hello");
let s2 = &s;  // Borrow, not move
println!("{}", s);   // Works!
```

**Fix 3:** Only use one variable:
```rust
let s = String::from("hello");
// Don't assign to s2
println!("{}", s);
```

---

### Error E0502: Cannot borrow as mutable because also borrowed as immutable

```rust
error[E0502]: cannot borrow `data` as mutable because it is also borrowed as immutable
 --> src/main.rs:5:5
  |
3 |     let first = &data[0];
  |                  ---- immutable borrow occurs here
4 |     data.push(4);
  |     ^^^^^^^^^^^^ mutable borrow occurs here
5 |     println!("{}", first);
  |                    ----- immutable borrow later used here
```

**Why:** You can't modify data while something else is reading it.

**Fix:** Finish using the immutable reference before mutating:
```rust
let mut data = vec![1, 2, 3];
let first = &data[0];
println!("{}", first);  // Use it now
// first goes out of scope here
data.push(4);  // Now safe to mutate
```

---

### Error E0499: Cannot borrow as mutable more than once

```rust
error[E0499]: cannot borrow `s` as mutable more than once at a time
```

**Why:** Only one mutable reference allowed at a time.

**Fix:** Use references in sequence, not simultaneously:
```rust
let mut s = String::from("hello");

let r1 = &mut s;
r1.push_str(" world");
// r1 is done being used here

let r2 = &mut s;  // Now this is OK
r2.push('!');
```

---

### Error: Expected type, found something else

```rust
error[E0308]: mismatched types
 --> src/main.rs:3:18
  |
3 |     let x: i32 = "hello";
  |            ---   ^^^^^^^ expected `i32`, found `&str`
  |            |
  |            expected due to this
```

**Why:** Type mismatch.

**Fix:** Use the correct type:
```rust
let x: i32 = 42;           // Integer
let y: &str = "hello";     // String slice
let z: String = String::from("hello");  // Owned string
```

---

### Error: Missing semicolon

```rust
error: expected `;`, found `}`
```

**Fix:** Add the semicolon:
```rust
// Wrong
fn main() {
    println!("hello")
}

// Right
fn main() {
    println!("hello");
}
```

---

### Error: Private field

```rust
error[E0616]: field `name` of struct `User` is private
```

**Why:** Struct fields are private by default.

**Fix:** Make fields public or add getter methods:
```rust
// Option 1: Public field
pub struct User {
    pub name: String,
}

// Option 2: Getter method
impl User {
    pub fn name(&self) -> &str {
        &self.name
    }
}
```

---

## Runtime Errors

### Panic: Index out of bounds

```
thread 'main' panicked at 'index out of bounds: the len is 3 but the index is 5'
```

**Why:** Accessing an array/vector element that doesn't exist.

**Fix:** Check bounds or use `.get()`:
```rust
let arr = [1, 2, 3];

// Safe access with get()
if let Some(value) = arr.get(5) {
    println!("{}", value);
} else {
    println!("Index out of bounds");
}

// Or check length first
if index < arr.len() {
    println!("{}", arr[index]);
}
```

---

### Panic: Unwrap on None

```
thread 'main' panicked at 'called `Option::unwrap()` on a `None` value'
```

**Why:** Called `.unwrap()` on `None`.

**Fix:** Use match or `if let`:
```rust
// Instead of:
let value = some_option.unwrap();

// Use:
match some_option {
    Some(value) => println!("{}", value),
    None => println!("No value"),
}

// Or:
if let Some(value) = some_option {
    println!("{}", value);
}

// Or with default:
let value = some_option.unwrap_or(default);
```

---

### Panic: Unwrap on Err

```
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: ...'
```

**Fix:** Handle the error:
```rust
// Instead of:
let file = File::open("config.txt").unwrap();

// Use:
let file = match File::open("config.txt") {
    Ok(f) => f,
    Err(e) => {
        eprintln!("Error opening file: {}", e);
        return;
    }
};

// Or with ? in functions that return Result:
let file = File::open("config.txt")?;
```

---

## Cargo Issues

### Problem: Dependency not found

```
error: failed to select a version for the requirement `some_crate = "^999.0"`
```

**Fix:** Check crates.io for correct version:
```bash
cargo search some_crate
```

Update `Cargo.toml` with valid version.

---

### Problem: Conflicting dependencies

```
error: failed to resolve: the current version of `tokio` is not compatible
```

**Fix:** Update dependencies:
```bash
cargo update
```

Or specify compatible versions in `Cargo.toml`.

---

### Problem: Build is slow

**Fix 1:** Use `cargo check` instead of `cargo build`:
```bash
cargo check  # Faster - just checks for errors
```

**Fix 2:** Enable incremental compilation (usually default):
```bash
export CARGO_INCREMENTAL=1
```

**Fix 3:** Use sccache for caching:
```bash
cargo install sccache
export RUSTC_WRAPPER=sccache
```

---

## Async/Tokio Issues

### Error: `async` without `await`

```
warning: unused implementer of `Future` that must be used
```

**Fix:** Add `.await`:
```rust
// Wrong
async fn fetch_data() {
    reqwest::get("https://api.example.com");  // Missing .await!
}

// Right
async fn fetch_data() {
    reqwest::get("https://api.example.com").await.unwrap();
}
```

---

### Error: Runtime not found

```
there is no reactor running, must be called from the context of a Tokio 1.x runtime
```

**Fix:** Use `#[tokio::main]` or create runtime:
```rust
#[tokio::main]
async fn main() {
    // Your async code here
}

// Or manually:
fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Your async code here
    });
}
```

---

## Networking Issues

### Error: Connection refused

```
Os { code: 111, kind: ConnectionRefused, message: "Connection refused" }
```

**Why:** Target host isn't accepting connections on that port.

**Fix:** Verify the service is running:
```bash
# Check if port is open
nc -zv localhost 8080

# Check if service is running
systemctl status your-service
```

---

### Error: Address already in use

```
Os { code: 98, kind: AddrInUse, message: "Address already in use" }
```

**Fix:** Use a different port or kill the existing process:
```bash
# Find what's using the port
lsof -i :8080

# Kill it
kill -9 <PID>
```

---

## FAQ

### Q: What's the difference between `String` and `&str`?

| `String` | `&str` |
|----------|--------|
| Owned, heap-allocated | Borrowed reference |
| Can be modified | Immutable view |
| Has `push()`, `push_str()` | No modification |
| Created with `String::from()` | String literals are `&str` |

```rust
let owned: String = String::from("hello");  // Owned
let borrowed: &str = "hello";               // Borrowed
let also_borrowed: &str = &owned;           // Borrow from String
```

---

### Q: When should I use `clone()`?

Use `clone()` when:
1. You need a true copy of the data
2. You can't restructure to use references
3. The data is small and copying is cheap

Avoid excessive `clone()` for performance - it's often a sign that you should rethink your approach.

---

### Q: What's the difference between `?` and `unwrap()`?

| `?` | `unwrap()` |
|-----|------------|
| Returns error to caller | Panics on error |
| Requires function returns `Result` | Works anywhere |
| Clean error propagation | Quick but dangerous |

```rust
// With ? - propagates error
fn read_file() -> Result<String, io::Error> {
    let content = fs::read_to_string("file.txt")?;
    Ok(content)
}

// With unwrap() - panics on error
fn read_file_dangerous() -> String {
    fs::read_to_string("file.txt").unwrap()
}
```

---

### Q: Why use `Vec<T>` instead of arrays?

| Array | Vec |
|-------|-----|
| Fixed size at compile time | Dynamic size |
| `[T; N]` | `Vec<T>` |
| Stack allocated | Heap allocated |
| Use when size is known | Use when size varies |

```rust
let array: [i32; 3] = [1, 2, 3];  // Fixed size
let mut vec: Vec<i32> = vec![1, 2, 3];  // Dynamic
vec.push(4);  // Can grow
```

---

### Q: How do I convert between types?

```rust
// String to &str
let s: String = String::from("hello");
let s_ref: &str = &s;

// &str to String
let s_ref: &str = "hello";
let s: String = s_ref.to_string();
// or
let s: String = String::from(s_ref);

// Number to String
let n: i32 = 42;
let s: String = n.to_string();

// String to number
let s: &str = "42";
let n: i32 = s.parse().unwrap();
// or with error handling
let n: i32 = s.parse()?;
```

---

### Q: How do I read command line arguments?

**Simple way:**
```rust
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("Program: {}", args[0]);
    if args.len() > 1 {
        println!("First arg: {}", args[1]);
    }
}
```

**Better way with clap:**
```rust
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    target: String,
}

fn main() {
    let args = Args::parse();
    println!("Target: {}", args.target);
}
```

---

## Still Stuck?

1. **Read the compiler message** - Rust has excellent error messages
2. **Search the error code** - Google "rust E0382"
3. **Check the docs** - `cargo doc --open`
4. **Ask the community:**
   - [Rust Users Forum](https://users.rust-lang.org/)
   - [r/rust](https://reddit.com/r/rust)
   - [Rust Discord](https://discord.gg/rust-lang)

---

[← Back to Main](./README.md)
