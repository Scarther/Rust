//! # Ownership Exercises
//!
//! These exercises will help you understand Rust's ownership system,
//! which is fundamental to memory safety in security applications.
//!
//! Complete each exercise by fixing the code or implementing the required functionality.
//! Run with: cargo run
//! Check solutions in: src/solutions.rs

#![allow(unused_variables, dead_code)]

mod solutions;

fn main() {
    println!("=== Rust Ownership Exercises ===\n");

    println!("Exercise 1: Basic Ownership Transfer");
    exercise_1();

    println!("\nExercise 2: Clone vs Move");
    exercise_2();

    println!("\nExercise 3: Ownership in Functions");
    exercise_3();

    println!("\nExercise 4: Return Ownership");
    exercise_4();

    println!("\nExercise 5: Ownership with Tuples");
    exercise_5();

    println!("\nExercise 6: Security Context Ownership");
    exercise_6();

    println!("\nExercise 7: Sensitive Data Handling");
    exercise_7();

    println!("\nExercise 8: Resource Management");
    exercise_8();

    println!("\nExercise 9: Ownership Chains");
    exercise_9();

    println!("\nExercise 10: Challenge - Secure Memory Transfer");
    exercise_10();

    println!("\n=== All exercises completed! ===");
}

// =============================================================================
// EXERCISE 1: Basic Ownership Transfer
// =============================================================================
//
// The code below has an ownership error. The string `password` is moved
// when assigned to `backup`, making the original unusable.
//
// YOUR TASK: Fix the code so both variables can be printed.
// HINT: Use .clone() to create an independent copy.
//
fn exercise_1() {
    let password = String::from("supersecret123");

    // TODO: Fix this line - password is moved here
    let backup = password; // This moves ownership

    // This will cause a compile error because password was moved
    // Uncomment and fix:
    // println!("Original password: {}", password);
    // println!("Backup password: {}", backup);

    // For now, just print to show it runs:
    println!("  [Exercise 1 - Fix the ownership transfer]");

    // Call solution to see the correct implementation:
    solutions::solution_1();
}

// =============================================================================
// EXERCISE 2: Clone vs Move
// =============================================================================
//
// Understanding when to clone and when moving is acceptable is crucial
// for efficient and secure code.
//
// YOUR TASK: Implement secure_copy that creates an independent copy,
// and transfer_ownership that moves without cloning.
//
fn exercise_2() {
    // TODO: Implement these functions
    fn secure_copy(data: &String) -> String {
        // Return a clone of the data
        String::new() // Replace this
    }

    fn transfer_ownership(data: String) -> String {
        // Just return the data (ownership transfers)
        data
    }

    let secret = String::from("api_key_12345");

    // Create a copy - original should still be valid
    let copy = secure_copy(&secret);
    println!("  Original still valid: {}", secret.len() > 0);

    // Transfer ownership - original will be invalid after this
    let transferred = transfer_ownership(secret);
    // println!("{}", secret); // This would fail!

    println!("  Transferred: {} bytes", transferred.len());

    solutions::solution_2();
}

// =============================================================================
// EXERCISE 3: Ownership in Functions
// =============================================================================
//
// Functions can take ownership of parameters, which is destroyed when
// the function ends unless returned.
//
// YOUR TASK: Fix encrypt_data to return ownership so the data isn't lost.
//
fn exercise_3() {
    fn encrypt_data(data: String) -> String {
        // Simple "encryption" (XOR with 0x42 for demonstration)
        let encrypted: Vec<u8> = data.bytes().map(|b| b ^ 0x42).collect();
        // TODO: Return the encrypted data as a hex string
        String::new() // Replace this
    }

    fn decrypt_data(hex_data: String) -> String {
        // TODO: Implement decryption (reverse of encrypt)
        String::new() // Replace this
    }

    let sensitive = String::from("password123");
    // After this call, sensitive is moved into encrypt_data
    let encrypted = encrypt_data(sensitive.clone());

    println!("  [Exercise 3 - Implement encrypt/decrypt with ownership]");

    solutions::solution_3();
}

// =============================================================================
// EXERCISE 4: Return Ownership
// =============================================================================
//
// Sometimes you need to take ownership, process data, and return it.
// This pattern is common in security contexts for data transformation.
//
// YOUR TASK: Implement process_credentials that takes ownership,
// processes the data, and returns ownership of the result.
//
fn exercise_4() {
    struct Credentials {
        username: String,
        password: String,
    }

    fn process_credentials(creds: Credentials) -> Credentials {
        // TODO: Transform credentials (e.g., trim whitespace, lowercase username)
        // Return ownership of the processed credentials
        creds // Modify this
    }

    let raw_creds = Credentials {
        username: String::from("  ADMIN  "),
        password: String::from("secret123"),
    };

    let processed = process_credentials(raw_creds);
    // raw_creds is no longer valid here

    println!("  [Exercise 4 - Process and return ownership]");

    solutions::solution_4();
}

// =============================================================================
// EXERCISE 5: Ownership with Tuples
// =============================================================================
//
// Tuples can help return multiple values with their ownership.
// This is useful for returning both data and metadata.
//
// YOUR TASK: Implement analyze_packet that returns a tuple with
// the processed packet and analysis results.
//
fn exercise_5() {
    fn analyze_packet(packet: Vec<u8>) -> (Vec<u8>, usize, bool) {
        // TODO: Analyze the packet
        // Return: (original packet, size, is_suspicious)
        let size = packet.len();
        let suspicious = packet.iter().any(|&b| b == 0x00);
        (packet, size, suspicious)
    }

    let packet = vec![0x48, 0x45, 0x4C, 0x4C, 0x4F];
    let (returned_packet, size, suspicious) = analyze_packet(packet);
    // packet is moved, but returned_packet has ownership now

    println!("  Packet size: {}, Suspicious: {}", size, suspicious);

    solutions::solution_5();
}

// =============================================================================
// EXERCISE 6: Security Context Ownership
// =============================================================================
//
// In security applications, managing ownership of security contexts
// is critical. The context should only be accessible to authorized code.
//
// YOUR TASK: Implement a SecurityContext that can only be used once.
//
fn exercise_6() {
    struct SecurityContext {
        token: String,
        permissions: Vec<String>,
    }

    impl SecurityContext {
        fn new(token: String) -> Self {
            SecurityContext {
                token,
                permissions: vec![String::from("read"), String::from("write")],
            }
        }

        // This consumes the context - it can only be used once
        fn consume(self) -> String {
            format!("Token {} consumed with {:?}", self.token, self.permissions)
        }
    }

    let ctx = SecurityContext::new(String::from("auth_token_xyz"));
    let result = ctx.consume();
    // ctx is no longer valid - cannot be reused
    // let again = ctx.consume(); // This would fail!

    println!("  {}", result);

    solutions::solution_6();
}

// =============================================================================
// EXERCISE 7: Sensitive Data Handling
// =============================================================================
//
// When handling sensitive data, ownership ensures the data is properly
// cleaned up when it goes out of scope.
//
// YOUR TASK: Implement SecureString that clears memory when dropped.
//
fn exercise_7() {
    struct SecureString {
        data: Vec<u8>,
    }

    impl SecureString {
        fn new(s: &str) -> Self {
            SecureString {
                data: s.as_bytes().to_vec(),
            }
        }

        fn as_str(&self) -> &str {
            std::str::from_utf8(&self.data).unwrap_or("")
        }
    }

    impl Drop for SecureString {
        fn drop(&mut self) {
            // TODO: Zero out the memory before dropping
            // This prevents the data from lingering in memory
            for byte in &mut self.data {
                *byte = 0;
            }
            println!("  [SecureString memory cleared]");
        }
    }

    {
        let secret = SecureString::new("my_password");
        println!("  Secret length: {}", secret.data.len());
        // secret goes out of scope here and Drop is called
    }

    solutions::solution_7();
}

// =============================================================================
// EXERCISE 8: Resource Management
// =============================================================================
//
// Ownership is perfect for managing resources like file handles,
// network connections, or cryptographic keys.
//
// YOUR TASK: Implement a CryptoKey that can only be used while owned.
//
fn exercise_8() {
    struct CryptoKey {
        key_data: [u8; 32],
        algorithm: String,
    }

    impl CryptoKey {
        fn generate(algorithm: &str) -> Self {
            // Simulate key generation
            let mut key_data = [0u8; 32];
            for i in 0..32 {
                key_data[i] = (i as u8).wrapping_mul(7);
            }
            CryptoKey {
                key_data,
                algorithm: algorithm.to_string(),
            }
        }

        // Takes ownership - key is consumed after encryption
        fn encrypt_and_destroy(self, data: &[u8]) -> Vec<u8> {
            // Simple XOR encryption for demonstration
            let encrypted: Vec<u8> = data.iter()
                .zip(self.key_data.iter().cycle())
                .map(|(d, k)| d ^ k)
                .collect();
            encrypted
            // self is dropped here, key_data is destroyed
        }
    }

    let key = CryptoKey::generate("AES-256");
    let plaintext = b"Secret message";
    let ciphertext = key.encrypt_and_destroy(plaintext);
    // key is no longer valid - cannot be reused

    println!("  Encrypted {} bytes", ciphertext.len());

    solutions::solution_8();
}

// =============================================================================
// EXERCISE 9: Ownership Chains
// =============================================================================
//
// When data passes through multiple functions, ownership transfers
// create a clear chain of custody.
//
// YOUR TASK: Implement a data pipeline where ownership flows through
// multiple processing stages.
//
fn exercise_9() {
    fn receive_data() -> Vec<u8> {
        vec![72, 101, 108, 108, 111] // "Hello"
    }

    fn validate_data(data: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        // TODO: Validate and return ownership if valid
        if data.is_empty() {
            Err("Empty data")
        } else {
            Ok(data)
        }
    }

    fn process_data(data: Vec<u8>) -> Vec<u8> {
        // TODO: Process (e.g., uppercase) and return ownership
        data.iter().map(|&b| {
            if b >= 97 && b <= 122 {
                b - 32
            } else {
                b
            }
        }).collect()
    }

    fn store_data(data: Vec<u8>) -> usize {
        // Consumes the data, returns bytes stored
        let len = data.len();
        // data is dropped here
        len
    }

    // Chain of ownership
    let raw = receive_data();
    let validated = validate_data(raw).expect("Validation failed");
    let processed = process_data(validated);
    let bytes_stored = store_data(processed);

    println!("  Stored {} bytes through the pipeline", bytes_stored);

    solutions::solution_9();
}

// =============================================================================
// EXERCISE 10: Challenge - Secure Memory Transfer
// =============================================================================
//
// Create a secure memory transfer system that ensures:
// 1. Data can only be read once
// 2. Memory is cleared after transfer
// 3. Ownership tracking prevents double-reads
//
// YOUR TASK: Implement SecureTransfer with these properties.
//
fn exercise_10() {
    struct SecureTransfer<T> {
        data: Option<T>,
        read_count: usize,
    }

    impl<T> SecureTransfer<T> {
        fn new(data: T) -> Self {
            SecureTransfer {
                data: Some(data),
                read_count: 0,
            }
        }

        // Takes ownership of self, returns the data (consumed after)
        fn take(mut self) -> Option<T> {
            self.read_count += 1;
            if self.read_count > 1 {
                None // Already read
            } else {
                self.data.take()
            }
        }

        fn is_available(&self) -> bool {
            self.data.is_some()
        }
    }

    let transfer = SecureTransfer::new(String::from("one-time-secret"));
    println!("  Available: {}", transfer.is_available());

    if let Some(secret) = transfer.take() {
        println!("  Retrieved: {} chars", secret.len());
    }
    // transfer is consumed, cannot be used again

    solutions::solution_10();
}
