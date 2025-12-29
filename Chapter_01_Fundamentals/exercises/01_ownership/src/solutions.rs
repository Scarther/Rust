//! # Solutions for Ownership Exercises
//!
//! These are the reference solutions. Try to solve the exercises
//! yourself before looking at these!

/// Solution 1: Use clone() to create an independent copy
pub fn solution_1() {
    println!("  [Solution 1]:");
    let password = String::from("supersecret123");
    let backup = password.clone(); // Clone creates an independent copy

    println!("    Original password: {}", password);
    println!("    Backup password: {}", backup);
}

/// Solution 2: Clone vs Move implementations
pub fn solution_2() {
    println!("  [Solution 2]:");

    fn secure_copy(data: &String) -> String {
        data.clone() // Create an independent copy
    }

    fn transfer_ownership(data: String) -> String {
        data // Ownership moves through the function
    }

    let secret = String::from("api_key_12345");
    let copy = secure_copy(&secret);

    println!("    Original: {} bytes", secret.len());
    println!("    Copy: {} bytes", copy.len());

    let transferred = transfer_ownership(secret);
    println!("    Transferred: {} bytes", transferred.len());
}

/// Solution 3: Encrypt and decrypt with proper ownership
pub fn solution_3() {
    println!("  [Solution 3]:");

    fn encrypt_data(data: String) -> String {
        let encrypted: Vec<u8> = data.bytes().map(|b| b ^ 0x42).collect();
        encrypted.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn decrypt_data(hex_data: String) -> String {
        let bytes: Vec<u8> = (0..hex_data.len())
            .step_by(2)
            .filter_map(|i| {
                u8::from_str_radix(&hex_data[i..i + 2], 16).ok()
            })
            .map(|b| b ^ 0x42)
            .collect();
        String::from_utf8(bytes).unwrap_or_default()
    }

    let sensitive = String::from("password123");
    let encrypted = encrypt_data(sensitive);
    println!("    Encrypted: {}", encrypted);

    let decrypted = decrypt_data(encrypted);
    println!("    Decrypted: {}", decrypted);
}

/// Solution 4: Process credentials with ownership transfer
pub fn solution_4() {
    println!("  [Solution 4]:");

    struct Credentials {
        username: String,
        password: String,
    }

    fn process_credentials(creds: Credentials) -> Credentials {
        Credentials {
            username: creds.username.trim().to_lowercase(),
            password: creds.password, // Don't modify password
        }
    }

    let raw_creds = Credentials {
        username: String::from("  ADMIN  "),
        password: String::from("secret123"),
    };

    let processed = process_credentials(raw_creds);
    println!("    Processed username: '{}'", processed.username);
    println!("    Password preserved: {} chars", processed.password.len());
}

/// Solution 5: Analyze packet with tuple return
pub fn solution_5() {
    println!("  [Solution 5]:");

    fn analyze_packet(packet: Vec<u8>) -> (Vec<u8>, usize, bool, String) {
        let size = packet.len();
        let has_null = packet.iter().any(|&b| b == 0x00);
        let has_high_bytes = packet.iter().any(|&b| b > 127);
        let suspicious = has_null || has_high_bytes;

        let classification = if suspicious {
            String::from("SUSPICIOUS")
        } else {
            String::from("CLEAN")
        };

        (packet, size, suspicious, classification)
    }

    let packet = vec![0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x00];
    let (returned_packet, size, suspicious, class) = analyze_packet(packet);

    println!("    Size: {} bytes", size);
    println!("    Classification: {}", class);
    println!("    Packet preserved: {} bytes", returned_packet.len());
}

/// Solution 6: Security context with single-use consumption
pub fn solution_6() {
    println!("  [Solution 6]:");

    struct SecurityContext {
        token: String,
        permissions: Vec<String>,
        created_at: std::time::Instant,
    }

    impl SecurityContext {
        fn new(token: String) -> Self {
            SecurityContext {
                token,
                permissions: vec![
                    String::from("read"),
                    String::from("write"),
                    String::from("execute"),
                ],
                created_at: std::time::Instant::now(),
            }
        }

        fn consume(self) -> (String, Vec<String>) {
            // Context is consumed, cannot be reused
            (self.token, self.permissions)
        }

        // Alternative: verify and consume
        fn verify_and_consume(self, expected_permission: &str) -> Result<String, String> {
            if self.permissions.contains(&expected_permission.to_string()) {
                Ok(self.token)
            } else {
                Err(format!("Permission '{}' not found", expected_permission))
            }
        }
    }

    let ctx = SecurityContext::new(String::from("secure_token_abc"));
    match ctx.verify_and_consume("write") {
        Ok(token) => println!("    Verified and consumed: {}", token),
        Err(e) => println!("    Error: {}", e),
    }
}

/// Solution 7: SecureString with memory clearing
pub fn solution_7() {
    println!("  [Solution 7]:");

    use std::ptr;

    struct SecureString {
        data: Vec<u8>,
    }

    impl SecureString {
        fn new(s: &str) -> Self {
            SecureString {
                data: s.as_bytes().to_vec(),
            }
        }

        fn as_str(&self) -> Option<&str> {
            std::str::from_utf8(&self.data).ok()
        }

        fn len(&self) -> usize {
            self.data.len()
        }
    }

    impl Drop for SecureString {
        fn drop(&mut self) {
            // Securely zero out memory
            // Using volatile write to prevent optimization
            for byte in &mut self.data {
                unsafe {
                    ptr::write_volatile(byte, 0);
                }
            }
            // Additional read to ensure write isn't optimized away
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            println!("    [SecureString: {} bytes securely cleared]", self.data.len());
        }
    }

    {
        let secret = SecureString::new("super_secret_password");
        println!("    Secret created: {} bytes", secret.len());
    }
    println!("    Secret has been dropped and cleared");
}

/// Solution 8: CryptoKey with consumption pattern
pub fn solution_8() {
    println!("  [Solution 8]:");

    struct CryptoKey {
        key_data: [u8; 32],
        algorithm: String,
        used: bool,
    }

    impl CryptoKey {
        fn generate(algorithm: &str) -> Self {
            // In real code, use a CSPRNG
            let mut key_data = [0u8; 32];
            for (i, byte) in key_data.iter_mut().enumerate() {
                *byte = ((i as u8).wrapping_mul(31).wrapping_add(17)) ^ 0xAB;
            }
            CryptoKey {
                key_data,
                algorithm: algorithm.to_string(),
                used: false,
            }
        }

        fn encrypt(mut self, data: &[u8]) -> (Vec<u8>, CryptoKey) {
            self.used = true;
            let encrypted: Vec<u8> = data
                .iter()
                .zip(self.key_data.iter().cycle())
                .map(|(d, k)| d ^ k)
                .collect();
            (encrypted, self) // Return key for potential decryption
        }

        fn encrypt_and_destroy(self, data: &[u8]) -> Vec<u8> {
            let encrypted: Vec<u8> = data
                .iter()
                .zip(self.key_data.iter().cycle())
                .map(|(d, k)| d ^ k)
                .collect();
            // Key is dropped here, cannot be reused
            encrypted
        }
    }

    impl Drop for CryptoKey {
        fn drop(&mut self) {
            // Zero out key material
            for byte in &mut self.key_data {
                *byte = 0;
            }
            println!("    [CryptoKey ({}) securely destroyed]", self.algorithm);
        }
    }

    let key = CryptoKey::generate("AES-256-GCM");
    let plaintext = b"Classified Information";
    let ciphertext = key.encrypt_and_destroy(plaintext);
    println!("    Encrypted: {} bytes", ciphertext.len());
}

/// Solution 9: Ownership chain pipeline
pub fn solution_9() {
    println!("  [Solution 9]:");

    #[derive(Debug)]
    struct AuditLog {
        stage: String,
        bytes: usize,
    }

    struct Pipeline {
        logs: Vec<AuditLog>,
    }

    impl Pipeline {
        fn new() -> Self {
            Pipeline { logs: Vec::new() }
        }

        fn receive(&mut self) -> Vec<u8> {
            let data = vec![104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
            self.logs.push(AuditLog {
                stage: String::from("receive"),
                bytes: data.len(),
            });
            data
        }

        fn validate(&mut self, data: Vec<u8>) -> Result<Vec<u8>, &'static str> {
            if data.is_empty() {
                return Err("Empty data rejected");
            }
            if data.len() > 1024 {
                return Err("Data too large");
            }
            self.logs.push(AuditLog {
                stage: String::from("validate"),
                bytes: data.len(),
            });
            Ok(data)
        }

        fn transform(&mut self, data: Vec<u8>) -> Vec<u8> {
            let transformed: Vec<u8> = data
                .iter()
                .map(|&b| if b >= 97 && b <= 122 { b - 32 } else { b })
                .collect();
            self.logs.push(AuditLog {
                stage: String::from("transform"),
                bytes: transformed.len(),
            });
            transformed
        }

        fn finalize(&mut self, data: Vec<u8>) -> String {
            self.logs.push(AuditLog {
                stage: String::from("finalize"),
                bytes: data.len(),
            });
            String::from_utf8(data).unwrap_or_default()
        }

        fn get_audit_trail(&self) -> &[AuditLog] {
            &self.logs
        }
    }

    let mut pipeline = Pipeline::new();

    let raw = pipeline.receive();
    let validated = pipeline.validate(raw).expect("Validation failed");
    let transformed = pipeline.transform(validated);
    let final_result = pipeline.finalize(transformed);

    println!("    Result: {}", final_result);
    println!("    Audit trail:");
    for log in pipeline.get_audit_trail() {
        println!("      - {:?}", log);
    }
}

/// Solution 10: Secure single-read transfer
pub fn solution_10() {
    println!("  [Solution 10]:");

    use std::ptr;

    struct SecureTransfer<T> {
        data: Option<T>,
        transferred: bool,
    }

    impl<T> SecureTransfer<T> {
        fn new(data: T) -> Self {
            println!("    [SecureTransfer: Package created]");
            SecureTransfer {
                data: Some(data),
                transferred: false,
            }
        }

        fn is_available(&self) -> bool {
            self.data.is_some() && !self.transferred
        }

        // Consumes the transfer, data can only be retrieved once
        fn take(mut self) -> Option<T> {
            if self.transferred {
                println!("    [SecureTransfer: Already transferred!]");
                None
            } else {
                self.transferred = true;
                let result = self.data.take();
                println!("    [SecureTransfer: Data transferred]");
                result
            }
        }
    }

    // Implement secure string clearing for string transfers
    impl SecureTransfer<String> {
        fn take_and_clear(mut self) -> Option<String> {
            if self.transferred {
                None
            } else {
                self.transferred = true;
                self.data.take()
                // Original data in SecureTransfer is now None
            }
        }
    }

    impl<T> Drop for SecureTransfer<T> {
        fn drop(&mut self) {
            if self.data.is_some() {
                println!("    [SecureTransfer: Unclaimed data destroyed]");
            } else {
                println!("    [SecureTransfer: Container cleaned up]");
            }
        }
    }

    // Demonstrate single-use pattern
    let transfer1 = SecureTransfer::new(String::from("classified-data"));
    println!("    Available: {}", transfer1.is_available());

    if let Some(data) = transfer1.take() {
        println!("    Retrieved: '{}' ({} chars)", data, data.len());
    }

    // Demonstrate unclaimed data destruction
    println!("\n    Creating unclaimed transfer:");
    let _transfer2 = SecureTransfer::new(String::from("never-retrieved"));
    // transfer2 goes out of scope without being taken
}
