# Rust Security Bible - Glossary

## A

**AES (Advanced Encryption Standard)**
Symmetric encryption algorithm used for securing data. Common variants: AES-128, AES-256.

**Async/Await**
Rust's syntax for asynchronous programming. Enables non-blocking I/O operations.

**Arc (Atomically Reference Counted)**
Thread-safe reference counting smart pointer. Used for sharing ownership across threads.

## B

**Borrow Checker**
Rust's compile-time system that enforces ownership and borrowing rules.

**Borrowing**
Temporarily accessing data owned by another variable without taking ownership.

**Banner Grabbing**
Technique to identify services by reading their initial response message.

## C

**C2 (Command and Control)**
Infrastructure used to communicate with compromised systems.

**Cargo**
Rust's package manager and build system.

**Crate**
A Rust package that can be shared and reused.

**CLI (Command Line Interface)**
Text-based interface for interacting with programs.

**Clippy**
Rust's official linter for catching common mistakes and improving code.

## D

**DNS (Domain Name System)**
Protocol for resolving domain names to IP addresses.

**Drop Trait**
Rust trait that runs cleanup code when a value goes out of scope.

## E

**EDR (Endpoint Detection and Response)**
Security solution for monitoring and responding to threats on endpoints.

**Enum**
Rust type that can be one of several variants.

**Exfiltration**
Unauthorized transfer of data from a network.

## F

**FFI (Foreign Function Interface)**
Mechanism for calling code written in other languages from Rust.

**Future**
Rust type representing a value that may not be available yet.

## G

**GCM (Galois/Counter Mode)**
Authenticated encryption mode providing confidentiality and integrity.

**Goblin**
Rust crate for parsing binary formats (ELF, PE, Mach-O).

## H

**Hash Function**
One-way function that maps data to a fixed-size output.

**HMAC (Hash-based Message Authentication Code)**
Cryptographic construction for message authentication.

## I

**IOC (Indicator of Compromise)**
Artifact observed on a network or system indicating potential intrusion.

**IDS (Intrusion Detection System)**
System that monitors for malicious activity or policy violations.

**impl Block**
Rust block for implementing methods on types or traits.

## J

**JSON (JavaScript Object Notation)**
Lightweight data interchange format.

## K

**Key Derivation Function (KDF)**
Function that derives cryptographic keys from passwords or other secrets.

## L

**Lifetime**
Rust annotation that describes how long references are valid.

**LTO (Link-Time Optimization)**
Compiler optimization performed during linking for smaller/faster binaries.

## M

**MITRE ATT&CK**
Knowledge base of adversary tactics and techniques.

**Mutex**
Mutual exclusion primitive for protecting shared data.

**musl**
Alternative C library for building static Linux binaries.

## N

**NTP (Network Time Protocol)**
Protocol for clock synchronization.

## O

**Ownership**
Rust's system where each value has exactly one owner.

**Option<T>**
Rust enum representing a value that may or may not exist.

## P

**PCAP**
Packet capture file format for storing network traffic.

**PE (Portable Executable)**
Windows executable file format.

**pnet**
Rust crate for low-level network packet manipulation.

**Poisoned Mutex**
Mutex state after a thread panics while holding the lock.

## R

**Rayon**
Rust crate for data-parallelism.

**Reqwest**
Popular Rust HTTP client library.

**Result<T, E>**
Rust enum for operations that may fail.

**RwLock**
Read-write lock allowing multiple readers or one writer.

## S

**Serde**
Rust framework for serializing and deserializing data.

**SHA (Secure Hash Algorithm)**
Family of cryptographic hash functions.

**SIEM (Security Information and Event Management)**
System for collecting and analyzing security events.

**Smart Pointer**
Data structures that act like pointers but have additional metadata and capabilities.

**SYN Scan**
Port scanning technique using TCP SYN packets.

## T

**Tokio**
Async runtime for Rust providing event-driven, non-blocking I/O.

**Trait**
Rust mechanism for defining shared behavior.

**Trait Bound**
Constraint requiring a generic type to implement specific traits.

## U

**Unwrap**
Method to extract value from Option or Result, panicking on None/Err.

**UDP (User Datagram Protocol)**
Connectionless transport protocol.

## V

**Vec<T>**
Rust's growable array type.

## W

**WebSocket**
Protocol for full-duplex communication over TCP.

## X

**XOR**
Bitwise operation commonly used in cryptography.

**XSS (Cross-Site Scripting)**
Web vulnerability allowing injection of malicious scripts.

## Y

**YARA**
Pattern matching tool for malware research.

## Z

**Zeroize**
Rust crate for securely clearing sensitive data from memory.

**Zero-Copy**
Parsing technique that avoids copying data.

---

## Acronym Reference

| Acronym | Meaning |
|---------|---------|
| AES | Advanced Encryption Standard |
| API | Application Programming Interface |
| C2 | Command and Control |
| CLI | Command Line Interface |
| DNS | Domain Name System |
| EDR | Endpoint Detection and Response |
| ELF | Executable and Linkable Format |
| FFI | Foreign Function Interface |
| GCM | Galois/Counter Mode |
| HMAC | Hash-based Message Authentication Code |
| IDS | Intrusion Detection System |
| IOC | Indicator of Compromise |
| IP | Internet Protocol |
| JSON | JavaScript Object Notation |
| KDF | Key Derivation Function |
| LTO | Link-Time Optimization |
| PE | Portable Executable |
| PCAP | Packet Capture |
| SHA | Secure Hash Algorithm |
| SIEM | Security Information and Event Management |
| SQL | Structured Query Language |
| TCP | Transmission Control Protocol |
| UDP | User Datagram Protocol |
| XSS | Cross-Site Scripting |

---

[← Back to Main](./README.md)
