# Security Tool Project Ideas

## Portfolio-worthy projects to build after completing this guide.

---

## Beginner Projects

### 1. Password Strength Checker
**Difficulty:** Easy | **Time:** 2-4 hours

Build a CLI tool that:
- Checks password length, complexity, character variety
- Estimates crack time
- Checks against common password lists
- Provides improvement suggestions

**Skills:** File I/O, string manipulation, CLI parsing

---

### 2. File Hasher
**Difficulty:** Easy | **Time:** 2-4 hours

Build a tool that:
- Calculates MD5, SHA1, SHA256 for files
- Compares against known hashes
- Supports batch processing
- Outputs in multiple formats (text, JSON, CSV)

**Skills:** Crypto crates, file handling, output formatting

---

### 3. IP/Domain Validator
**Difficulty:** Easy | **Time:** 3-5 hours

Build a tool that:
- Validates IP addresses (IPv4/IPv6)
- Validates domain names
- Resolves domains to IPs
- Checks if IPs are private/public/reserved

**Skills:** Regex, DNS resolution, networking basics

---

### 4. Log File Analyzer
**Difficulty:** Easy-Medium | **Time:** 4-8 hours

Build a tool that:
- Parses common log formats (Apache, syslog)
- Counts events by type/source
- Identifies anomalies (high frequency, odd times)
- Generates summary reports

**Skills:** Regex, file parsing, aggregation

---

### 5. Encoding/Decoding Multi-Tool
**Difficulty:** Easy | **Time:** 3-5 hours

Build a tool that:
- Encodes/decodes Base64, Hex, URL encoding
- Detects encoding type automatically
- Supports file and stdin input
- Chain multiple transformations

**Skills:** String manipulation, CLI design

---

## Intermediate Projects

### 6. Network Scanner
**Difficulty:** Medium | **Time:** 8-16 hours

Build a tool that:
- Discovers hosts on a network (ping sweep)
- Scans TCP/UDP ports
- Grabs service banners
- Outputs in multiple formats
- Supports rate limiting

**Skills:** Async programming, networking, concurrency

---

### 7. Web Vulnerability Scanner
**Difficulty:** Medium | **Time:** 12-20 hours

Build a tool that:
- Crawls websites
- Tests for common vulnerabilities (XSS, SQLi indicators)
- Checks security headers
- Identifies outdated software
- Generates HTML reports

**Skills:** HTTP clients, HTML parsing, vulnerability detection

---

### 8. File Integrity Monitor
**Difficulty:** Medium | **Time:** 8-12 hours

Build a daemon that:
- Creates baseline of file hashes
- Monitors directories for changes
- Alerts on modifications/deletions/additions
- Logs all changes
- Supports ignore patterns

**Skills:** File system, hashing, background services

---

### 9. API Security Tester
**Difficulty:** Medium | **Time:** 10-15 hours

Build a tool that:
- Tests API endpoints for common issues
- Checks authentication bypasses
- Tests rate limiting
- Validates input handling
- Generates test reports

**Skills:** HTTP, JSON, async requests

---

### 10. Credential Manager
**Difficulty:** Medium | **Time:** 8-12 hours

Build a tool that:
- Stores credentials encrypted
- Uses master password
- Generates strong passwords
- Supports multiple vaults
- CLI and/or TUI interface

**Skills:** Encryption, secure storage, UI

---

## Advanced Projects

### 11. Packet Sniffer/Analyzer
**Difficulty:** Hard | **Time:** 20-40 hours

Build a tool that:
- Captures network packets
- Parses common protocols (TCP, UDP, HTTP, DNS)
- Filters by various criteria
- Detects suspicious patterns
- Saves to PCAP format

**Skills:** Raw sockets, protocol parsing, libpcap

---

### 12. Binary Analysis Tool
**Difficulty:** Hard | **Time:** 20-30 hours

Build a tool that:
- Parses PE and ELF formats
- Extracts strings and imports
- Calculates entropy
- Identifies packers
- Generates analysis reports

**Skills:** Binary parsing, file formats, static analysis

---

### 13. Custom IDS/IPS
**Difficulty:** Hard | **Time:** 40-60 hours

Build a system that:
- Monitors network traffic
- Matches against rule sets (Snort/Suricata compatible)
- Alerts on detections
- Optionally blocks traffic
- Web dashboard for monitoring

**Skills:** Packet capture, rule engines, real-time processing

---

### 14. Malware Sandbox
**Difficulty:** Hard | **Time:** 30-50 hours

Build a system that:
- Executes samples in isolated environment
- Monitors file/network/process activity
- Captures behavioral indicators
- Generates analysis reports
- Uses virtualization/containers

**Skills:** System calls, virtualization, behavior analysis

---

### 15. SIEM Collector
**Difficulty:** Hard | **Time:** 25-40 hours

Build a system that:
- Collects logs from multiple sources
- Normalizes to common format
- Stores in searchable database
- Correlates events
- Web interface for searching

**Skills:** Log parsing, databases, web frameworks

---

## Expert Projects

### 16. C2 Framework (Educational)
**Difficulty:** Expert | **Time:** 60-100 hours

Build a system that:
- Server for managing agents
- Agent that executes commands
- Encrypted communications
- Multiple transport protocols
- Modular task system

**Note:** For authorized testing and CTF only!

**Skills:** Networking, encryption, protocol design

---

### 17. Fuzzer
**Difficulty:** Expert | **Time:** 40-60 hours

Build a tool that:
- Generates mutated inputs
- Monitors for crashes
- Tracks code coverage
- Minimizes test cases
- Supports multiple targets

**Skills:** Mutation strategies, coverage tracking, process control

---

### 18. EDR Agent
**Difficulty:** Expert | **Time:** 60-80 hours

Build an agent that:
- Monitors process creation
- Tracks file system changes
- Hooks system calls
- Detects suspicious behavior
- Reports to central server

**Skills:** System internals, kernel interaction, real-time monitoring

---

### 19. Threat Intelligence Platform
**Difficulty:** Expert | **Time:** 50-70 hours

Build a system that:
- Aggregates IOCs from multiple sources
- Normalizes and deduplicates
- Provides API for lookups
- Integrates with other tools
- Web interface for management

**Skills:** APIs, databases, data processing

---

### 20. Custom Protocol Implementation
**Difficulty:** Expert | **Time:** 30-50 hours

Implement a network protocol:
- Defined message formats
- State machine
- Error handling
- Security features (encryption, auth)
- Both client and server

**Skills:** Protocol design, state machines, networking

---

## Project Evaluation Criteria

### What Makes a Good Portfolio Project

| Criteria | Description |
|----------|-------------|
| **Solves Real Problem** | Would security professionals actually use this? |
| **Clean Code** | Well-organized, documented, idiomatic Rust |
| **Error Handling** | Robust handling of edge cases |
| **Testing** | Unit and integration tests |
| **Documentation** | README, usage examples, API docs |
| **CLI/UX** | Good user experience, helpful messages |
| **Performance** | Efficient for intended use case |

### Project Structure Best Practices

```
my-security-tool/
├── Cargo.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── tcp.rs
│   │   └── udp.rs
│   └── output/
│       ├── mod.rs
│       ├── json.rs
│       └── text.rs
├── tests/
│   ├── integration_tests.rs
│   └── fixtures/
├── examples/
│   └── basic_usage.rs
└── docs/
    └── USAGE.md
```

---

## Combining Projects

### Security Toolkit

Combine multiple projects into an integrated toolkit:

```
security-toolkit/
├── scan           # Network scanner
├── web-scan       # Web vulnerability scanner
├── hash           # File hasher
├── analyze        # Binary analyzer
├── monitor        # File integrity monitor
└── stk            # Unified CLI entry point
```

### Full Platform

Build a complete security platform:

1. **Collectors** - Agents gathering data
2. **Backend** - API and data processing
3. **Database** - Storing events/IOCs
4. **Frontend** - Web dashboard
5. **Alerting** - Notification system

---

## Getting Started

1. **Choose a project** matching your skill level
2. **Plan first** - Write README before code
3. **Start small** - Get basic functionality working
4. **Iterate** - Add features incrementally
5. **Test** - Write tests as you go
6. **Document** - Keep README updated
7. **Share** - Put on GitHub, get feedback

---

## Remember

- **Security tools require responsibility**
- Only test against systems you own or have permission to test
- Follow responsible disclosure for vulnerabilities
- Consider legal implications in your jurisdiction
- Build to learn, not to cause harm

---

[← Back to Main](./README.md)
