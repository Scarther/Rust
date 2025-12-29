# The Rust Security Bible
### Created by Cipher - AI

The complete guide to learning Rust through security-focused projects. From absolute beginner to production-ready security tools.

```
██████╗ ██╗   ██╗███████╗████████╗    ██████╗ ██╗██████╗ ██╗     ███████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝    ██╔══██╗██║██╔══██╗██║     ██╔════╝
██████╔╝██║   ██║███████╗   ██║       ██████╔╝██║██████╔╝██║     █████╗
██╔══██╗██║   ██║╚════██║   ██║       ██╔══██╗██║██╔══██╗██║     ██╔══╝
██║  ██║╚██████╔╝███████║   ██║       ██████╔╝██║██████╔╝███████╗███████╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝
```

---

## New Here? Start Here!

| Your Background | Start With |
|-----------------|------------|
| Complete beginner | [GETTING_STARTED.md](./GETTING_STARTED.md) |
| Know another language | [Chapter 01 Fundamentals](./Chapter_01_Fundamentals/) |
| Experienced dev | [Quick Reference](./Quick_Reference/) |
| Security professional | [Lab Environment](./Lab_Environment/) |

---

## Overview

| Feature | Description |
|---------|-------------|
| **Focus** | Security, Automation, Red Team, Blue Team |
| **Projects** | 50+ hands-on exercises |
| **Skill Levels** | Basic → Intermediate → Advanced → Expert |
| **Lab Environment** | Docker-based practice targets |
| **CTF Challenges** | Capture-the-flag exercises |
| **Case Studies** | Real-world scenarios |

## Quick Start

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and run first project
git clone https://github.com/yourusername/rust-bible.git
cd rust-bible/Chapter_02_Skill_Levels/01_Basic/B01_Hello_Security
cargo run
```

## Contents

| Chapter | Description | Projects |
|---------|-------------|----------|
| [1. Fundamentals](Chapter_01_Fundamentals/) | Core Rust concepts | Ownership, structs, enums |
| [2. Skill Levels](Chapter_02_Skill_Levels/) | Progressive learning | B01-B15, I01-I15, A01-A10, E01-E05 |
| [3. Red Team](Chapter_03_Red_Team/) | Offensive security | Recon, exploitation, persistence |
| [4. Blue Team](Chapter_04_Blue_Team/) | Defensive security | Detection, forensics, hardening |
| [5. Automation](Chapter_05_Automation/) | System automation | Services, backups, monitoring |
| [6. Technical](Chapter_06_Technical_Addendum/) | References | Crates, cross-compilation |
| [7. GUI Development](Chapter_07_GUI_Development/) | Visual interfaces | egui, security dashboards |
| [8. Malware Analysis](Chapter_08_Malware_Analysis/) | Threat analysis | PE/ELF parsing, signatures |
| [9. IDS Development](Chapter_09_IDS_Development/) | Intrusion detection | Packet capture, rule engine |
| [10. Real World Scenarios](Chapter_10_Real_World_Scenarios/) | Practical exercises | Basic to Expert challenges |

## Featured Projects

### Basic Level
- **B01**: Hello Security World - Project structure and output
- **B02**: CLI Arguments - Command-line parsing with clap
- **B09**: Hash Calculator - MD5/SHA file hashing

### Intermediate Level
- **I01**: Port Scanner - Multi-threaded TCP scanning
- **I05**: File Integrity Monitor - Detect file changes

### GUI Projects
- **G11**: Google Dorking Interface - Template query builder
- **G12**: Multi-Tool Launcher - Manage multiple security tools

## Learning Path

```
Basic (B01-B15)
    ↓
Intermediate (I01-I15)
    ↓
Choose Path:
├── Red Team (Chapter 3)
├── Blue Team (Chapter 4)
├── Automation (Chapter 5)
└── GUI Development (Chapter 7)
    ↓
Advanced/Expert
```

## Project Structure

Each project includes:
- `README.md` - Detailed documentation with Red/Blue team perspectives
- `Cargo.toml` - Dependencies
- `src/main.rs` - Implementation with tests

## Requirements

- Rust 1.70+ (install via [rustup](https://rustup.rs))
- Basic command line familiarity
- Text editor or IDE (VS Code recommended)

---

## Additional Resources

| Resource | Description |
|----------|-------------|
| [GETTING_STARTED.md](./GETTING_STARTED.md) | Complete setup and first steps guide |
| [LEARNING_PATHS.md](./LEARNING_PATHS.md) | Structured learning roadmaps |
| [Quick_Reference/](./Quick_Reference/) | Cheat sheets and quick lookups |
| [Cookbook/](./Cookbook/) | Copy-paste recipes for common tasks |
| [Lab_Environment/](./Lab_Environment/) | Docker-based practice environment |
| [Assessments/](./Assessments/) | Quizzes to test your knowledge |
| [CTF_Challenges/](./CTF_Challenges/) | Capture-the-flag exercises |
| [Case_Studies/](./Case_Studies/) | Real-world security scenarios |
| [Projects/](./Projects/) | Complete tool implementations |
| [Templates/](./Templates/) | Ready-to-use project templates |
| [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) | Common problems and solutions |
| [GLOSSARY.md](./GLOSSARY.md) | Security and Rust terminology |
| [INDEX.md](./INDEX.md) | Complete content index |
| [PROJECT_IDEAS.md](./PROJECT_IDEAS.md) | 20+ portfolio project suggestions |
| [RESOURCES.md](./RESOURCES.md) | Curated external learning resources |

### Quick Reference Guides

| Guide | Description |
|-------|-------------|
| [Rust Security Cheatsheet](./Quick_Reference/Rust_Security_Cheatsheet.md) | Common patterns and syntax |
| [Async/Tokio Cheatsheet](./Quick_Reference/Async_Tokio_Cheatsheet.md) | Async programming patterns |
| [Common Crates](./Quick_Reference/Common_Crates.md) | Essential crates with examples |
| [Cross-Compilation](./Quick_Reference/Cross_Compilation.md) | Build for multiple platforms |

---

## Lab Environment Quick Start

```bash
cd Lab_Environment
docker-compose up -d

# Access development container
ssh root@localhost -p 2222
# Password: rustlab

# Lab targets available at:
# - 172.30.0.20 - Linux target
# - 172.30.0.30 - Vulnerable web app
# - 172.30.0.40 - Multiple services
```

---

## Legal Notice

This material is for **authorized security testing** and **educational purposes** only. Always obtain proper written authorization before testing systems you don't own.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first.

---

## Support

- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues and fixes
- [Rust Users Forum](https://users.rust-lang.org/) - Community help
- [r/rust](https://reddit.com/r/rust) - Reddit community

---

Made with Rust by security professionals, for security professionals.


