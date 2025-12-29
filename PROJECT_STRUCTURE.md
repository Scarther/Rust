# Rust Security Bible - Project Structure

## Repository Layout

```
Rust_Bible/
├── Rust_Bible.md                    # Main documentation (2000+ lines)
├── PROJECT_STRUCTURE.md             # This file
├── README.md                        # Project overview
│
├── Chapter_01_Fundamentals/         # Core Rust concepts
│   └── README.md
│
├── Chapter_02_Skill_Levels/         # Progressive learning
│   ├── 01_Basic/                    # B01-B15 projects
│   │   ├── README.md
│   │   ├── B01_Hello_Security/
│   │   │   ├── README.md            # Detailed explanation
│   │   │   ├── Cargo.toml           # Dependencies
│   │   │   └── src/main.rs          # Implementation
│   │   ├── B02_CLI_Args/
│   │   ├── B09_Hash_Calculator/
│   │   └── ...
│   │
│   ├── 02_Intermediate/             # I01-I15 projects
│   │   ├── README.md
│   │   ├── I01_Port_Scanner/
│   │   │   ├── README.md
│   │   │   ├── Cargo.toml
│   │   │   └── src/main.rs
│   │   └── ...
│   │
│   ├── 03_Advanced/                 # A01-A10 projects
│   │   └── README.md
│   │
│   └── 04_Expert/                   # E01-E05 projects
│       └── README.md
│
├── Chapter_03_Red_Team/             # Offensive security
│   ├── README.md                    # MITRE ATT&CK mapping
│   ├── 01_Reconnaissance/
│   │   └── README.md                # Subdomain enum, web scanning
│   ├── 02_Exploitation/
│   ├── 03_Post_Exploitation/
│   ├── 04_Persistence/
│   └── 05_Evasion/
│
├── Chapter_04_Blue_Team/            # Defensive security
│   ├── README.md
│   ├── 01_Detection/
│   │   └── README.md                # IOC scanner, log analysis
│   ├── 02_Forensics/
│   ├── 03_Hardening/
│   └── 04_Incident_Response/
│
├── Chapter_05_Automation/           # System automation
│   ├── README.md
│   ├── 01_System_Admin/
│   ├── 02_Network/
│   ├── 03_File_Processing/
│   └── 04_DevOps/
│
├── Chapter_06_Technical_Addendum/   # References
│   └── README.md
│
├── Chapter_07_GUI_Development/      # GUI interfaces
│   ├── README.md                    # GUI framework comparison
│   ├── 01_Basics/                   # G01-G05 projects
│   ├── 02_Security_Tools/           # G06-G10 projects
│   └── 03_Automation_Interfaces/    # G11-G15 projects
│       ├── G11_Google_Dorking/
│       └── G12_Multi_Tool_Launcher/
│
├── Chapter_08_Malware_Analysis/     # Malware analysis tools
│   ├── README.md
│   ├── 01_Static_Analysis/          # PE/ELF parsing, strings
│   ├── 02_Dynamic_Analysis/         # Sandbox, syscall tracing
│   ├── 03_Behavioral_Analysis/      # API monitoring
│   └── 04_Signature_Detection/      # YARA, hash matching
│
├── Chapter_09_IDS_Development/      # Intrusion detection
│   ├── README.md
│   ├── 01_Packet_Capture/           # libpcap, BPF
│   ├── 02_Rule_Engine/              # Detection rules
│   ├── 03_IP_Reputation/            # Threat intel, iptables
│   └── 04_Alert_System/             # Notifications
│
├── Chapter_10_Real_World_Scenarios/ # Practical exercises
│   ├── README.md
│   ├── 01_Basic/                    # SOC Analyst tasks
│   ├── 02_Intermediate/             # Security Engineer tools
│   ├── 03_Advanced/                 # Threat Hunter workflows
│   └── 04_Expert/                   # Security Researcher tools
│
└── Projects/                        # Standalone projects
    ├── Basic/
    ├── Intermediate/
    ├── Advanced/
    └── Expert/
```

## Project Naming Convention

- **B##**: Basic level (B01-B15)
- **I##**: Intermediate level (I01-I15)
- **A##**: Advanced level (A01-A10)
- **E##**: Expert level (E01-E05)
- **G##**: GUI projects (G01-G15)
- **RT##**: Red Team tools
- **BT##**: Blue Team tools

## Each Project Contains

```
Project_Name/
├── README.md        # Detailed documentation
│   ├── Overview table (ID, difficulty, time, prerequisites)
│   ├── What You'll Learn
│   ├── The Code (with syntax highlighting)
│   ├── Line-by-Line Breakdown
│   ├── Red Team Perspective
│   ├── Blue Team Perspective
│   ├── Exercises
│   └── Next/Previous links
│
├── Cargo.toml       # Dependencies and metadata
│   ├── [package] section
│   └── [dependencies] section
│
└── src/
    └── main.rs      # Implementation
        ├── Documentation comments
        ├── Main implementation
        └── Unit tests
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/rust-bible.git
cd rust-bible

# Start with Basic level
cd Chapter_02_Skill_Levels/01_Basic/B01_Hello_Security
cargo run

# Build all projects
for dir in Chapter_02_Skill_Levels/01_Basic/*/; do
    (cd "$dir" && cargo build)
done
```

## Learning Path

```
1. Read Rust_Bible.md (Quick Start + Fundamentals)
       ↓
2. Complete Basic projects (B01 → B15)
       ↓
3. Complete Intermediate projects (I01 → I15)
       ↓
4. Choose specialization:
   ├── Red Team → Chapter 3
   ├── Blue Team → Chapter 4
   └── Automation → Chapter 5
       ↓
5. Add GUI skills → Chapter 7
       ↓
6. Advanced/Expert projects
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add new project following naming convention
4. Include comprehensive README
5. Add tests
6. Submit pull request

## License

MIT License - See LICENSE file
