# Chapter 3: Red Team Rust

## Overview

Offensive security tools and techniques implemented in Rust. All tools are for **authorized security testing and educational purposes only**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RED TEAM ATTACK LIFECYCLE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │              │   │              │   │              │   │              │ │
│  │    RECON     │──►│  WEAPONIZE   │──►│   DELIVER    │──►│   EXPLOIT    │ │
│  │              │   │              │   │              │   │              │ │
│  └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘ │
│         │                                                         │         │
│         │                                                         ▼         │
│         │           ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│         │           │              │   │              │   │              │ │
│         └──────────►│    EVADE     │◄──│   PERSIST    │◄──│   INSTALL    │ │
│                     │              │   │              │   │              │ │
│                     └──────────────┘   └──────────────┘   └──────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Sections

| Section | Focus | Projects |
|---------|-------|----------|
| [01_Reconnaissance](01_Reconnaissance/) | Information gathering | Subdomain enum, web scanner, OSINT |
| [02_Exploitation](02_Exploitation/) | Vulnerability exploitation | Exploit frameworks, buffer overflow |
| [03_Post_Exploitation](03_Post_Exploitation/) | System control | Enumeration, credential harvesting |
| [04_Persistence](04_Persistence/) | Maintaining access | Scheduled tasks, registry, services |
| [05_Evasion](05_Evasion/) | Avoiding detection | AMSI bypass, EDR evasion, obfuscation |

## MITRE ATT&CK Mapping

| Technique ID | Name | Our Projects |
|-------------|------|--------------|
| T1595 | Active Scanning | Port Scanner, Web Scanner |
| T1592 | Gather Victim Host Info | System Enumeration |
| T1589 | Gather Victim Identity | OSINT Collector |
| T1046 | Network Service Scanning | Port Scanner, Service Detection |
| T1059 | Command & Scripting | Various automation tools |
| T1053 | Scheduled Task/Job | Persistence mechanisms |
| T1547 | Boot/Logon Autostart | Persistence mechanisms |
| T1562 | Impair Defenses | AMSI Bypass, ETW Patching |

## Legal Notice

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                           AUTHORIZATION REQUIRED                           ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  These tools are intended for:                                            ║
║  • Authorized penetration testing                                         ║
║  • Security research in controlled environments                           ║
║  • Educational purposes                                                   ║
║  • Capture The Flag (CTF) competitions                                    ║
║                                                                           ║
║  NEVER use against systems without explicit written permission.           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```
