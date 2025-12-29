# Chapter 08: Windows Security Tools in Rust

## Overview

This chapter covers building security tools specifically for Windows using Rust. Learn to interact with Windows APIs, parse Windows-specific formats, and create cross-platform tools with Windows support.

---

## Chapter Contents

| Lesson | Topic | Description |
|--------|-------|-------------|
| [01_Windows_API](./01_Windows_API.md) | Windows API Basics | Using windows-rs crate |
| [02_Registry](./02_Registry.md) | Registry Operations | Read/write registry keys |
| [03_Process_Enum](./03_Process_Enum.md) | Process Enumeration | List and analyze processes |
| [04_Service_Control](./04_Service_Control.md) | Service Management | Interact with Windows services |
| [05_Event_Logs](./05_Event_Logs.md) | Event Log Analysis | Parse and monitor event logs |
| [06_PE_Analysis](./06_PE_Analysis.md) | PE File Analysis | Parse Windows executables |
| [07_WMI](./07_WMI.md) | WMI Queries | System information via WMI |
| [08_Persistence](./08_Persistence.md) | Persistence Detection | Find persistence mechanisms |

---

## Prerequisites

- Rust toolchain with Windows target
- Windows SDK (for development)
- Administrator privileges (for some operations)

---

## Key Crates for Windows Development

| Crate | Purpose | Notes |
|-------|---------|-------|
| `windows` | Official Windows API bindings | Most comprehensive |
| `winreg` | Registry access | Simple registry operations |
| `wmi` | WMI queries | COM-based system queries |
| `goblin` | PE parsing | Cross-platform binary analysis |
| `pelite` | PE parsing | Windows-specific, more detailed |
| `ntapi` | NT API functions | Low-level system access |

---

## Setup

### Cargo.toml

```toml
[package]
name = "windows_security_tool"
version = "0.1.0"
edition = "2021"

[dependencies]
# Windows API bindings
windows = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_System_Registry",
    "Win32_System_ProcessStatus",
    "Win32_System_Threading",
    "Win32_System_Services",
    "Win32_Security",
    "Win32_System_Diagnostics_ToolHelp",
]}

# Registry
winreg = "0.52"

# WMI
wmi = "0.13"

# PE parsing
pelite = "0.10"
goblin = "0.8"

# Error handling
anyhow = "1.0"
thiserror = "1.0"

# CLI
clap = { version = "4.4", features = ["derive"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[target.'cfg(windows)'.dependencies]
windows-sys = "0.52"
```

### Cross-Compilation from Linux

```bash
# Install Windows target
rustup target add x86_64-pc-windows-gnu

# Install MinGW
sudo apt install mingw-w64

# Build for Windows
cargo build --release --target x86_64-pc-windows-gnu
```

---

## Quick Examples

### Process Enumeration

```rust
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::Foundation::*;

fn list_processes() -> anyhow::Result<Vec<(u32, String)>> {
    let mut processes = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)]
                );
                processes.push((entry.th32ProcessID, name));

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        CloseHandle(snapshot)?;
    }

    Ok(processes)
}
```

### Registry Access

```rust
use winreg::enums::*;
use winreg::RegKey;

fn check_run_keys() -> anyhow::Result<Vec<(String, String)>> {
    let mut entries = Vec::new();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let run_key = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;

    for (name, value) in run_key.enum_values().filter_map(|x| x.ok()) {
        let value_str: String = value.to_string();
        entries.push((name, value_str));
    }

    Ok(entries)
}
```

### Service Enumeration

```rust
use windows::Win32::System::Services::*;
use windows::Win32::Foundation::*;
use windows::core::*;

fn list_services() -> anyhow::Result<Vec<String>> {
    let mut services = Vec::new();

    unsafe {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)?;

        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;

        // First call to get buffer size
        let _ = EnumServicesStatusW(
            manager,
            SERVICE_TYPE(SERVICE_WIN32.0),
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
        );

        let mut buffer = vec![0u8; bytes_needed as usize];

        EnumServicesStatusW(
            manager,
            SERVICE_TYPE(SERVICE_WIN32.0),
            SERVICE_STATE_ALL,
            Some(&mut buffer),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
        )?;

        let service_entries = std::slice::from_raw_parts(
            buffer.as_ptr() as *const ENUM_SERVICE_STATUSW,
            services_returned as usize,
        );

        for entry in service_entries {
            let name = entry.lpServiceName.to_string()?;
            services.push(name);
        }

        CloseServiceHandle(manager)?;
    }

    Ok(services)
}
```

---

## Security Tool Patterns

### Privilege Check

```rust
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;

fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ).is_ok() {
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

            if GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                size,
                &mut size,
            ).is_ok() {
                return elevation.TokenIsElevated != 0;
            }
        }
    }
    false
}
```

### Safe Handle Wrapper

```rust
use windows::Win32::Foundation::*;
use std::ops::Deref;

pub struct SafeHandle(HANDLE);

impl SafeHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}

impl Deref for SafeHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
```

---

## MITRE ATT&CK Relevance

| Technique | Detection Method |
|-----------|------------------|
| T1547.001 Registry Run Keys | Monitor Run/RunOnce keys |
| T1053.005 Scheduled Task | Enumerate scheduled tasks |
| T1543.003 Windows Service | Monitor service creation |
| T1055 Process Injection | Memory analysis |
| T1003 OS Credential Dumping | Monitor LSASS access |

---

## Further Reading

- [Official windows-rs Documentation](https://microsoft.github.io/windows-docs-rs/)
- [Windows Internals Book](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Rust Windows Programming](https://kennykerr.ca/rust-getting-started/)

---

[← Back to Main](../README.md) | [Next: Lesson 01 →](./01_Windows_API.md)
