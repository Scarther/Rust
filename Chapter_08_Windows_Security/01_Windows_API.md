# Lesson 01: Windows API Basics in Rust

## Overview

Learn to use the `windows-rs` crate to interact with Windows APIs safely from Rust.

---

## The windows-rs Crate

Microsoft's official Rust bindings for Windows APIs provide:

- Type-safe wrappers
- Automatic handle management
- COM support
- Comprehensive API coverage

### Installation

```toml
[dependencies.windows]
version = "0.52"
features = [
    "Win32_Foundation",
    "Win32_System_Threading",
    "Win32_Security",
]
```

---

## Basic Patterns

### Calling Windows Functions

```rust
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

fn get_current_process_id() -> u32 {
    unsafe { GetCurrentProcessId() }
}

fn get_current_thread_id() -> u32 {
    unsafe { GetCurrentThreadId() }
}
```

### Error Handling

```rust
use windows::core::*;
use windows::Win32::Foundation::*;

fn example_with_error() -> Result<()> {
    unsafe {
        // Functions that can fail return Result
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, 1234)?;

        // Use the handle...

        CloseHandle(handle)?;
    }

    Ok(())
}

// Get detailed error information
fn get_last_error_message() -> String {
    unsafe {
        let error = GetLastError();
        format!("Error code: {:?}", error)
    }
}
```

### Working with Strings

```rust
use windows::core::*;

fn working_with_strings() {
    // Rust &str to Windows PCWSTR
    let rust_str = "Hello, Windows!";
    let wide: Vec<u16> = rust_str.encode_utf16().chain(std::iter::once(0)).collect();
    let pcwstr = PCWSTR::from_raw(wide.as_ptr());

    // Windows string to Rust String
    unsafe {
        let windows_str = PCWSTR::from_raw(wide.as_ptr());
        let rust_string = windows_str.to_string().unwrap_or_default();
    }
}

// Helper macro for string literals
macro_rules! w {
    ($s:literal) => {{
        const WIDE: &[u16] = &{
            let mut arr = [0u16; $s.len() + 1];
            let bytes = $s.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                arr[i] = bytes[i] as u16;
                i += 1;
            }
            arr
        };
        windows::core::PCWSTR::from_raw(WIDE.as_ptr())
    }};
}
```

---

## Common Operations

### Memory Allocation

```rust
use windows::Win32::System::Memory::*;

fn allocate_memory(size: usize) -> *mut std::ffi::c_void {
    unsafe {
        VirtualAlloc(
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    }
}

fn free_memory(ptr: *mut std::ffi::c_void, size: usize) -> bool {
    unsafe {
        VirtualFree(ptr, size, MEM_RELEASE).is_ok()
    }
}
```

### File Operations

```rust
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::Foundation::*;

fn open_file_read(path: &str) -> windows::core::Result<HANDLE> {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide_path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
}
```

### Process Operations

```rust
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

fn open_process(pid: u32) -> windows::core::Result<HANDLE> {
    unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
    }
}

fn terminate_process(handle: HANDLE, exit_code: u32) -> windows::core::Result<()> {
    unsafe {
        TerminateProcess(handle, exit_code)
    }
}
```

---

## Security-Focused Examples

### Check if Running as Admin

```rust
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

pub fn is_admin() -> bool {
    unsafe {
        let mut token = HANDLE::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut size,
        );

        let _ = CloseHandle(token);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}
```

### Enable Privilege

```rust
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;
use windows::core::*;

pub fn enable_privilege(privilege_name: &str) -> Result<bool> {
    unsafe {
        let mut token = HANDLE::default();

        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;

        let wide_name: Vec<u16> = privilege_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid = LUID::default();

        LookupPrivilegeValueW(None, PCWSTR::from_raw(wide_name.as_ptr()), &mut luid)?;

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let result = AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            0,
            None,
            None,
        );

        CloseHandle(token)?;

        // Check if the operation was successful
        Ok(result.is_ok() && GetLastError() == WIN32_ERROR(0))
    }
}
```

### Get Process Integrity Level

```rust
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    High,
    System,
    Unknown,
}

pub fn get_process_integrity() -> IntegrityLevel {
    unsafe {
        let mut token = HANDLE::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return IntegrityLevel::Unknown;
        }

        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut size);

        let mut buffer = vec![0u8; size as usize];

        if GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as *mut _),
            size,
            &mut size,
        ).is_err() {
            let _ = CloseHandle(token);
            return IntegrityLevel::Unknown;
        }

        let _ = CloseHandle(token);

        let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;

        let rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) as u32 - 1);

        match rid {
            x if x < 0x1000 => IntegrityLevel::Untrusted,
            x if x < 0x2000 => IntegrityLevel::Low,
            x if x < 0x3000 => IntegrityLevel::Medium,
            x if x < 0x4000 => IntegrityLevel::High,
            _ => IntegrityLevel::System,
        }
    }
}
```

---

## Best Practices

### Resource Management

```rust
use windows::Win32::Foundation::*;

/// RAII wrapper for Windows HANDLEs
pub struct WinHandle(HANDLE);

impl WinHandle {
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_invalid() || handle.0.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
```

### Error Conversion

```rust
use windows::core::Error as WinError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Windows API error: {0}")]
    WinApi(#[from] WinError),

    #[error("Access denied")]
    AccessDenied,

    #[error("Process not found: {0}")]
    ProcessNotFound(u32),

    #[error("Privilege not held: {0}")]
    PrivilegeNotHeld(String),
}
```

---

## Exercises

1. Write a function to enumerate all window handles on the desktop
2. Create a tool that lists all DLLs loaded by a process
3. Implement a function to read a process's environment variables
4. Build a utility to check file digital signatures

---

## Next Steps

- [Lesson 02: Registry Operations](./02_Registry.md)
- [Lesson 03: Process Enumeration](./03_Process_Enum.md)

---

[← Back to Chapter](./README.md) | [Next Lesson →](./02_Registry.md)
