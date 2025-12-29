//! # Filesystem Isolation
//!
//! This module provides filesystem isolation utilities:
//! - Bind mounts for selective access
//! - Tmpfs for scratch space
//! - Readonly remounts
//! - Minimal root filesystem setup

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use nix::mount::{mount, umount2, MntFlags, MsFlags};

use crate::error::{SandboxError, SandboxResult};

/// Filesystem isolation configuration
#[derive(Debug, Clone)]
pub struct FilesystemConfig {
    /// New root directory (for chroot/pivot_root)
    pub root: Option<PathBuf>,
    /// Bind mounts to apply
    pub mounts: Vec<MountSpec>,
    /// Mount proc filesystem
    pub mount_proc: bool,
    /// Mount tmpfs at /tmp
    pub mount_tmp: bool,
    /// Mount devtmpfs at /dev
    pub mount_dev: bool,
    /// Make root filesystem readonly
    pub readonly_root: bool,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            root: None,
            mounts: Vec::new(),
            mount_proc: true,
            mount_tmp: true,
            mount_dev: true,
            readonly_root: false,
        }
    }
}

/// Mount specification
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// Source path (for bind mounts) or filesystem type
    pub source: String,
    /// Target path inside sandbox
    pub target: PathBuf,
    /// Mount type
    pub mount_type: MountType,
    /// Mount flags
    pub flags: MountFlags,
}

/// Types of mounts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountType {
    /// Bind mount from host
    Bind,
    /// tmpfs (memory filesystem)
    Tmpfs,
    /// proc filesystem
    Proc,
    /// sysfs filesystem
    Sysfs,
    /// devtmpfs for /dev
    Devtmpfs,
    /// devpts for /dev/pts
    Devpts,
}

impl MountType {
    /// Get the filesystem type string for mount()
    pub fn fstype(&self) -> Option<&'static str> {
        match self {
            MountType::Bind => None,
            MountType::Tmpfs => Some("tmpfs"),
            MountType::Proc => Some("proc"),
            MountType::Sysfs => Some("sysfs"),
            MountType::Devtmpfs => Some("devtmpfs"),
            MountType::Devpts => Some("devpts"),
        }
    }
}

/// Mount flags
#[derive(Debug, Clone, Copy, Default)]
pub struct MountFlags {
    /// Mount as readonly
    pub readonly: bool,
    /// Don't allow setuid
    pub nosuid: bool,
    /// Don't interpret device special files
    pub nodev: bool,
    /// Don't allow execution
    pub noexec: bool,
    /// Make mount recursive
    pub recursive: bool,
}

impl MountFlags {
    /// Create flags for a readonly bind mount
    pub fn readonly_bind() -> Self {
        Self {
            readonly: true,
            nosuid: true,
            nodev: true,
            noexec: false,
            recursive: true,
        }
    }

    /// Create flags for a secure tmpfs
    pub fn secure_tmpfs() -> Self {
        Self {
            readonly: false,
            nosuid: true,
            nodev: true,
            noexec: true,
            recursive: false,
        }
    }

    /// Convert to nix MsFlags
    pub fn to_ms_flags(&self) -> MsFlags {
        let mut flags = MsFlags::empty();

        if self.readonly {
            flags |= MsFlags::MS_RDONLY;
        }
        if self.nosuid {
            flags |= MsFlags::MS_NOSUID;
        }
        if self.nodev {
            flags |= MsFlags::MS_NODEV;
        }
        if self.noexec {
            flags |= MsFlags::MS_NOEXEC;
        }
        if self.recursive {
            flags |= MsFlags::MS_REC;
        }

        flags
    }
}

/// Apply a single mount
pub fn apply_mount(spec: &MountSpec) -> SandboxResult<()> {
    // Create target directory if needed
    if !spec.target.exists() {
        if spec.mount_type == MountType::Bind {
            // For bind mounts, create file or directory based on source
            let source = Path::new(&spec.source);
            if source.is_dir() {
                fs::create_dir_all(&spec.target)?;
            } else {
                if let Some(parent) = spec.target.parent() {
                    fs::create_dir_all(parent)?;
                }
                File::create(&spec.target)?;
            }
        } else {
            fs::create_dir_all(&spec.target)?;
        }
    }

    let flags = spec.flags.to_ms_flags();

    match spec.mount_type {
        MountType::Bind => {
            // First do the bind
            mount(
                Some(spec.source.as_str()),
                &spec.target,
                None::<&str>,
                MsFlags::MS_BIND | flags,
                None::<&str>,
            ).map_err(|e| SandboxError::Mount(format!(
                "Bind mount {} -> {:?}: {}",
                spec.source, spec.target, e
            )))?;

            // Then remount with additional flags if needed
            if spec.flags.readonly {
                mount(
                    None::<&str>,
                    &spec.target,
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | flags,
                    None::<&str>,
                ).map_err(|e| SandboxError::Mount(format!(
                    "Remount readonly {:?}: {}",
                    spec.target, e
                )))?;
            }
        }
        _ => {
            let fstype = spec.mount_type.fstype();
            mount(
                Some("none"),
                &spec.target,
                fstype,
                flags,
                None::<&str>,
            ).map_err(|e| SandboxError::Mount(format!(
                "Mount {:?} at {:?}: {}",
                spec.mount_type, spec.target, e
            )))?;
        }
    }

    Ok(())
}

/// Create a minimal root filesystem for sandboxing
pub fn create_minimal_rootfs(base: &Path) -> SandboxResult<()> {
    // Create essential directories
    let dirs = [
        "bin", "dev", "etc", "lib", "lib64", "proc", "sys",
        "tmp", "usr", "usr/bin", "usr/lib", "usr/lib64", "var",
    ];

    for dir in dirs {
        fs::create_dir_all(base.join(dir))?;
    }

    // Create essential device nodes (if we have permission)
    create_dev_nodes(base)?;

    // Copy essential files
    copy_essential_files(base)?;

    Ok(())
}

/// Create minimal device nodes
fn create_dev_nodes(base: &Path) -> SandboxResult<()> {
    let dev = base.join("dev");

    // Create /dev/null, /dev/zero, /dev/urandom as files
    // (Actual device nodes require CAP_MKNOD)
    for name in ["null", "zero", "urandom", "random"] {
        File::create(dev.join(name))?;
    }

    // Create /dev/pts and /dev/shm directories
    fs::create_dir_all(dev.join("pts"))?;
    fs::create_dir_all(dev.join("shm"))?;

    Ok(())
}

/// Copy essential files to the new root
fn copy_essential_files(base: &Path) -> SandboxResult<()> {
    // Copy resolv.conf if it exists
    if Path::new("/etc/resolv.conf").exists() {
        let _ = fs::copy("/etc/resolv.conf", base.join("etc/resolv.conf"));
    }

    // Copy nsswitch.conf
    if Path::new("/etc/nsswitch.conf").exists() {
        let _ = fs::copy("/etc/nsswitch.conf", base.join("etc/nsswitch.conf"));
    }

    // Copy hosts
    if Path::new("/etc/hosts").exists() {
        let _ = fs::copy("/etc/hosts", base.join("etc/hosts"));
    }

    // Create minimal passwd and group
    fs::write(base.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n")?;
    fs::write(base.join("etc/group"), "root:x:0:\nnogroup:x:65534:\n")?;

    Ok(())
}

/// Mount proc filesystem
pub fn mount_proc(target: &Path) -> SandboxResult<()> {
    mount(
        Some("proc"),
        target,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ).map_err(|e| SandboxError::Mount(format!(
        "Mount proc at {:?}: {}",
        target, e
    )))?;

    Ok(())
}

/// Mount tmpfs
pub fn mount_tmpfs(target: &Path, size_mb: usize) -> SandboxResult<()> {
    let options = format!("size={}m,mode=1777", size_mb);

    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(options.as_str()),
    ).map_err(|e| SandboxError::Mount(format!(
        "Mount tmpfs at {:?}: {}",
        target, e
    )))?;

    Ok(())
}

/// Make a mount point readonly
pub fn remount_readonly(target: &Path) -> SandboxResult<()> {
    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    ).map_err(|e| SandboxError::Mount(format!(
        "Remount readonly {:?}: {}",
        target, e
    )))?;

    Ok(())
}

/// Unmount a path
pub fn unmount(target: &Path, force: bool) -> SandboxResult<()> {
    let flags = if force {
        MntFlags::MNT_DETACH
    } else {
        MntFlags::empty()
    };

    umount2(target, flags).map_err(|e| SandboxError::Mount(format!(
        "Unmount {:?}: {}",
        target, e
    )))?;

    Ok(())
}

/// Check if a path is a mount point
pub fn is_mount_point(path: &Path) -> bool {
    // Check /proc/mounts
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        let path_str = path.to_string_lossy();
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == path_str {
                return true;
            }
        }
    }
    false
}

/// Get list of mount points
pub fn get_mounts() -> SandboxResult<Vec<MountInfo>> {
    let content = fs::read_to_string("/proc/mounts")?;
    let mut mounts = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            mounts.push(MountInfo {
                source: parts[0].to_string(),
                target: PathBuf::from(parts[1]),
                fstype: parts[2].to_string(),
                options: parts[3].to_string(),
            });
        }
    }

    Ok(mounts)
}

/// Mount information
#[derive(Debug, Clone)]
pub struct MountInfo {
    pub source: String,
    pub target: PathBuf,
    pub fstype: String,
    pub options: String,
}

impl std::fmt::Display for MountInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} on {:?} type {} ({})",
            self.source, self.target, self.fstype, self.options)
    }
}

/// Overlay filesystem mount
pub fn mount_overlay(
    lower: &Path,
    upper: &Path,
    work: &Path,
    merged: &Path,
) -> SandboxResult<()> {
    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );

    // Create directories if needed
    fs::create_dir_all(upper)?;
    fs::create_dir_all(work)?;
    fs::create_dir_all(merged)?;

    mount(
        Some("overlay"),
        merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    ).map_err(|e| SandboxError::Mount(format!(
        "Mount overlay at {:?}: {}",
        merged, e
    )))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_flags() {
        let flags = MountFlags::readonly_bind();
        assert!(flags.readonly);
        assert!(flags.nosuid);
        assert!(flags.nodev);
        assert!(flags.recursive);

        let ms_flags = flags.to_ms_flags();
        assert!(ms_flags.contains(MsFlags::MS_RDONLY));
    }

    #[test]
    fn test_get_mounts() {
        let mounts = get_mounts();
        assert!(mounts.is_ok());

        let mounts = mounts.unwrap();
        assert!(!mounts.is_empty());

        // Root should be mounted
        assert!(mounts.iter().any(|m| m.target == PathBuf::from("/")));
    }

    #[test]
    fn test_is_mount_point() {
        // Root is always a mount point
        assert!(is_mount_point(Path::new("/")));
    }
}
