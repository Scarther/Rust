//! # BT05 - Security Configuration Auditor
//!
//! A comprehensive security configuration auditing tool for system hardening.
//!
//! ## Blue Team Concepts
//!
//! **Security Hardening** is the process of securing systems by reducing their
//! attack surface and eliminating potential security vulnerabilities. Key areas:
//!
//! - **Access Control**: User permissions, sudo configuration, SSH settings
//! - **Network Security**: Firewall rules, open ports, network services
//! - **File System**: Permissions, SUID/SGID binaries, world-writable files
//! - **Service Configuration**: Unnecessary services, secure configurations
//! - **Logging & Auditing**: Audit policies, log retention, monitoring
//!
//! ## Compliance Frameworks
//!
//! This tool can be used to verify compliance with:
//! - CIS Benchmarks (Center for Internet Security)
//! - NIST Security Guidelines
//! - PCI-DSS Requirements
//! - HIPAA Security Rules
//! - SOC 2 Controls
//!
//! ## Audit Categories
//!
//! 1. **Account Security**: Password policies, inactive accounts, root access
//! 2. **File Permissions**: Critical file permissions, SUID/SGID audit
//! 3. **Network Configuration**: Firewall, open ports, unnecessary services
//! 4. **SSH Hardening**: Key-based auth, protocol version, allowed users
//! 5. **Logging Configuration**: Audit logs, log rotation, rsyslog
//! 6. **Kernel Parameters**: sysctl security settings, kernel hardening
//!
//! ## Usage Examples
//!
//! ```bash
//! # Run full security audit
//! config-auditor --output report.html
//!
//! # Run specific checks
//! config-auditor --category ssh --category network --output ssh_report.json
//!
//! # Generate compliance report
//! config-auditor --compliance cis --output cis_report.html
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use colored::*;
use maud::{html, DOCTYPE, Markup};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

// ============================================================================
// CLI ARGUMENT DEFINITIONS
// ============================================================================

/// Config Auditor - Security configuration auditing tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output file for audit report
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Audit categories to check
    #[arg(short, long)]
    category: Vec<AuditCategory>,

    /// Compliance framework to check against
    #[arg(long, value_enum)]
    compliance: Option<ComplianceFramework>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Show only failed checks
    #[arg(long)]
    failures_only: bool,

    /// Custom audit rules file
    #[arg(long)]
    rules: Option<PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Html,
    Csv,
}

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum AuditCategory {
    Accounts,
    FilePermissions,
    Network,
    Ssh,
    Logging,
    Kernel,
    Services,
    All,
}

impl std::fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditCategory::Accounts => write!(f, "Account Security"),
            AuditCategory::FilePermissions => write!(f, "File Permissions"),
            AuditCategory::Network => write!(f, "Network Security"),
            AuditCategory::Ssh => write!(f, "SSH Hardening"),
            AuditCategory::Logging => write!(f, "Logging & Auditing"),
            AuditCategory::Kernel => write!(f, "Kernel Parameters"),
            AuditCategory::Services => write!(f, "Service Configuration"),
            AuditCategory::All => write!(f, "All Categories"),
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum ComplianceFramework {
    Cis,
    Nist,
    Pci,
    Custom,
}

// ============================================================================
// AUDIT CHECK STRUCTURES
// ============================================================================

/// Definition of a security audit check
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditCheck {
    /// Unique identifier
    id: String,
    /// Human-readable title
    title: String,
    /// Detailed description
    description: String,
    /// Category
    category: AuditCategory,
    /// Severity (1-10)
    severity: u8,
    /// CIS Benchmark reference
    cis_ref: Option<String>,
    /// Remediation steps
    remediation: String,
    /// Check type
    check_type: CheckType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CheckType {
    /// Check if file exists
    FileExists { path: String },
    /// Check file permissions
    FilePermissions { path: String, expected: u32 },
    /// Check file contains pattern
    FileContains { path: String, pattern: String, should_match: bool },
    /// Check command output
    CommandOutput { command: String, args: Vec<String>, pattern: String, should_match: bool },
    /// Check sysctl value
    Sysctl { key: String, expected: String },
    /// Check service status
    ServiceStatus { service: String, expected_status: String },
    /// Custom check function
    Custom { check_name: String },
}

/// Result of an audit check
#[derive(Debug, Serialize, Deserialize)]
struct AuditResult {
    /// Check that was performed
    check_id: String,
    check_title: String,
    /// Whether the check passed
    passed: bool,
    /// Status message
    status: CheckStatus,
    /// Actual value found
    actual_value: Option<String>,
    /// Expected value
    expected_value: Option<String>,
    /// Severity
    severity: u8,
    /// Category
    category: AuditCategory,
    /// Remediation
    remediation: String,
    /// CIS reference
    cis_ref: Option<String>,
    /// Timestamp
    checked_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum CheckStatus {
    Pass,
    Fail,
    Warning,
    NotApplicable,
    Error(String),
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Fail => write!(f, "FAIL"),
            CheckStatus::Warning => write!(f, "WARN"),
            CheckStatus::NotApplicable => write!(f, "N/A"),
            CheckStatus::Error(e) => write!(f, "ERROR: {}", e),
        }
    }
}

/// Complete audit report
#[derive(Debug, Serialize, Deserialize)]
struct AuditReport {
    /// Report metadata
    report_info: ReportInfo,
    /// System information
    system_info: SystemInfo,
    /// All audit results
    results: Vec<AuditResult>,
    /// Summary statistics
    summary: AuditSummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReportInfo {
    generated_at: DateTime<Utc>,
    tool_version: String,
    categories_audited: Vec<AuditCategory>,
    compliance_framework: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemInfo {
    hostname: String,
    os: String,
    os_version: String,
    kernel: Option<String>,
    architecture: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AuditSummary {
    total_checks: usize,
    passed: usize,
    failed: usize,
    warnings: usize,
    not_applicable: usize,
    errors: usize,
    compliance_score: f64,
    results_by_category: HashMap<String, CategorySummary>,
    critical_failures: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct CategorySummary {
    total: usize,
    passed: usize,
    failed: usize,
}

// ============================================================================
// AUDIT CHECK DEFINITIONS
// ============================================================================

impl AuditCheck {
    /// Get all default security audit checks
    fn default_checks() -> Vec<Self> {
        let mut checks = Vec::new();

        // Account Security Checks
        checks.extend(Self::account_checks());

        // File Permission Checks
        checks.extend(Self::file_permission_checks());

        // Network Security Checks
        checks.extend(Self::network_checks());

        // SSH Hardening Checks
        checks.extend(Self::ssh_checks());

        // Logging Checks
        checks.extend(Self::logging_checks());

        // Kernel Parameter Checks
        checks.extend(Self::kernel_checks());

        // Service Checks
        checks.extend(Self::service_checks());

        checks
    }

    fn account_checks() -> Vec<Self> {
        vec![
            AuditCheck {
                id: "ACC-001".to_string(),
                title: "Password expiration configured".to_string(),
                description: "Ensure password expiration is set to 90 days or less".to_string(),
                category: AuditCategory::Accounts,
                severity: 7,
                cis_ref: Some("5.4.1.1".to_string()),
                remediation: "Edit /etc/login.defs and set PASS_MAX_DAYS to 90 or less".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/login.defs".to_string(),
                    pattern: r"PASS_MAX_DAYS\s+(?:[1-9]|[1-8][0-9]|90)\s*$".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "ACC-002".to_string(),
                title: "Minimum password length".to_string(),
                description: "Ensure minimum password length is 14 characters or more".to_string(),
                category: AuditCategory::Accounts,
                severity: 8,
                cis_ref: Some("5.4.1.2".to_string()),
                remediation: "Edit /etc/login.defs and set PASS_MIN_LEN to 14 or more".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/login.defs".to_string(),
                    pattern: r"PASS_MIN_LEN\s+(?:1[4-9]|[2-9][0-9])\s*$".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "ACC-003".to_string(),
                title: "Root login disabled".to_string(),
                description: "Ensure direct root login is disabled".to_string(),
                category: AuditCategory::Accounts,
                severity: 9,
                cis_ref: Some("5.6".to_string()),
                remediation: "Run: passwd -l root".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/shadow".to_string(),
                    pattern: r"^root:[*!]:".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "ACC-004".to_string(),
                title: "No empty passwords".to_string(),
                description: "Ensure no accounts have empty passwords".to_string(),
                category: AuditCategory::Accounts,
                severity: 10,
                cis_ref: Some("6.2.1".to_string()),
                remediation: "Lock or set passwords for accounts with empty passwords".to_string(),
                check_type: CheckType::CommandOutput {
                    command: "awk".to_string(),
                    args: vec!["-F:".to_string(), "($2 == \"\") {print $1}".to_string(), "/etc/shadow".to_string()],
                    pattern: r"^\s*$".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "ACC-005".to_string(),
                title: "No UID 0 accounts except root".to_string(),
                description: "Ensure only root has UID 0".to_string(),
                category: AuditCategory::Accounts,
                severity: 10,
                cis_ref: Some("6.2.2".to_string()),
                remediation: "Remove or change UID for non-root accounts with UID 0".to_string(),
                check_type: CheckType::CommandOutput {
                    command: "awk".to_string(),
                    args: vec!["-F:".to_string(), "($3 == 0 && $1 != \"root\") {print $1}".to_string(), "/etc/passwd".to_string()],
                    pattern: r"^\s*$".to_string(),
                    should_match: true,
                },
            },
        ]
    }

    fn file_permission_checks() -> Vec<Self> {
        vec![
            AuditCheck {
                id: "FILE-001".to_string(),
                title: "/etc/passwd permissions".to_string(),
                description: "Ensure /etc/passwd permissions are 644 or more restrictive".to_string(),
                category: AuditCategory::FilePermissions,
                severity: 8,
                cis_ref: Some("6.1.2".to_string()),
                remediation: "Run: chmod 644 /etc/passwd".to_string(),
                check_type: CheckType::FilePermissions {
                    path: "/etc/passwd".to_string(),
                    expected: 0o644,
                },
            },
            AuditCheck {
                id: "FILE-002".to_string(),
                title: "/etc/shadow permissions".to_string(),
                description: "Ensure /etc/shadow permissions are 640 or more restrictive".to_string(),
                category: AuditCategory::FilePermissions,
                severity: 10,
                cis_ref: Some("6.1.3".to_string()),
                remediation: "Run: chmod 640 /etc/shadow".to_string(),
                check_type: CheckType::FilePermissions {
                    path: "/etc/shadow".to_string(),
                    expected: 0o640,
                },
            },
            AuditCheck {
                id: "FILE-003".to_string(),
                title: "/etc/group permissions".to_string(),
                description: "Ensure /etc/group permissions are 644 or more restrictive".to_string(),
                category: AuditCategory::FilePermissions,
                severity: 7,
                cis_ref: Some("6.1.4".to_string()),
                remediation: "Run: chmod 644 /etc/group".to_string(),
                check_type: CheckType::FilePermissions {
                    path: "/etc/group".to_string(),
                    expected: 0o644,
                },
            },
            AuditCheck {
                id: "FILE-004".to_string(),
                title: "/etc/gshadow permissions".to_string(),
                description: "Ensure /etc/gshadow permissions are 640 or more restrictive".to_string(),
                category: AuditCategory::FilePermissions,
                severity: 8,
                cis_ref: Some("6.1.5".to_string()),
                remediation: "Run: chmod 640 /etc/gshadow".to_string(),
                check_type: CheckType::FilePermissions {
                    path: "/etc/gshadow".to_string(),
                    expected: 0o640,
                },
            },
            AuditCheck {
                id: "FILE-005".to_string(),
                title: "SSH directory permissions".to_string(),
                description: "Ensure /etc/ssh permissions are configured correctly".to_string(),
                category: AuditCategory::FilePermissions,
                severity: 8,
                cis_ref: Some("5.2.1".to_string()),
                remediation: "Run: chmod 700 /etc/ssh".to_string(),
                check_type: CheckType::FilePermissions {
                    path: "/etc/ssh".to_string(),
                    expected: 0o700,
                },
            },
        ]
    }

    fn network_checks() -> Vec<Self> {
        vec![
            AuditCheck {
                id: "NET-001".to_string(),
                title: "IP forwarding disabled".to_string(),
                description: "Ensure IP forwarding is disabled".to_string(),
                category: AuditCategory::Network,
                severity: 7,
                cis_ref: Some("3.1.1".to_string()),
                remediation: "Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf".to_string(),
                check_type: CheckType::Sysctl {
                    key: "net.ipv4.ip_forward".to_string(),
                    expected: "0".to_string(),
                },
            },
            AuditCheck {
                id: "NET-002".to_string(),
                title: "ICMP redirects disabled".to_string(),
                description: "Ensure ICMP redirects are not accepted".to_string(),
                category: AuditCategory::Network,
                severity: 6,
                cis_ref: Some("3.2.2".to_string()),
                remediation: "Set net.ipv4.conf.all.accept_redirects = 0".to_string(),
                check_type: CheckType::Sysctl {
                    key: "net.ipv4.conf.all.accept_redirects".to_string(),
                    expected: "0".to_string(),
                },
            },
            AuditCheck {
                id: "NET-003".to_string(),
                title: "Source routing disabled".to_string(),
                description: "Ensure source routed packets are not accepted".to_string(),
                category: AuditCategory::Network,
                severity: 7,
                cis_ref: Some("3.2.1".to_string()),
                remediation: "Set net.ipv4.conf.all.accept_source_route = 0".to_string(),
                check_type: CheckType::Sysctl {
                    key: "net.ipv4.conf.all.accept_source_route".to_string(),
                    expected: "0".to_string(),
                },
            },
            AuditCheck {
                id: "NET-004".to_string(),
                title: "TCP SYN cookies enabled".to_string(),
                description: "Ensure TCP SYN cookies is enabled".to_string(),
                category: AuditCategory::Network,
                severity: 6,
                cis_ref: Some("3.2.8".to_string()),
                remediation: "Set net.ipv4.tcp_syncookies = 1".to_string(),
                check_type: CheckType::Sysctl {
                    key: "net.ipv4.tcp_syncookies".to_string(),
                    expected: "1".to_string(),
                },
            },
            AuditCheck {
                id: "NET-005".to_string(),
                title: "IPv6 router advertisements disabled".to_string(),
                description: "Ensure IPv6 router advertisements are not accepted".to_string(),
                category: AuditCategory::Network,
                severity: 5,
                cis_ref: Some("3.3.1".to_string()),
                remediation: "Set net.ipv6.conf.all.accept_ra = 0".to_string(),
                check_type: CheckType::Sysctl {
                    key: "net.ipv6.conf.all.accept_ra".to_string(),
                    expected: "0".to_string(),
                },
            },
        ]
    }

    fn ssh_checks() -> Vec<Self> {
        vec![
            AuditCheck {
                id: "SSH-001".to_string(),
                title: "SSH Protocol 2 only".to_string(),
                description: "Ensure only SSH Protocol 2 is used".to_string(),
                category: AuditCategory::Ssh,
                severity: 10,
                cis_ref: Some("5.2.4".to_string()),
                remediation: "Set Protocol 2 in /etc/ssh/sshd_config".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/ssh/sshd_config".to_string(),
                    pattern: r"^\s*Protocol\s+1".to_string(),
                    should_match: false,
                },
            },
            AuditCheck {
                id: "SSH-002".to_string(),
                title: "SSH root login disabled".to_string(),
                description: "Ensure SSH root login is disabled".to_string(),
                category: AuditCategory::Ssh,
                severity: 9,
                cis_ref: Some("5.2.10".to_string()),
                remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/ssh/sshd_config".to_string(),
                    pattern: r"^\s*PermitRootLogin\s+no".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "SSH-003".to_string(),
                title: "SSH empty passwords disabled".to_string(),
                description: "Ensure SSH PermitEmptyPasswords is disabled".to_string(),
                category: AuditCategory::Ssh,
                severity: 10,
                cis_ref: Some("5.2.11".to_string()),
                remediation: "Set PermitEmptyPasswords no in /etc/ssh/sshd_config".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/ssh/sshd_config".to_string(),
                    pattern: r"^\s*PermitEmptyPasswords\s+no".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "SSH-004".to_string(),
                title: "SSH X11 forwarding disabled".to_string(),
                description: "Ensure SSH X11 forwarding is disabled".to_string(),
                category: AuditCategory::Ssh,
                severity: 5,
                cis_ref: Some("5.2.6".to_string()),
                remediation: "Set X11Forwarding no in /etc/ssh/sshd_config".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/ssh/sshd_config".to_string(),
                    pattern: r"^\s*X11Forwarding\s+no".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "SSH-005".to_string(),
                title: "SSH MaxAuthTries configured".to_string(),
                description: "Ensure SSH MaxAuthTries is set to 4 or less".to_string(),
                category: AuditCategory::Ssh,
                severity: 6,
                cis_ref: Some("5.2.7".to_string()),
                remediation: "Set MaxAuthTries 4 in /etc/ssh/sshd_config".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/ssh/sshd_config".to_string(),
                    pattern: r"^\s*MaxAuthTries\s+[1-4]\s*$".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "SSH-006".to_string(),
                title: "SSH IgnoreRhosts enabled".to_string(),
                description: "Ensure SSH IgnoreRhosts is enabled".to_string(),
                category: AuditCategory::Ssh,
                severity: 7,
                cis_ref: Some("5.2.8".to_string()),
                remediation: "Set IgnoreRhosts yes in /etc/ssh/sshd_config".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/ssh/sshd_config".to_string(),
                    pattern: r"^\s*IgnoreRhosts\s+yes".to_string(),
                    should_match: true,
                },
            },
        ]
    }

    fn logging_checks() -> Vec<Self> {
        vec![
            AuditCheck {
                id: "LOG-001".to_string(),
                title: "Rsyslog installed".to_string(),
                description: "Ensure rsyslog is installed".to_string(),
                category: AuditCategory::Logging,
                severity: 7,
                cis_ref: Some("4.2.1.1".to_string()),
                remediation: "Run: apt install rsyslog".to_string(),
                check_type: CheckType::FileExists {
                    path: "/etc/rsyslog.conf".to_string(),
                },
            },
            AuditCheck {
                id: "LOG-002".to_string(),
                title: "Audit log storage configured".to_string(),
                description: "Ensure audit log storage size is configured".to_string(),
                category: AuditCategory::Logging,
                severity: 6,
                cis_ref: Some("4.1.2.1".to_string()),
                remediation: "Configure max_log_file in /etc/audit/auditd.conf".to_string(),
                check_type: CheckType::FileContains {
                    path: "/etc/audit/auditd.conf".to_string(),
                    pattern: r"^\s*max_log_file\s*=".to_string(),
                    should_match: true,
                },
            },
            AuditCheck {
                id: "LOG-003".to_string(),
                title: "Auditd service enabled".to_string(),
                description: "Ensure auditd service is enabled".to_string(),
                category: AuditCategory::Logging,
                severity: 8,
                cis_ref: Some("4.1.1.2".to_string()),
                remediation: "Run: systemctl enable auditd".to_string(),
                check_type: CheckType::ServiceStatus {
                    service: "auditd".to_string(),
                    expected_status: "enabled".to_string(),
                },
            },
            AuditCheck {
                id: "LOG-004".to_string(),
                title: "Logrotate configured".to_string(),
                description: "Ensure logrotate is configured".to_string(),
                category: AuditCategory::Logging,
                severity: 5,
                cis_ref: Some("4.3".to_string()),
                remediation: "Configure /etc/logrotate.conf".to_string(),
                check_type: CheckType::FileExists {
                    path: "/etc/logrotate.conf".to_string(),
                },
            },
        ]
    }

    fn kernel_checks() -> Vec<Self> {
        vec![
            AuditCheck {
                id: "KERN-001".to_string(),
                title: "ASLR enabled".to_string(),
                description: "Ensure address space layout randomization is enabled".to_string(),
                category: AuditCategory::Kernel,
                severity: 8,
                cis_ref: Some("1.5.1".to_string()),
                remediation: "Set kernel.randomize_va_space = 2".to_string(),
                check_type: CheckType::Sysctl {
                    key: "kernel.randomize_va_space".to_string(),
                    expected: "2".to_string(),
                },
            },
            AuditCheck {
                id: "KERN-002".to_string(),
                title: "Core dumps restricted".to_string(),
                description: "Ensure core dumps are restricted".to_string(),
                category: AuditCategory::Kernel,
                severity: 6,
                cis_ref: Some("1.5.4".to_string()),
                remediation: "Set fs.suid_dumpable = 0".to_string(),
                check_type: CheckType::Sysctl {
                    key: "fs.suid_dumpable".to_string(),
                    expected: "0".to_string(),
                },
            },
            AuditCheck {
                id: "KERN-003".to_string(),
                title: "Kernel pointer restriction".to_string(),
                description: "Ensure kernel pointers are restricted".to_string(),
                category: AuditCategory::Kernel,
                severity: 6,
                cis_ref: Some("1.5.2".to_string()),
                remediation: "Set kernel.kptr_restrict = 2".to_string(),
                check_type: CheckType::Sysctl {
                    key: "kernel.kptr_restrict".to_string(),
                    expected: "2".to_string(),
                },
            },
            AuditCheck {
                id: "KERN-004".to_string(),
                title: "Dmesg restriction".to_string(),
                description: "Ensure dmesg is restricted".to_string(),
                category: AuditCategory::Kernel,
                severity: 5,
                cis_ref: Some("1.5.3".to_string()),
                remediation: "Set kernel.dmesg_restrict = 1".to_string(),
                check_type: CheckType::Sysctl {
                    key: "kernel.dmesg_restrict".to_string(),
                    expected: "1".to_string(),
                },
            },
        ]
    }

    fn service_checks() -> Vec<Self> {
        vec![
            AuditCheck {
                id: "SVC-001".to_string(),
                title: "Telnet server not installed".to_string(),
                description: "Ensure telnet server is not installed".to_string(),
                category: AuditCategory::Services,
                severity: 9,
                cis_ref: Some("2.2.18".to_string()),
                remediation: "Run: apt remove telnetd".to_string(),
                check_type: CheckType::FileExists {
                    path: "/usr/sbin/in.telnetd".to_string(),
                },
            },
            AuditCheck {
                id: "SVC-002".to_string(),
                title: "RSH server not installed".to_string(),
                description: "Ensure rsh server is not installed".to_string(),
                category: AuditCategory::Services,
                severity: 9,
                cis_ref: Some("2.2.17".to_string()),
                remediation: "Run: apt remove rsh-server".to_string(),
                check_type: CheckType::FileExists {
                    path: "/usr/sbin/in.rshd".to_string(),
                },
            },
        ]
    }
}

// ============================================================================
// AUDIT ENGINE IMPLEMENTATION
// ============================================================================

/// Main audit engine
struct AuditEngine {
    /// Checks to perform
    checks: Vec<AuditCheck>,
    /// Categories to audit
    categories: Vec<AuditCategory>,
    /// Verbose output
    verbose: bool,
    /// Show failures only
    failures_only: bool,
}

impl AuditEngine {
    /// Create a new audit engine
    fn new(
        categories: Vec<AuditCategory>,
        verbose: bool,
        failures_only: bool,
    ) -> Self {
        let mut checks = AuditCheck::default_checks();

        // Filter by category if specified
        let effective_categories = if categories.is_empty() || categories.contains(&AuditCategory::All) {
            vec![
                AuditCategory::Accounts,
                AuditCategory::FilePermissions,
                AuditCategory::Network,
                AuditCategory::Ssh,
                AuditCategory::Logging,
                AuditCategory::Kernel,
                AuditCategory::Services,
            ]
        } else {
            categories.clone()
        };

        checks.retain(|c| effective_categories.contains(&c.category));

        AuditEngine {
            checks,
            categories: effective_categories,
            verbose,
            failures_only,
        }
    }

    /// Run all audit checks
    fn run_audit(&self) -> Vec<AuditResult> {
        let mut results = Vec::new();

        println!("{}", "=".repeat(60).blue());
        println!("{}", "Security Configuration Audit".blue().bold());
        println!("{}", "=".repeat(60).blue());
        println!("Checks to perform: {}", self.checks.len());
        println!("{}", "-".repeat(60));

        for check in &self.checks {
            let result = self.execute_check(check);

            // Print result
            self.print_result(&result);

            results.push(result);
        }

        results
    }

    /// Execute a single check
    fn execute_check(&self, check: &AuditCheck) -> AuditResult {
        let (passed, status, actual, expected) = match &check.check_type {
            CheckType::FileExists { path } => {
                self.check_file_exists(path, check)
            }
            CheckType::FilePermissions { path, expected } => {
                self.check_file_permissions(path, *expected)
            }
            CheckType::FileContains { path, pattern, should_match } => {
                self.check_file_contains(path, pattern, *should_match)
            }
            CheckType::CommandOutput { command, args, pattern, should_match } => {
                self.check_command_output(command, args, pattern, *should_match)
            }
            CheckType::Sysctl { key, expected } => {
                self.check_sysctl(key, expected)
            }
            CheckType::ServiceStatus { service, expected_status } => {
                self.check_service_status(service, expected_status)
            }
            CheckType::Custom { check_name } => {
                self.run_custom_check(check_name)
            }
        };

        AuditResult {
            check_id: check.id.clone(),
            check_title: check.title.clone(),
            passed,
            status,
            actual_value: actual,
            expected_value: expected,
            severity: check.severity,
            category: check.category.clone(),
            remediation: check.remediation.clone(),
            cis_ref: check.cis_ref.clone(),
            checked_at: Utc::now(),
        }
    }

    fn check_file_exists(&self, path: &str, check: &AuditCheck) -> (bool, CheckStatus, Option<String>, Option<String>) {
        let exists = Path::new(path).exists();

        // For security-negative checks (should NOT exist)
        let is_negative_check = check.id.starts_with("SVC-");

        let passed = if is_negative_check { !exists } else { exists };
        let status = if passed { CheckStatus::Pass } else { CheckStatus::Fail };

        (passed, status, Some(exists.to_string()), Some((!is_negative_check).to_string()))
    }

    fn check_file_permissions(&self, path: &str, expected: u32) -> (bool, CheckStatus, Option<String>, Option<String>) {
        let path = Path::new(path);

        if !path.exists() {
            return (false, CheckStatus::NotApplicable, None, Some(format!("{:o}", expected)));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            match fs::metadata(path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    let passed = mode <= expected;
                    let status = if passed { CheckStatus::Pass } else { CheckStatus::Fail };
                    (passed, status, Some(format!("{:o}", mode)), Some(format!("{:o}", expected)))
                }
                Err(e) => (false, CheckStatus::Error(e.to_string()), None, Some(format!("{:o}", expected))),
            }
        }

        #[cfg(not(unix))]
        {
            (true, CheckStatus::NotApplicable, None, None)
        }
    }

    fn check_file_contains(&self, path: &str, pattern: &str, should_match: bool) -> (bool, CheckStatus, Option<String>, Option<String>) {
        let path = Path::new(path);

        if !path.exists() {
            return (false, CheckStatus::NotApplicable, None, Some(pattern.to_string()));
        }

        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(e) => return (false, CheckStatus::Error(e.to_string()), None, None),
        };

        match File::open(path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let mut found = false;
                let mut matched_line = None;

                for line in reader.lines().filter_map(|l| l.ok()) {
                    if regex.is_match(&line) {
                        found = true;
                        matched_line = Some(line);
                        break;
                    }
                }

                let passed = found == should_match;
                let status = if passed { CheckStatus::Pass } else { CheckStatus::Fail };

                (passed, status, matched_line.or(Some("No match".to_string())), Some(format!("Pattern: {}", pattern)))
            }
            Err(e) => (false, CheckStatus::Error(e.to_string()), None, None),
        }
    }

    fn check_command_output(&self, command: &str, args: &[String], pattern: &str, should_match: bool) -> (bool, CheckStatus, Option<String>, Option<String>) {
        let output = Command::new(command)
            .args(args)
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

                let regex = match Regex::new(pattern) {
                    Ok(r) => r,
                    Err(e) => return (false, CheckStatus::Error(e.to_string()), None, None),
                };

                let found = regex.is_match(&stdout);
                let passed = found == should_match;
                let status = if passed { CheckStatus::Pass } else { CheckStatus::Fail };

                (passed, status, Some(stdout), Some(pattern.to_string()))
            }
            Err(e) => (false, CheckStatus::Error(e.to_string()), None, None),
        }
    }

    fn check_sysctl(&self, key: &str, expected: &str) -> (bool, CheckStatus, Option<String>, Option<String>) {
        let output = Command::new("sysctl")
            .arg("-n")
            .arg(key)
            .output();

        match output {
            Ok(output) => {
                let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let passed = value == expected;
                let status = if passed { CheckStatus::Pass } else { CheckStatus::Fail };

                (passed, status, Some(value), Some(expected.to_string()))
            }
            Err(e) => (false, CheckStatus::Error(e.to_string()), None, Some(expected.to_string())),
        }
    }

    fn check_service_status(&self, service: &str, expected_status: &str) -> (bool, CheckStatus, Option<String>, Option<String>) {
        let output = Command::new("systemctl")
            .arg("is-enabled")
            .arg(service)
            .output();

        match output {
            Ok(output) => {
                let status_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let passed = status_str == expected_status;
                let status = if passed { CheckStatus::Pass } else { CheckStatus::Fail };

                (passed, status, Some(status_str), Some(expected_status.to_string()))
            }
            Err(_) => (false, CheckStatus::NotApplicable, Some("Service not found".to_string()), Some(expected_status.to_string())),
        }
    }

    fn run_custom_check(&self, check_name: &str) -> (bool, CheckStatus, Option<String>, Option<String>) {
        // Placeholder for custom checks
        (false, CheckStatus::NotApplicable, Some(format!("Custom check: {}", check_name)), None)
    }

    /// Print check result to console
    fn print_result(&self, result: &AuditResult) {
        if self.failures_only && result.passed {
            return;
        }

        let status_str = match &result.status {
            CheckStatus::Pass => "[PASS]".green().bold(),
            CheckStatus::Fail => "[FAIL]".red().bold(),
            CheckStatus::Warning => "[WARN]".yellow().bold(),
            CheckStatus::NotApplicable => "[N/A]".dimmed(),
            CheckStatus::Error(_) => "[ERR]".red(),
        };

        let severity_str = match result.severity {
            9..=10 => format!("(Critical)").red(),
            7..=8 => format!("(High)").red(),
            5..=6 => format!("(Medium)").yellow(),
            _ => format!("(Low)").white(),
        };

        println!(
            "{} {} {} {}",
            status_str,
            result.check_id.cyan(),
            result.check_title.white(),
            severity_str
        );

        if self.verbose && !result.passed {
            if let Some(actual) = &result.actual_value {
                println!("      Actual: {}", actual.dimmed());
            }
            if let Some(expected) = &result.expected_value {
                println!("      Expected: {}", expected.dimmed());
            }
            println!("      Remediation: {}", result.remediation.yellow());
        }
    }

    /// Get system information
    fn get_system_info() -> SystemInfo {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        #[cfg(unix)]
        let kernel = Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        #[cfg(not(unix))]
        let kernel = None;

        SystemInfo {
            hostname,
            os: std::env::consts::OS.to_string(),
            os_version: "Unknown".to_string(),
            kernel,
            architecture: std::env::consts::ARCH.to_string(),
        }
    }

    /// Generate summary from results
    fn generate_summary(&self, results: &[AuditResult]) -> AuditSummary {
        let mut summary = AuditSummary::default();

        summary.total_checks = results.len();

        for result in results {
            match result.status {
                CheckStatus::Pass => summary.passed += 1,
                CheckStatus::Fail => {
                    summary.failed += 1;
                    if result.severity >= 8 {
                        summary.critical_failures.push(format!(
                            "{}: {}",
                            result.check_id, result.check_title
                        ));
                    }
                }
                CheckStatus::Warning => summary.warnings += 1,
                CheckStatus::NotApplicable => summary.not_applicable += 1,
                CheckStatus::Error(_) => summary.errors += 1,
            }

            let cat_summary = summary.results_by_category
                .entry(result.category.to_string())
                .or_insert(CategorySummary::default());

            cat_summary.total += 1;
            if result.passed {
                cat_summary.passed += 1;
            } else {
                cat_summary.failed += 1;
            }
        }

        let applicable = summary.total_checks - summary.not_applicable - summary.errors;
        if applicable > 0 {
            summary.compliance_score = (summary.passed as f64 / applicable as f64) * 100.0;
        }

        summary
    }
}

// ============================================================================
// OUTPUT GENERATION
// ============================================================================

fn generate_output(report: &AuditReport, format: &OutputFormat, output: Option<&PathBuf>) -> Result<()> {
    let content = match format {
        OutputFormat::Json => serde_json::to_string_pretty(report)?,
        OutputFormat::Csv => generate_csv(report),
        OutputFormat::Html => generate_html(report),
        OutputFormat::Text => generate_text(report),
    };

    if let Some(path) = output {
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        println!("\nReport saved to: {}", path.display());
    }

    Ok(())
}

fn generate_csv(report: &AuditReport) -> String {
    let mut csv = String::from("Check ID,Title,Status,Severity,Category,Actual,Expected,CIS Ref\n");

    for result in &report.results {
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\"\n",
            result.check_id,
            result.check_title,
            result.status,
            result.severity,
            result.category,
            result.actual_value.as_deref().unwrap_or(""),
            result.expected_value.as_deref().unwrap_or(""),
            result.cis_ref.as_deref().unwrap_or("")
        ));
    }

    csv
}

fn generate_html(report: &AuditReport) -> String {
    let markup = html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                title { "Security Audit Report" }
                style {
                    r#"
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333; }
                    .summary { background-color: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
                    .score { font-size: 48px; font-weight: bold; }
                    .score.high { color: #28a745; }
                    .score.medium { color: #ffc107; }
                    .score.low { color: #dc3545; }
                    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                    th { background-color: #333; color: white; }
                    .pass { color: #28a745; font-weight: bold; }
                    .fail { color: #dc3545; font-weight: bold; }
                    .warn { color: #ffc107; font-weight: bold; }
                    .critical { background-color: #fff0f0; }
                    "#
                }
            }
            body {
                h1 { "Security Configuration Audit Report" }

                div class="summary" {
                    h2 { "Compliance Score" }
                    @let score_class = if report.summary.compliance_score >= 80.0 { "high" }
                        else if report.summary.compliance_score >= 60.0 { "medium" }
                        else { "low" };
                    p class={"score " (score_class)} {
                        (format!("{:.1}%", report.summary.compliance_score))
                    }

                    h3 { "Summary" }
                    p { "Total Checks: " (report.summary.total_checks) }
                    p class="pass" { "Passed: " (report.summary.passed) }
                    p class="fail" { "Failed: " (report.summary.failed) }
                    p { "Warnings: " (report.summary.warnings) }
                }

                @if !report.summary.critical_failures.is_empty() {
                    div style="background-color: #fff0f0; padding: 15px; margin: 20px 0; border: 1px solid #dc3545;" {
                        h3 style="color: #dc3545;" { "Critical Failures" }
                        ul {
                            @for failure in &report.summary.critical_failures {
                                li { (failure) }
                            }
                        }
                    }
                }

                h2 { "Detailed Results" }
                table {
                    thead {
                        tr {
                            th { "Status" }
                            th { "ID" }
                            th { "Check" }
                            th { "Severity" }
                            th { "Category" }
                            th { "CIS Ref" }
                        }
                    }
                    tbody {
                        @for result in &report.results {
                            @let row_class = if result.severity >= 8 && !result.passed { "critical" } else { "" };
                            tr class=(row_class) {
                                td class=(if result.passed { "pass" } else { "fail" }) {
                                    (result.status.to_string())
                                }
                                td { (result.check_id.clone()) }
                                td { (result.check_title.clone()) }
                                td { (result.severity) }
                                td { (result.category.to_string()) }
                                td { (result.cis_ref.clone().unwrap_or_default()) }
                            }
                        }
                    }
                }

                p style="margin-top: 30px; color: #666;" {
                    "Generated: " (report.report_info.generated_at.to_rfc3339())
                }
            }
        }
    };

    markup.into_string()
}

fn generate_text(report: &AuditReport) -> String {
    let mut text = String::new();

    text.push_str(&format!("{}\n", "=".repeat(60)));
    text.push_str("SECURITY CONFIGURATION AUDIT REPORT\n");
    text.push_str(&format!("{}\n\n", "=".repeat(60)));

    text.push_str(&format!("Generated: {}\n", report.report_info.generated_at));
    text.push_str(&format!("Hostname: {}\n", report.system_info.hostname));
    text.push_str(&format!("OS: {} {}\n\n", report.system_info.os, report.system_info.architecture));

    text.push_str(&format!("{}\n", "-".repeat(40)));
    text.push_str("COMPLIANCE SCORE\n");
    text.push_str(&format!("{}\n", "-".repeat(40)));
    text.push_str(&format!("Score: {:.1}%\n\n", report.summary.compliance_score));

    text.push_str(&format!("Total: {}\n", report.summary.total_checks));
    text.push_str(&format!("Passed: {}\n", report.summary.passed));
    text.push_str(&format!("Failed: {}\n", report.summary.failed));
    text.push_str(&format!("Warnings: {}\n\n", report.summary.warnings));

    if !report.summary.critical_failures.is_empty() {
        text.push_str("CRITICAL FAILURES:\n");
        for failure in &report.summary.critical_failures {
            text.push_str(&format!("  - {}\n", failure));
        }
        text.push('\n');
    }

    text.push_str(&format!("{}\n", "-".repeat(40)));
    text.push_str("DETAILED RESULTS\n");
    text.push_str(&format!("{}\n\n", "-".repeat(40)));

    for result in &report.results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        text.push_str(&format!(
            "[{}] {} - {}\n",
            status, result.check_id, result.check_title
        ));

        if !result.passed {
            text.push_str(&format!("     Remediation: {}\n", result.remediation));
        }
    }

    text
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    // Create audit engine
    let engine = AuditEngine::new(
        args.category,
        args.verbose,
        args.failures_only,
    );

    // Run audit
    let results = engine.run_audit();

    // Generate summary
    let summary = engine.generate_summary(&results);

    // Create report
    let report = AuditReport {
        report_info: ReportInfo {
            generated_at: Utc::now(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            categories_audited: engine.categories.clone(),
            compliance_framework: args.compliance.map(|c| format!("{:?}", c)),
        },
        system_info: AuditEngine::get_system_info(),
        results,
        summary,
    };

    // Print summary
    println!("{}", "-".repeat(60).blue());
    println!("{}", "AUDIT SUMMARY".green().bold());
    println!("{}", "-".repeat(60).blue());
    println!("Compliance Score: {:.1}%", report.summary.compliance_score);
    println!("Total Checks: {}", report.summary.total_checks);
    println!("{}: {}", "Passed".green(), report.summary.passed);
    println!("{}: {}", "Failed".red(), report.summary.failed);
    println!("Warnings: {}", report.summary.warnings);
    println!("N/A: {}", report.summary.not_applicable);

    if !report.summary.critical_failures.is_empty() {
        println!("\n{}", "CRITICAL FAILURES:".red().bold());
        for failure in &report.summary.critical_failures {
            println!("  - {}", failure.red());
        }
    }

    // Generate output
    if let Some(ref output) = args.output {
        generate_output(&report, &args.format, Some(output))?;
    }

    // Exit with appropriate code
    if report.summary.failed > 0 {
        println!("\n{}", "Some checks failed. Review and remediate findings.".yellow());
    } else {
        println!("\n{}", "All checks passed!".green().bold());
    }

    println!("{}", "=".repeat(60).blue());

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_engine_creation() {
        let engine = AuditEngine::new(vec![], false, false);
        assert!(!engine.checks.is_empty());
    }

    #[test]
    fn test_category_filtering() {
        let engine = AuditEngine::new(vec![AuditCategory::Ssh], false, false);

        for check in &engine.checks {
            assert_eq!(check.category, AuditCategory::Ssh);
        }
    }

    #[test]
    fn test_default_checks_exist() {
        let checks = AuditCheck::default_checks();
        assert!(!checks.is_empty());

        // Verify we have checks for each category
        let categories: Vec<_> = checks.iter().map(|c| &c.category).collect();
        assert!(categories.contains(&&AuditCategory::Accounts));
        assert!(categories.contains(&&AuditCategory::Ssh));
        assert!(categories.contains(&&AuditCategory::Network));
    }

    #[test]
    fn test_check_structure() {
        let checks = AuditCheck::default_checks();

        for check in checks {
            assert!(!check.id.is_empty());
            assert!(!check.title.is_empty());
            assert!(!check.description.is_empty());
            assert!(check.severity >= 1 && check.severity <= 10);
        }
    }

    #[test]
    fn test_file_permission_check() {
        let engine = AuditEngine::new(vec![], false, false);

        // Check a file that should exist
        let (_, status, _, _) = engine.check_file_permissions("/etc/passwd", 0o644);

        // Status should not be an error
        assert!(!matches!(status, CheckStatus::Error(_)));
    }

    #[test]
    fn test_file_exists_check() {
        let engine = AuditEngine::new(vec![], false, false);

        let check = AuditCheck {
            id: "TEST-001".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            category: AuditCategory::FilePermissions,
            severity: 5,
            cis_ref: None,
            remediation: "None".to_string(),
            check_type: CheckType::FileExists { path: "/etc/passwd".to_string() },
        };

        let (passed, status, _, _) = engine.check_file_exists("/etc/passwd", &check);

        assert!(passed);
        assert!(matches!(status, CheckStatus::Pass));
    }

    #[test]
    fn test_sysctl_check() {
        let engine = AuditEngine::new(vec![], false, false);

        // This sysctl key should exist on Linux
        let (_, status, actual, _) = engine.check_sysctl("kernel.hostname", "");

        // Should not error, even if value doesn't match
        assert!(!matches!(status, CheckStatus::Error(_)));
        assert!(actual.is_some());
    }

    #[test]
    fn test_summary_generation() {
        let engine = AuditEngine::new(vec![], false, false);

        let results = vec![
            AuditResult {
                check_id: "TEST-001".to_string(),
                check_title: "Test Pass".to_string(),
                passed: true,
                status: CheckStatus::Pass,
                actual_value: None,
                expected_value: None,
                severity: 5,
                category: AuditCategory::Ssh,
                remediation: String::new(),
                cis_ref: None,
                checked_at: Utc::now(),
            },
            AuditResult {
                check_id: "TEST-002".to_string(),
                check_title: "Test Fail".to_string(),
                passed: false,
                status: CheckStatus::Fail,
                actual_value: None,
                expected_value: None,
                severity: 9,
                category: AuditCategory::Ssh,
                remediation: String::new(),
                cis_ref: None,
                checked_at: Utc::now(),
            },
        ];

        let summary = engine.generate_summary(&results);

        assert_eq!(summary.total_checks, 2);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert!(!summary.critical_failures.is_empty());
    }

    #[test]
    fn test_compliance_score_calculation() {
        let engine = AuditEngine::new(vec![], false, false);

        let results = vec![
            AuditResult {
                check_id: "1".to_string(),
                check_title: "".to_string(),
                passed: true,
                status: CheckStatus::Pass,
                actual_value: None,
                expected_value: None,
                severity: 5,
                category: AuditCategory::Ssh,
                remediation: String::new(),
                cis_ref: None,
                checked_at: Utc::now(),
            },
            AuditResult {
                check_id: "2".to_string(),
                check_title: "".to_string(),
                passed: true,
                status: CheckStatus::Pass,
                actual_value: None,
                expected_value: None,
                severity: 5,
                category: AuditCategory::Ssh,
                remediation: String::new(),
                cis_ref: None,
                checked_at: Utc::now(),
            },
        ];

        let summary = engine.generate_summary(&results);
        assert_eq!(summary.compliance_score, 100.0);
    }

    #[test]
    fn test_check_status_display() {
        assert_eq!(CheckStatus::Pass.to_string(), "PASS");
        assert_eq!(CheckStatus::Fail.to_string(), "FAIL");
        assert_eq!(CheckStatus::Warning.to_string(), "WARN");
    }

    #[test]
    fn test_category_display() {
        assert_eq!(AuditCategory::Ssh.to_string(), "SSH Hardening");
        assert_eq!(AuditCategory::Network.to_string(), "Network Security");
    }

    #[test]
    fn test_report_serialization() {
        let report = AuditReport {
            report_info: ReportInfo {
                generated_at: Utc::now(),
                tool_version: "1.0.0".to_string(),
                categories_audited: vec![AuditCategory::Ssh],
                compliance_framework: None,
            },
            system_info: SystemInfo {
                hostname: "test".to_string(),
                os: "linux".to_string(),
                os_version: "1.0".to_string(),
                kernel: None,
                architecture: "x86_64".to_string(),
            },
            results: vec![],
            summary: AuditSummary::default(),
        };

        let json = serde_json::to_string(&report);
        assert!(json.is_ok());
    }

    #[test]
    fn test_csv_generation() {
        let report = AuditReport {
            report_info: ReportInfo {
                generated_at: Utc::now(),
                tool_version: "1.0.0".to_string(),
                categories_audited: vec![],
                compliance_framework: None,
            },
            system_info: SystemInfo {
                hostname: "test".to_string(),
                os: "linux".to_string(),
                os_version: "1.0".to_string(),
                kernel: None,
                architecture: "x86_64".to_string(),
            },
            results: vec![],
            summary: AuditSummary::default(),
        };

        let csv = generate_csv(&report);
        assert!(csv.contains("Check ID"));
    }

    #[test]
    fn test_file_contains_check() {
        let engine = AuditEngine::new(vec![], false, false);

        // Check for a pattern that should exist in /etc/passwd
        let (_, status, _, _) = engine.check_file_contains(
            "/etc/passwd",
            "root",
            true,
        );

        assert!(!matches!(status, CheckStatus::Error(_)));
    }
}
