//! AU02 User Manager - User Account Management Tool
//!
//! This tool provides comprehensive user account management for Linux systems.
//! Essential for security operations including access control and auditing.
//!
//! Features:
//! - List all users with detailed information
//! - Create/delete user accounts
//! - Modify user properties (groups, shell, home)
//! - Password management and policy enforcement
//! - Lock/unlock user accounts
//! - Audit user login history
//! - Detect suspicious user configurations
//! - Group management
//!
//! Security applications:
//! - User access control and provisioning
//! - Incident response (lock compromised accounts)
//! - Compliance auditing
//! - Detecting unauthorized accounts

use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use clap::{Parser, Subcommand};
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use tabled::{Table, Tabled};

/// User Manager - Comprehensive user account management tool
#[derive(Parser)]
#[command(name = "user-manager")]
#[command(author = "Security Engineer")]
#[command(version = "1.0")]
#[command(about = "Manage user accounts for security operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// List all users
    List {
        /// Show system users (UID < 1000)
        #[arg(short, long)]
        system: bool,

        /// Show only human users (UID >= 1000)
        #[arg(short = 'H', long)]
        human: bool,

        /// Filter by group
        #[arg(short, long)]
        group: Option<String>,
    },

    /// Show detailed user information
    Info {
        /// Username
        username: String,
    },

    /// Create a new user
    Create {
        /// Username
        username: String,

        /// Full name/comment
        #[arg(short, long)]
        comment: Option<String>,

        /// Home directory
        #[arg(short = 'H', long)]
        home: Option<String>,

        /// Login shell
        #[arg(short, long)]
        shell: Option<String>,

        /// Primary group
        #[arg(short, long)]
        group: Option<String>,

        /// Additional groups (comma-separated)
        #[arg(short = 'G', long)]
        groups: Option<String>,

        /// Create home directory
        #[arg(short, long)]
        create_home: bool,

        /// Set password interactively
        #[arg(short, long)]
        password: bool,
    },

    /// Delete a user
    Delete {
        /// Username
        username: String,

        /// Remove home directory
        #[arg(short, long)]
        remove_home: bool,

        /// Force deletion even if user is logged in
        #[arg(short, long)]
        force: bool,
    },

    /// Modify user properties
    Modify {
        /// Username
        username: String,

        /// New login shell
        #[arg(short, long)]
        shell: Option<String>,

        /// New home directory
        #[arg(short = 'H', long)]
        home: Option<String>,

        /// New comment/full name
        #[arg(short, long)]
        comment: Option<String>,

        /// Add to groups (comma-separated)
        #[arg(short = 'G', long)]
        add_groups: Option<String>,

        /// Remove from groups (comma-separated)
        #[arg(short = 'R', long)]
        remove_groups: Option<String>,
    },

    /// Lock a user account
    Lock {
        /// Username
        username: String,

        /// Reason for locking
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Unlock a user account
    Unlock {
        /// Username
        username: String,
    },

    /// Change user password
    Password {
        /// Username
        username: String,

        /// Expire password (force change on next login)
        #[arg(short, long)]
        expire: bool,
    },

    /// Show user login history
    History {
        /// Username (all users if not specified)
        username: Option<String>,

        /// Number of entries to show
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Show failed login attempts
        #[arg(short, long)]
        failed: bool,
    },

    /// Security audit of user accounts
    Audit {
        /// Check for specific issues
        #[arg(short, long)]
        check: Option<String>,

        /// Fix found issues automatically
        #[arg(short, long)]
        fix: bool,
    },

    /// List all groups
    Groups {
        /// Show members of each group
        #[arg(short, long)]
        members: bool,
    },

    /// Manage group membership
    GroupMod {
        /// Group name
        group: String,

        /// Add user to group
        #[arg(short, long)]
        add: Option<String>,

        /// Remove user from group
        #[arg(short, long)]
        remove: Option<String>,
    },

    /// Export user data
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Check for currently logged in users
    Sessions {
        /// Show detailed session info
        #[arg(short, long)]
        detailed: bool,
    },
}

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct UserInfo {
    #[tabled(rename = "Username")]
    username: String,
    #[tabled(rename = "UID")]
    uid: u32,
    #[tabled(rename = "GID")]
    gid: u32,
    #[tabled(rename = "Shell")]
    shell: String,
    #[tabled(rename = "Home")]
    home: String,
    #[tabled(rename = "Status")]
    status: String,
}

/// Detailed user information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserDetails {
    username: String,
    uid: u32,
    gid: u32,
    comment: String,
    home: String,
    shell: String,
    groups: Vec<String>,
    locked: bool,
    password_status: PasswordStatus,
    last_login: Option<String>,
    login_count: u32,
    home_exists: bool,
    home_size: Option<u64>,
}

/// Password status information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordStatus {
    has_password: bool,
    last_change: Option<String>,
    expires: Option<String>,
    max_age: Option<i32>,
    min_age: Option<i32>,
    warn_days: Option<i32>,
}

/// Group information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct GroupInfo {
    #[tabled(rename = "Group")]
    name: String,
    #[tabled(rename = "GID")]
    gid: u32,
    #[tabled(rename = "Members")]
    members: String,
}

/// Login session information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct SessionInfo {
    #[tabled(rename = "User")]
    user: String,
    #[tabled(rename = "TTY")]
    tty: String,
    #[tabled(rename = "From")]
    from: String,
    #[tabled(rename = "Login Time")]
    login_time: String,
    #[tabled(rename = "Idle")]
    idle: String,
}

/// Security audit finding
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditFinding {
    severity: String,
    category: String,
    user: String,
    issue: String,
    recommendation: String,
}

/// User manager implementation
struct UserManager {
    verbose: bool,
}

impl UserManager {
    fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// List all users based on filters
    fn list_users(&self, show_system: bool, show_human: bool, group_filter: Option<&str>) -> Result<Vec<UserInfo>> {
        let mut users = Vec::new();

        // Read /etc/passwd
        let passwd_file = File::open("/etc/passwd").context("Failed to open /etc/passwd")?;
        let reader = BufReader::new(passwd_file);

        // Get locked users
        let locked_users = self.get_locked_users()?;

        // Get group members if filtering by group
        let group_members: Option<Vec<String>> = if let Some(grp) = group_filter {
            Some(self.get_group_members(grp)?)
        } else {
            None
        };

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                continue;
            }

            let username = parts[0].to_string();
            let uid: u32 = parts[2].parse().unwrap_or(0);
            let gid: u32 = parts[3].parse().unwrap_or(0);
            let _comment = parts[4];
            let home = parts[5].to_string();
            let shell = parts[6].to_string();

            // Apply filters
            if show_human && uid < 1000 && uid != 0 {
                continue;
            }
            if !show_system && !show_human && uid < 1000 && uid != 0 {
                // Default: show human users only
                continue;
            }

            if let Some(ref members) = group_members {
                if !members.contains(&username) {
                    continue;
                }
            }

            let status = if locked_users.contains(&username) {
                "Locked".to_string()
            } else if shell.contains("nologin") || shell.contains("false") {
                "No Login".to_string()
            } else {
                "Active".to_string()
            };

            users.push(UserInfo {
                username,
                uid,
                gid,
                shell,
                home,
                status,
            });
        }

        Ok(users)
    }

    /// Get list of locked users
    fn get_locked_users(&self) -> Result<Vec<String>> {
        let mut locked = Vec::new();

        let shadow = fs::read_to_string("/etc/shadow").unwrap_or_default();
        for line in shadow.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let password = parts[1];
                // Locked accounts have ! or * at the start of password field
                if password.starts_with('!') || password.starts_with('*') {
                    locked.push(parts[0].to_string());
                }
            }
        }

        Ok(locked)
    }

    /// Get members of a group
    fn get_group_members(&self, group_name: &str) -> Result<Vec<String>> {
        let group_file = fs::read_to_string("/etc/group")?;

        for line in group_file.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 && parts[0] == group_name {
                return Ok(parts[3].split(',').map(|s| s.to_string()).filter(|s| !s.is_empty()).collect());
            }
        }

        Ok(Vec::new())
    }

    /// Get detailed user information
    fn get_user_details(&self, username: &str) -> Result<UserDetails> {
        // Read from passwd
        let passwd = fs::read_to_string("/etc/passwd")?;
        let mut user_entry: Option<Vec<String>> = None;

        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 && parts[0] == username {
                user_entry = Some(parts.iter().map(|s| s.to_string()).collect());
                break;
            }
        }

        let entry = user_entry.context("User not found")?;
        let uid: u32 = entry[2].parse()?;
        let gid: u32 = entry[3].parse()?;
        let comment = entry[4].clone();
        let home = entry[5].clone();
        let shell = entry[6].clone();

        // Get groups
        let output = Command::new("groups").arg(username).output()?;
        let groups_str = String::from_utf8_lossy(&output.stdout);
        let groups: Vec<String> = groups_str
            .split(':')
            .last()
            .unwrap_or("")
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Check if locked
        let locked = self.get_locked_users()?.contains(&username.to_string());

        // Get password status
        let password_status = self.get_password_status(username)?;

        // Get last login
        let last_login = self.get_last_login(username)?;

        // Check home directory
        let home_path = PathBuf::from(&home);
        let home_exists = home_path.exists();
        let home_size = if home_exists {
            self.get_directory_size(&home_path).ok()
        } else {
            None
        };

        // Get login count
        let login_count = self.get_login_count(username)?;

        Ok(UserDetails {
            username: username.to_string(),
            uid,
            gid,
            comment,
            home,
            shell,
            groups,
            locked,
            password_status,
            last_login,
            login_count,
            home_exists,
            home_size,
        })
    }

    /// Get password status for a user
    fn get_password_status(&self, username: &str) -> Result<PasswordStatus> {
        let output = Command::new("chage")
            .args(["-l", username])
            .output();

        let mut status = PasswordStatus {
            has_password: true,
            last_change: None,
            expires: None,
            max_age: None,
            min_age: None,
            warn_days: None,
        };

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if let Some((key, value)) = line.split_once(':') {
                    let value = value.trim();
                    match key.trim() {
                        "Last password change" => {
                            status.last_change = Some(value.to_string());
                        }
                        "Password expires" => {
                            status.expires = Some(value.to_string());
                        }
                        "Maximum number of days between password change" => {
                            status.max_age = value.parse().ok();
                        }
                        "Minimum number of days between password change" => {
                            status.min_age = value.parse().ok();
                        }
                        "Number of days of warning before password expires" => {
                            status.warn_days = value.parse().ok();
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(status)
    }

    /// Get last login time for a user
    fn get_last_login(&self, username: &str) -> Result<Option<String>> {
        let output = Command::new("lastlog")
            .args(["-u", username])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() >= 2 {
            let parts: Vec<&str> = lines[1].split_whitespace().collect();
            if parts.len() >= 4 && !lines[1].contains("Never logged in") {
                return Ok(Some(parts[3..].join(" ")));
            }
        }

        Ok(None)
    }

    /// Get login count for a user
    fn get_login_count(&self, username: &str) -> Result<u32> {
        let output = Command::new("last")
            .args(["-c", username])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let count = stdout.lines().filter(|l| l.starts_with(username)).count();
        Ok(count as u32)
    }

    /// Get directory size
    fn get_directory_size(&self, path: &PathBuf) -> Result<u64> {
        let output = Command::new("du")
            .args(["-sb", &path.to_string_lossy()])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(size_str) = stdout.split_whitespace().next() {
            return Ok(size_str.parse().unwrap_or(0));
        }

        Ok(0)
    }

    /// Create a new user
    fn create_user(
        &self,
        username: &str,
        comment: Option<&str>,
        home: Option<&str>,
        shell: Option<&str>,
        group: Option<&str>,
        groups: Option<&str>,
        create_home: bool,
    ) -> Result<()> {
        println!("{} Creating user: {}", "[*]".blue(), username.cyan());

        // Validate username
        let re = Regex::new(r"^[a-z_][a-z0-9_-]*$")?;
        if !re.is_match(username) {
            anyhow::bail!("Invalid username format");
        }

        let mut cmd = Command::new("useradd");

        if create_home {
            cmd.arg("-m");
        }

        if let Some(c) = comment {
            cmd.args(["-c", c]);
        }

        if let Some(h) = home {
            cmd.args(["-d", h]);
        }

        if let Some(s) = shell {
            cmd.args(["-s", s]);
        }

        if let Some(g) = group {
            cmd.args(["-g", g]);
        }

        if let Some(gs) = groups {
            cmd.args(["-G", gs]);
        }

        cmd.arg(username);

        let output = cmd.output().context("Failed to run useradd")?;

        if output.status.success() {
            println!("{} User {} created successfully", "[+]".green(), username.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to create user: {}", stderr);
        }
    }

    /// Delete a user
    fn delete_user(&self, username: &str, remove_home: bool, force: bool) -> Result<()> {
        println!("{} Deleting user: {}", "[*]".blue(), username.cyan());

        // Check if user is logged in
        if !force {
            let sessions = self.get_sessions()?;
            if sessions.iter().any(|s| s.user == username) {
                anyhow::bail!("User is currently logged in. Use --force to override.");
            }
        }

        let mut cmd = Command::new("userdel");

        if remove_home {
            cmd.arg("-r");
        }

        if force {
            cmd.arg("-f");
        }

        cmd.arg(username);

        let output = cmd.output().context("Failed to run userdel")?;

        if output.status.success() {
            println!("{} User {} deleted successfully", "[+]".green(), username.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to delete user: {}", stderr);
        }
    }

    /// Modify user properties
    fn modify_user(
        &self,
        username: &str,
        shell: Option<&str>,
        home: Option<&str>,
        comment: Option<&str>,
        add_groups: Option<&str>,
        remove_groups: Option<&str>,
    ) -> Result<()> {
        println!("{} Modifying user: {}", "[*]".blue(), username.cyan());

        let mut modified = false;

        // Use usermod for basic modifications
        if shell.is_some() || home.is_some() || comment.is_some() {
            let mut cmd = Command::new("usermod");

            if let Some(s) = shell {
                cmd.args(["-s", s]);
                modified = true;
            }

            if let Some(h) = home {
                cmd.args(["-d", h, "-m"]);
                modified = true;
            }

            if let Some(c) = comment {
                cmd.args(["-c", c]);
                modified = true;
            }

            cmd.arg(username);

            let output = cmd.output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Failed to modify user: {}", stderr);
            }
        }

        // Add to groups
        if let Some(groups) = add_groups {
            for group in groups.split(',') {
                let output = Command::new("usermod")
                    .args(["-aG", group.trim(), username])
                    .output()?;
                if output.status.success() {
                    println!("  {} Added to group: {}", "[+]".green(), group.trim());
                    modified = true;
                }
            }
        }

        // Remove from groups
        if let Some(groups) = remove_groups {
            for group in groups.split(',') {
                let output = Command::new("gpasswd")
                    .args(["-d", username, group.trim()])
                    .output()?;
                if output.status.success() {
                    println!("  {} Removed from group: {}", "[+]".green(), group.trim());
                    modified = true;
                }
            }
        }

        if modified {
            println!("{} User {} modified successfully", "[+]".green(), username.cyan());
        } else {
            println!("{} No modifications made", "[*]".yellow());
        }

        Ok(())
    }

    /// Lock a user account
    fn lock_user(&self, username: &str, reason: Option<&str>) -> Result<()> {
        println!("{} Locking user account: {}", "[*]".blue(), username.cyan());

        let output = Command::new("usermod")
            .args(["-L", username])
            .output()
            .context("Failed to lock user")?;

        if output.status.success() {
            println!("{} User {} locked successfully", "[+]".green(), username.cyan());
            if let Some(r) = reason {
                println!("  Reason: {}", r);
                // Log the reason
                self.log_action(username, &format!("Account locked: {}", r))?;
            }
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to lock user: {}", stderr);
        }
    }

    /// Unlock a user account
    fn unlock_user(&self, username: &str) -> Result<()> {
        println!("{} Unlocking user account: {}", "[*]".blue(), username.cyan());

        let output = Command::new("usermod")
            .args(["-U", username])
            .output()
            .context("Failed to unlock user")?;

        if output.status.success() {
            println!("{} User {} unlocked successfully", "[+]".green(), username.cyan());
            self.log_action(username, "Account unlocked")?;
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to unlock user: {}", stderr);
        }
    }

    /// Log an action for auditing
    fn log_action(&self, username: &str, action: &str) -> Result<()> {
        let now: DateTime<Local> = Local::now();
        let log_entry = format!(
            "{} - User: {} - Action: {}\n",
            now.format("%Y-%m-%d %H:%M:%S"),
            username,
            action
        );

        // Try to append to system log
        let log_path = "/var/log/user-manager.log";
        if let Err(_) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, log_entry.as_bytes()))
        {
            // If we can't write to /var/log, just print
            if self.verbose {
                println!("  Log: {}", action);
            }
        }

        Ok(())
    }

    /// Get login history
    fn get_login_history(&self, username: Option<&str>, limit: usize, failed: bool) -> Result<Vec<String>> {
        let mut entries = Vec::new();

        let cmd = if failed {
            let output = Command::new("lastb")
                .args(match username {
                    Some(u) => vec!["-n", &limit.to_string(), u],
                    None => vec!["-n", &limit.to_string()],
                })
                .output()?;
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            let output = Command::new("last")
                .args(match username {
                    Some(u) => vec!["-n", &limit.to_string(), u],
                    None => vec!["-n", &limit.to_string()],
                })
                .output()?;
            String::from_utf8_lossy(&output.stdout).to_string()
        };

        for line in cmd.lines() {
            if !line.trim().is_empty() && !line.starts_with("wtmp") && !line.starts_with("btmp") {
                entries.push(line.to_string());
            }
        }

        Ok(entries)
    }

    /// Perform security audit
    fn audit(&self, check: Option<&str>, fix: bool) -> Result<Vec<AuditFinding>> {
        println!("{} Performing security audit...", "[*]".blue());
        let mut findings = Vec::new();

        // Get all users
        let users = self.list_users(true, false, None)?;

        for user in &users {
            // Check for users with UID 0 (root equivalents)
            if user.uid == 0 && user.username != "root" {
                findings.push(AuditFinding {
                    severity: "CRITICAL".to_string(),
                    category: "Privilege".to_string(),
                    user: user.username.clone(),
                    issue: "User has UID 0 (root equivalent)".to_string(),
                    recommendation: "Review and remove unauthorized root equivalent".to_string(),
                });
            }

            // Check for users with no password
            let details = self.get_user_details(&user.username)?;
            if !details.password_status.has_password && !details.locked {
                findings.push(AuditFinding {
                    severity: "HIGH".to_string(),
                    category: "Password".to_string(),
                    user: user.username.clone(),
                    issue: "User has no password set".to_string(),
                    recommendation: "Set a strong password or lock the account".to_string(),
                });
            }

            // Check for world-readable home directories
            if details.home_exists && user.uid >= 1000 {
                let perms = fs::metadata(&details.home).ok().map(|m| m.permissions());
                if let Some(p) = perms {
                    use std::os::unix::fs::PermissionsExt;
                    if p.mode() & 0o007 != 0 {
                        findings.push(AuditFinding {
                            severity: "MEDIUM".to_string(),
                            category: "Permissions".to_string(),
                            user: user.username.clone(),
                            issue: "Home directory is world-accessible".to_string(),
                            recommendation: "Remove world permissions from home directory".to_string(),
                        });

                        if fix {
                            let _ = Command::new("chmod")
                                .args(["o-rwx", &details.home])
                                .output();
                        }
                    }
                }
            }

            // Check for users in sudo/wheel group
            if details.groups.contains(&"sudo".to_string()) || details.groups.contains(&"wheel".to_string()) {
                findings.push(AuditFinding {
                    severity: "INFO".to_string(),
                    category: "Privilege".to_string(),
                    user: user.username.clone(),
                    issue: "User has sudo/admin privileges".to_string(),
                    recommendation: "Verify this access is authorized".to_string(),
                });
            }

            // Check for shells that allow login on system accounts
            if user.uid < 1000 && user.uid != 0 {
                if !user.shell.contains("nologin") && !user.shell.contains("false") {
                    findings.push(AuditFinding {
                        severity: "MEDIUM".to_string(),
                        category: "Shell".to_string(),
                        user: user.username.clone(),
                        issue: "System account has interactive shell".to_string(),
                        recommendation: "Change shell to /usr/sbin/nologin".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// List all groups
    fn list_groups(&self, show_members: bool) -> Result<Vec<GroupInfo>> {
        let mut groups = Vec::new();

        let group_file = fs::read_to_string("/etc/group")?;
        for line in group_file.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let members = if show_members {
                    parts[3].to_string()
                } else {
                    let count = parts[3].split(',').filter(|s| !s.is_empty()).count();
                    format!("{} members", count)
                };

                groups.push(GroupInfo {
                    name: parts[0].to_string(),
                    gid: parts[2].parse().unwrap_or(0),
                    members,
                });
            }
        }

        Ok(groups)
    }

    /// Get current sessions
    fn get_sessions(&self) -> Result<Vec<SessionInfo>> {
        let mut sessions = Vec::new();

        let output = Command::new("who")
            .args(["-u"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                sessions.push(SessionInfo {
                    user: parts[0].to_string(),
                    tty: parts[1].to_string(),
                    login_time: format!("{} {}", parts.get(2).unwrap_or(&""), parts.get(3).unwrap_or(&"")),
                    from: parts.get(4).unwrap_or(&"-").trim_matches(|c| c == '(' || c == ')').to_string(),
                    idle: parts.get(5).unwrap_or(&"-").to_string(),
                });
            }
        }

        Ok(sessions)
    }

    /// Export user data
    fn export_users(&self, output: &PathBuf) -> Result<()> {
        println!("{} Exporting user data...", "[*]".blue());

        let users = self.list_users(true, false, None)?;
        let mut detailed_users = Vec::new();

        for user in &users {
            if let Ok(details) = self.get_user_details(&user.username) {
                detailed_users.push(details);
            }
        }

        let json = serde_json::to_string_pretty(&detailed_users)?;
        fs::write(output, json)?;

        println!("{} Exported {} users to {}", "[+]".green(), detailed_users.len(), output.display());
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manager = UserManager::new(cli.verbose);

    match cli.command {
        Commands::List { system, human, group } => {
            let users = manager.list_users(system, human, group.as_deref())?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&users)?);
            } else {
                println!("{} Found {} users:", "[+]".green(), users.len());
                let table = Table::new(&users).to_string();
                println!("{}", table);
            }
        }

        Commands::Info { username } => {
            let details = manager.get_user_details(&username)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&details)?);
            } else {
                println!("{} User Details: {}", "[*]".blue(), details.username.cyan().bold());
                println!("{}", "=".repeat(50));
                println!("  UID:          {}", details.uid);
                println!("  GID:          {}", details.gid);
                println!("  Comment:      {}", details.comment);
                println!("  Home:         {}", details.home);
                println!("  Shell:        {}", details.shell);
                println!("  Groups:       {}", details.groups.join(", "));
                println!("  Locked:       {}", if details.locked { "Yes".red() } else { "No".green() });
                println!("  Last Login:   {}", details.last_login.unwrap_or("-".to_string()));
                println!("  Login Count:  {}", details.login_count);
                println!("  Home Exists:  {}", details.home_exists);
                if let Some(size) = details.home_size {
                    println!("  Home Size:    {:.1} MB", size as f64 / 1024.0 / 1024.0);
                }
                println!("\n  Password Status:");
                println!("    Last Change:  {}", details.password_status.last_change.unwrap_or("-".to_string()));
                println!("    Expires:      {}", details.password_status.expires.unwrap_or("-".to_string()));
            }
        }

        Commands::Create { username, comment, home, shell, group, groups, create_home, password: _ } => {
            manager.create_user(
                &username,
                comment.as_deref(),
                home.as_deref(),
                shell.as_deref(),
                group.as_deref(),
                groups.as_deref(),
                create_home,
            )?;
        }

        Commands::Delete { username, remove_home, force } => {
            manager.delete_user(&username, remove_home, force)?;
        }

        Commands::Modify { username, shell, home, comment, add_groups, remove_groups } => {
            manager.modify_user(
                &username,
                shell.as_deref(),
                home.as_deref(),
                comment.as_deref(),
                add_groups.as_deref(),
                remove_groups.as_deref(),
            )?;
        }

        Commands::Lock { username, reason } => {
            manager.lock_user(&username, reason.as_deref())?;
        }

        Commands::Unlock { username } => {
            manager.unlock_user(&username)?;
        }

        Commands::Password { username, expire } => {
            if expire {
                let output = Command::new("passwd")
                    .args(["-e", &username])
                    .output()?;
                if output.status.success() {
                    println!("{} Password expired for {}", "[+]".green(), username.cyan());
                }
            } else {
                println!("{} Use 'passwd {}' to change password interactively", "[*]".yellow(), username);
            }
        }

        Commands::History { username, limit, failed } => {
            let history = manager.get_login_history(username.as_deref(), limit, failed)?;

            if failed {
                println!("{} Failed Login Attempts:", "[*]".red());
            } else {
                println!("{} Login History:", "[*]".blue());
            }

            for entry in &history {
                println!("  {}", entry);
            }
        }

        Commands::Audit { check, fix } => {
            let findings = manager.audit(check.as_deref(), fix)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                println!("{} Security Audit Results:", "[*]".blue());
                println!("{}", "=".repeat(70));

                for finding in &findings {
                    let severity_color = match finding.severity.as_str() {
                        "CRITICAL" => finding.severity.red().bold(),
                        "HIGH" => finding.severity.red(),
                        "MEDIUM" => finding.severity.yellow(),
                        "LOW" => finding.severity.cyan(),
                        _ => finding.severity.white(),
                    };

                    println!(
                        "  [{}] {} - {}: {}",
                        severity_color,
                        finding.category,
                        finding.user.cyan(),
                        finding.issue
                    );
                    if cli.verbose {
                        println!("    Recommendation: {}", finding.recommendation);
                    }
                }

                println!("{}", "=".repeat(70));
                println!("Total findings: {}", findings.len());
            }
        }

        Commands::Groups { members } => {
            let groups = manager.list_groups(members)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&groups)?);
            } else {
                let table = Table::new(&groups).to_string();
                println!("{}", table);
            }
        }

        Commands::GroupMod { group, add, remove } => {
            if let Some(user) = add {
                let output = Command::new("usermod")
                    .args(["-aG", &group, &user])
                    .output()?;
                if output.status.success() {
                    println!("{} Added {} to group {}", "[+]".green(), user.cyan(), group.cyan());
                }
            }

            if let Some(user) = remove {
                let output = Command::new("gpasswd")
                    .args(["-d", &user, &group])
                    .output()?;
                if output.status.success() {
                    println!("{} Removed {} from group {}", "[+]".green(), user.cyan(), group.cyan());
                }
            }
        }

        Commands::Export { output } => {
            manager.export_users(&output)?;
        }

        Commands::Sessions { detailed } => {
            let sessions = manager.get_sessions()?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
            } else {
                println!("{} Current Sessions:", "[*]".blue());
                if sessions.is_empty() {
                    println!("  No active sessions");
                } else {
                    let table = Table::new(&sessions).to_string();
                    println!("{}", table);
                }
            }
        }
    }

    Ok(())
}
