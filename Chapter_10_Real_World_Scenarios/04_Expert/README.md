# Expert Level: Real World Scenarios

## Overview

Complex security tools that require deep system knowledge, multi-threading, and advanced programming patterns. These scenarios represent tools built by security researchers and senior engineers.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      EXPERT LEVEL SCENARIOS                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   RW-E01: Mini EDR Agent            RW-E02: Malware Sandbox                 │
│   ──────────────────────            ────────────────────                    │
│   Event monitoring                  Process isolation                       │
│   Behavior detection                Syscall tracing                         │
│   Automated response                Network simulation                      │
│                                                                              │
│   RW-E03: C2 Beacon Detector        RW-E04: Vulnerability Scanner           │
│   ──────────────────────            ─────────────────────                   │
│   Traffic analysis                  Service detection                       │
│   Beaconing detection               Version fingerprinting                  │
│   Protocol decoding                 CVE matching                            │
│                                                                              │
│   RW-E05: Incident Response Toolkit                                         │
│   ─────────────────────────────────                                         │
│   Memory acquisition                                                         │
│   Artifact collection                                                        │
│   Timeline generation                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Scenarios

| ID | Name | Time | Skills |
|----|------|------|--------|
| RW-E01 | Mini EDR Agent | 10-15 hours | Events, IPC, response |
| RW-E02 | Malware Sandbox | 15-20 hours | Isolation, tracing |
| RW-E03 | C2 Beacon Detector | 8-12 hours | Traffic analysis |
| RW-E04 | Vulnerability Scanner | 10-15 hours | Protocols, CVE |
| RW-E05 | IR Toolkit | 12-15 hours | Forensics, artifacts |

---

## RW-E01: Mini EDR Agent

### Scenario Background

Build a lightweight Endpoint Detection and Response (EDR) agent that monitors system activity, detects suspicious behaviors, and can take automated response actions.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          MINI EDR ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   PROCESS   │  │    FILE     │  │   NETWORK   │  │   REGISTRY  │        │
│  │   MONITOR   │  │   MONITOR   │  │   MONITOR   │  │   MONITOR   │        │
│  │  (Linux)    │  │  (inotify)  │  │  (netlink)  │  │  (Windows)  │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│         │                │                │                │                │
│         └────────────────┼────────────────┼────────────────┘                │
│                          │                │                                  │
│                          ▼                ▼                                  │
│                    ┌───────────────────────────┐                            │
│                    │      EVENT CORRELATOR     │                            │
│                    │   ─────────────────────   │                            │
│                    │   • Pattern matching      │                            │
│                    │   • Behavior chains       │                            │
│                    │   • Anomaly detection     │                            │
│                    └─────────────┬─────────────┘                            │
│                                  │                                           │
│                    ┌─────────────┴─────────────┐                            │
│                    │     RESPONSE ENGINE       │                            │
│                    │   ─────────────────────   │                            │
│                    │   • Kill process          │                            │
│                    │   • Block network         │                            │
│                    │   • Quarantine file       │                            │
│                    │   • Alert                 │                            │
│                    └───────────────────────────┘                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Code

```rust
//! RW-E01: Mini EDR Agent
//!
//! A lightweight Endpoint Detection and Response agent that monitors
//! system activity, correlates events, and takes automated responses.
//!
//! # Features
//! - Process creation/termination monitoring
//! - File system activity tracking
//! - Network connection monitoring
//! - Behavior-based detection
//! - Automated response actions
//!
//! # Linux Implementation
//! Uses procfs, inotify, and netlink for monitoring.
//! Windows would use ETW/WMI.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════
// CORE DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

/// System event from any monitor
///
/// # Event Normalization
/// Different monitors produce different event types.
/// We normalize them into a common structure for correlation.
#[derive(Debug, Clone)]
pub struct SystemEvent {
    /// Event ID
    pub id: u64,

    /// Event type
    pub event_type: EventType,

    /// Unix timestamp (milliseconds)
    pub timestamp: u64,

    /// Process ID (if applicable)
    pub pid: Option<u32>,

    /// Process name
    pub process_name: Option<String>,

    /// Process path
    pub process_path: Option<String>,

    /// Parent PID
    pub parent_pid: Option<u32>,

    /// Command line arguments
    pub cmdline: Option<String>,

    /// User ID
    pub uid: Option<u32>,

    /// File path (if applicable)
    pub file_path: Option<String>,

    /// Network info (if applicable)
    pub network: Option<NetworkInfo>,

    /// Raw event data
    pub raw: String,
}

/// Types of system events
#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    // Process events
    ProcessCreate,
    ProcessTerminate,
    ProcessInject,

    // File events
    FileCreate,
    FileModify,
    FileDelete,
    FileRename,

    // Network events
    NetworkConnect,
    NetworkListen,
    NetworkDns,

    // Other
    RegistryModify,
    ModuleLoad,
    UserLogon,
}

/// Network connection information
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: String,
}

/// Detection rule
///
/// # Rule Structure
/// Rules define patterns to match and actions to take.
/// They can match single events or sequences.
#[derive(Debug, Clone)]
pub struct DetectionRule {
    /// Rule ID
    pub id: u32,

    /// Rule name
    pub name: String,

    /// Description
    pub description: String,

    /// Severity (1-10)
    pub severity: u8,

    /// Conditions to match
    pub conditions: Vec<RuleCondition>,

    /// Actions to take on match
    pub actions: Vec<ResponseAction>,

    /// Is rule enabled
    pub enabled: bool,

    /// MITRE ATT&CK reference
    pub mitre_id: Option<String>,
}

/// Condition for rule matching
#[derive(Debug, Clone)]
pub struct RuleCondition {
    /// Field to check
    pub field: String,

    /// Operator
    pub operator: ConditionOperator,

    /// Value to compare
    pub value: String,
}

/// Condition operators
#[derive(Debug, Clone)]
pub enum ConditionOperator {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    GreaterThan,
    LessThan,
}

/// Actions the EDR can take
#[derive(Debug, Clone)]
pub enum ResponseAction {
    /// Generate alert
    Alert,
    /// Kill the process
    KillProcess,
    /// Block network connection (via iptables)
    BlockNetwork,
    /// Quarantine file
    QuarantineFile,
    /// Log event for analysis
    Log,
    /// Execute custom command
    ExecuteCommand(String),
}

/// Detection alert
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: u64,
    pub timestamp: u64,
    pub rule_id: u32,
    pub rule_name: String,
    pub severity: u8,
    pub description: String,
    pub events: Vec<SystemEvent>,
    pub mitre_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// PROCESS MONITOR
// ═══════════════════════════════════════════════════════════════════════════

/// Monitors process creation and termination on Linux
///
/// # Implementation
/// Uses /proc filesystem polling. For production:
/// - Use eBPF for lower overhead
/// - Use audit subsystem for reliable events
/// - Use fanotify for file access
pub struct ProcessMonitor {
    /// Known processes
    known_pids: HashMap<u32, ProcessInfo>,

    /// Event sender
    event_tx: mpsc::Sender<SystemEvent>,

    /// Next event ID
    next_event_id: Arc<Mutex<u64>>,

    /// Polling interval
    poll_interval: Duration,

    /// Running flag
    running: Arc<Mutex<bool>>,
}

/// Process information
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub cmdline: String,
    pub ppid: u32,
    pub uid: u32,
    pub start_time: u64,
}

impl ProcessMonitor {
    pub fn new(
        event_tx: mpsc::Sender<SystemEvent>,
        next_event_id: Arc<Mutex<u64>>,
    ) -> Self {
        ProcessMonitor {
            known_pids: HashMap::new(),
            event_tx,
            next_event_id,
            poll_interval: Duration::from_millis(100),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Starts monitoring in background thread
    pub fn start(&mut self) -> thread::JoinHandle<()> {
        // Initial scan
        self.scan_processes();

        let known = self.known_pids.clone();
        let tx = self.event_tx.clone();
        let id_counter = self.next_event_id.clone();
        let interval = self.poll_interval;
        let running = self.running.clone();

        *running.lock().unwrap() = true;

        thread::spawn(move || {
            let mut known_pids = known;

            while *running.lock().unwrap() {
                let current = Self::get_all_pids();

                // Check for new processes
                for pid in &current {
                    if !known_pids.contains_key(pid) {
                        if let Some(info) = Self::get_process_info(*pid) {
                            // New process detected
                            let mut id = id_counter.lock().unwrap();
                            *id += 1;

                            let event = SystemEvent {
                                id: *id,
                                event_type: EventType::ProcessCreate,
                                timestamp: Self::now_ms(),
                                pid: Some(info.pid),
                                process_name: Some(info.name.clone()),
                                process_path: Some(info.exe.clone()),
                                parent_pid: Some(info.ppid),
                                cmdline: Some(info.cmdline.clone()),
                                uid: Some(info.uid),
                                file_path: None,
                                network: None,
                                raw: format!("{:?}", info),
                            };

                            let _ = tx.send(event);
                            known_pids.insert(*pid, info);
                        }
                    }
                }

                // Check for terminated processes
                let terminated: Vec<u32> = known_pids
                    .keys()
                    .filter(|pid| !current.contains(pid))
                    .cloned()
                    .collect();

                for pid in terminated {
                    if let Some(info) = known_pids.remove(&pid) {
                        let mut id = id_counter.lock().unwrap();
                        *id += 1;

                        let event = SystemEvent {
                            id: *id,
                            event_type: EventType::ProcessTerminate,
                            timestamp: Self::now_ms(),
                            pid: Some(info.pid),
                            process_name: Some(info.name),
                            process_path: Some(info.exe),
                            parent_pid: Some(info.ppid),
                            cmdline: Some(info.cmdline),
                            uid: Some(info.uid),
                            file_path: None,
                            network: None,
                            raw: String::new(),
                        };

                        let _ = tx.send(event);
                    }
                }

                thread::sleep(interval);
            }
        })
    }

    /// Scans current processes
    fn scan_processes(&mut self) {
        for pid in Self::get_all_pids() {
            if let Some(info) = Self::get_process_info(pid) {
                self.known_pids.insert(pid, info);
            }
        }
    }

    /// Gets all PIDs from /proc
    fn get_all_pids() -> Vec<u32> {
        fs::read_dir("/proc")
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets process info from /proc/<pid>
    fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        let proc_path = format!("/proc/{}", pid);

        // Read comm (process name)
        let name = fs::read_to_string(format!("{}/comm", proc_path))
            .ok()?
            .trim()
            .to_string();

        // Read exe symlink
        let exe = fs::read_link(format!("{}/exe", proc_path))
            .ok()?
            .to_string_lossy()
            .to_string();

        // Read cmdline
        let cmdline = fs::read_to_string(format!("{}/cmdline", proc_path))
            .ok()?
            .replace('\0', " ")
            .trim()
            .to_string();

        // Read status for ppid and uid
        let status = fs::read_to_string(format!("{}/status", proc_path)).ok()?;

        let mut ppid = 0;
        let mut uid = 0;

        for line in status.lines() {
            if line.starts_with("PPid:") {
                ppid = line.split_whitespace().nth(1)?.parse().ok()?;
            } else if line.starts_with("Uid:") {
                uid = line.split_whitespace().nth(1)?.parse().ok()?;
            }
        }

        Some(ProcessInfo {
            pid,
            name,
            exe,
            cmdline,
            ppid,
            uid,
            start_time: Self::now_ms(),
        })
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DETECTION ENGINE
// ═══════════════════════════════════════════════════════════════════════════

/// Correlates events and detects threats
///
/// # Detection Strategies
/// 1. Single-event matching (simple rules)
/// 2. Event sequences (attack chains)
/// 3. Anomaly detection (deviation from baseline)
/// 4. Threshold-based (frequency analysis)
pub struct DetectionEngine {
    /// Detection rules
    rules: Vec<DetectionRule>,

    /// Event history for correlation
    event_history: VecDeque<SystemEvent>,

    /// Maximum history size
    max_history: usize,

    /// Alert sender
    alert_tx: mpsc::Sender<Alert>,

    /// Next alert ID
    next_alert_id: u64,
}

impl DetectionEngine {
    pub fn new(alert_tx: mpsc::Sender<Alert>) -> Self {
        DetectionEngine {
            rules: Self::default_rules(),
            event_history: VecDeque::new(),
            max_history: 10000,
            alert_tx,
            next_alert_id: 1,
        }
    }

    /// Processes an event and checks for matches
    pub fn process_event(&mut self, event: SystemEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Add to history
        self.event_history.push_back(event.clone());
        if self.event_history.len() > self.max_history {
            self.event_history.pop_front();
        }

        // Check each rule
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if self.matches_rule(rule, &event) {
                let alert = Alert {
                    id: self.next_alert_id,
                    timestamp: event.timestamp,
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    description: rule.description.clone(),
                    events: vec![event.clone()],
                    mitre_id: rule.mitre_id.clone(),
                };

                self.next_alert_id += 1;
                let _ = self.alert_tx.send(alert.clone());
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Checks if event matches rule conditions
    fn matches_rule(&self, rule: &DetectionRule, event: &SystemEvent) -> bool {
        for condition in &rule.conditions {
            if !self.evaluate_condition(condition, event) {
                return false;
            }
        }
        true
    }

    /// Evaluates a single condition
    fn evaluate_condition(&self, condition: &RuleCondition, event: &SystemEvent) -> bool {
        let field_value = match condition.field.as_str() {
            "event_type" => format!("{:?}", event.event_type),
            "process_name" => event.process_name.clone().unwrap_or_default(),
            "process_path" => event.process_path.clone().unwrap_or_default(),
            "cmdline" => event.cmdline.clone().unwrap_or_default(),
            "file_path" => event.file_path.clone().unwrap_or_default(),
            "uid" => event.uid.map(|u| u.to_string()).unwrap_or_default(),
            _ => return false,
        };

        match condition.operator {
            ConditionOperator::Equals => field_value == condition.value,
            ConditionOperator::Contains => field_value.contains(&condition.value),
            ConditionOperator::StartsWith => field_value.starts_with(&condition.value),
            ConditionOperator::EndsWith => field_value.ends_with(&condition.value),
            ConditionOperator::Regex => {
                regex::Regex::new(&condition.value)
                    .map(|re| re.is_match(&field_value))
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Default detection rules
    fn default_rules() -> Vec<DetectionRule> {
        vec![
            // Suspicious process spawns
            DetectionRule {
                id: 1001,
                name: "Suspicious Shell Spawn".to_string(),
                description: "Shell spawned from web server process".to_string(),
                severity: 8,
                conditions: vec![
                    RuleCondition {
                        field: "event_type".to_string(),
                        operator: ConditionOperator::Equals,
                        value: "ProcessCreate".to_string(),
                    },
                    RuleCondition {
                        field: "process_name".to_string(),
                        operator: ConditionOperator::Regex,
                        value: r"^(bash|sh|dash|zsh)$".to_string(),
                    },
                ],
                actions: vec![ResponseAction::Alert, ResponseAction::Log],
                enabled: true,
                mitre_id: Some("T1059".to_string()),
            },

            // Reverse shell patterns
            DetectionRule {
                id: 1002,
                name: "Potential Reverse Shell".to_string(),
                description: "Process with network redirect pattern".to_string(),
                severity: 9,
                conditions: vec![
                    RuleCondition {
                        field: "cmdline".to_string(),
                        operator: ConditionOperator::Regex,
                        value: r"(nc|ncat|netcat).*-e.*(sh|bash)".to_string(),
                    },
                ],
                actions: vec![ResponseAction::Alert, ResponseAction::KillProcess],
                enabled: true,
                mitre_id: Some("T1059.004".to_string()),
            },

            // Crypto mining
            DetectionRule {
                id: 1003,
                name: "Cryptocurrency Miner".to_string(),
                description: "Known crypto mining process detected".to_string(),
                severity: 6,
                conditions: vec![
                    RuleCondition {
                        field: "process_name".to_string(),
                        operator: ConditionOperator::Regex,
                        value: r"(xmrig|minerd|cpuminer)".to_string(),
                    },
                ],
                actions: vec![ResponseAction::Alert, ResponseAction::KillProcess],
                enabled: true,
                mitre_id: Some("T1496".to_string()),
            },

            // Persistence via cron
            DetectionRule {
                id: 1004,
                name: "Cron Modification".to_string(),
                description: "Modification to cron files".to_string(),
                severity: 5,
                conditions: vec![
                    RuleCondition {
                        field: "file_path".to_string(),
                        operator: ConditionOperator::Contains,
                        value: "/etc/cron".to_string(),
                    },
                ],
                actions: vec![ResponseAction::Alert, ResponseAction::Log],
                enabled: true,
                mitre_id: Some("T1053.003".to_string()),
            },
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RESPONSE ENGINE
// ═══════════════════════════════════════════════════════════════════════════

/// Executes response actions
pub struct ResponseEngine {
    /// Quarantine directory
    quarantine_dir: String,

    /// Blocked IPs
    blocked_ips: Vec<IpAddr>,

    /// Killed processes
    killed_pids: Vec<u32>,
}

impl ResponseEngine {
    pub fn new(quarantine_dir: &str) -> Self {
        ResponseEngine {
            quarantine_dir: quarantine_dir.to_string(),
            blocked_ips: Vec::new(),
            killed_pids: Vec::new(),
        }
    }

    /// Executes actions for an alert
    pub fn execute_actions(&mut self, alert: &Alert, actions: &[ResponseAction]) {
        for action in actions {
            match action {
                ResponseAction::Alert => {
                    self.send_alert(alert);
                }
                ResponseAction::KillProcess => {
                    if let Some(pid) = alert.events.first().and_then(|e| e.pid) {
                        self.kill_process(pid);
                    }
                }
                ResponseAction::BlockNetwork => {
                    // Would block IPs from network events
                }
                ResponseAction::QuarantineFile => {
                    if let Some(path) = alert.events.first().and_then(|e| e.file_path.clone()) {
                        self.quarantine_file(&path);
                    }
                }
                ResponseAction::Log => {
                    self.log_alert(alert);
                }
                ResponseAction::ExecuteCommand(cmd) => {
                    self.execute_command(cmd);
                }
            }
        }
    }

    fn send_alert(&self, alert: &Alert) {
        println!("[ALERT] {} - {} (Severity: {})",
            alert.rule_name,
            alert.description,
            alert.severity
        );
    }

    fn kill_process(&mut self, pid: u32) {
        println!("[RESPONSE] Killing process {}", pid);

        let output = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                self.killed_pids.push(pid);
                println!("[RESPONSE] Process {} killed successfully", pid);
            }
        }
    }

    fn quarantine_file(&self, path: &str) {
        println!("[RESPONSE] Quarantining file: {}", path);

        let filename = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let quarantine_path = format!("{}/{}.quarantine", self.quarantine_dir, filename);

        if let Err(e) = fs::rename(path, &quarantine_path) {
            eprintln!("[ERROR] Failed to quarantine: {}", e);
        } else {
            println!("[RESPONSE] File quarantined to: {}", quarantine_path);
        }
    }

    fn log_alert(&self, alert: &Alert) {
        // In production, send to SIEM
        println!("[LOG] Alert {}: {} at {}",
            alert.id,
            alert.rule_name,
            alert.timestamp
        );
    }

    fn execute_command(&self, cmd: &str) {
        println!("[RESPONSE] Executing: {}", cmd);
        let _ = Command::new("sh")
            .args(["-c", cmd])
            .output();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN EDR AGENT
// ═══════════════════════════════════════════════════════════════════════════

/// Main EDR agent coordinator
pub struct EdrAgent {
    detection: DetectionEngine,
    response: ResponseEngine,
    event_rx: mpsc::Receiver<SystemEvent>,
    _alert_rx: mpsc::Receiver<Alert>,
}

impl EdrAgent {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let (alert_tx, alert_rx) = mpsc::channel();

        // Start process monitor
        let event_id = Arc::new(Mutex::new(0u64));
        let mut proc_monitor = ProcessMonitor::new(event_tx, event_id);
        proc_monitor.start();

        EdrAgent {
            detection: DetectionEngine::new(alert_tx),
            response: ResponseEngine::new("/var/quarantine"),
            event_rx,
            _alert_rx: alert_rx,
        }
    }

    /// Main event processing loop
    pub fn run(&mut self) {
        println!("[*] EDR Agent started");
        println!("[*] Monitoring system events...\n");

        loop {
            if let Ok(event) = self.event_rx.recv_timeout(Duration::from_millis(100)) {
                // Log event
                println!("[EVENT] {:?}: {} (PID: {:?})",
                    event.event_type,
                    event.process_name.as_deref().unwrap_or("unknown"),
                    event.pid
                );

                // Process through detection engine
                let alerts = self.detection.process_event(event);

                // Execute responses
                for alert in alerts {
                    // Get actions from matching rule
                    let actions = self.detection.rules
                        .iter()
                        .find(|r| r.id == alert.rule_id)
                        .map(|r| r.actions.clone())
                        .unwrap_or_default();

                    self.response.execute_actions(&alert, &actions);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║                    MINI EDR AGENT                               ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Check for root
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("[!] Warning: Running without root may limit monitoring capabilities");
    }

    let mut agent = EdrAgent::new();
    agent.run();
}
```

### Key Concepts

#### 1. Event Correlation
```
Single Event → Detection
    e.g., "bash spawned from apache"

Event Sequence → Attack Chain
    e.g., "download → chmod → execute → connect out"

Baseline Deviation → Anomaly
    e.g., "process X never connected to internet before"
```

#### 2. Response Actions
```
┌─────────────────────────────────────────────────────────────────┐
│                    RESPONSE HIERARCHY                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Alert Only       ─►  Log for analysis, no intervention          │
│       ↓                                                          │
│  Contain          ─►  Network isolation, block connections       │
│       ↓                                                          │
│  Terminate        ─►  Kill process, quarantine files             │
│       ↓                                                          │
│  Isolate Host     ─►  Block all network, alert SOC               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Exercises

1. **Add File Monitor**: Implement inotify-based file monitoring
2. **Add Network Monitor**: Use /proc/net/tcp for connection monitoring
3. **Add ML Detection**: Implement simple anomaly detection
4. **Add MITRE Mapping**: Map all detections to ATT&CK techniques
5. **Add Remote Management**: API for querying agent status

---

## Additional Expert Scenarios

See the following for complete implementations:

- [RW-E02: Malware Sandbox](./RW-E02_Sandbox/) - Process isolation and analysis
- [RW-E03: C2 Detector](./RW-E03_C2_Detector/) - Beacon traffic analysis
- [RW-E04: Vuln Scanner](./RW-E04_Vuln_Scanner/) - Service fingerprinting
- [RW-E05: IR Toolkit](./RW-E05_IR_Toolkit/) - Incident response automation

---

**← Previous:** [Advanced Scenarios](../03_Advanced/README.md) | **Back to:** [Chapter 10 Overview](../README.md)
