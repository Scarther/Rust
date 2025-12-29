# G12: Multi-Tool Launcher

## Overview

| Property | Value |
|----------|-------|
| **ID** | G12 |
| **Name** | Multi-Tool Launcher |
| **Difficulty** | Intermediate |
| **Time** | 2-3 hours |
| **Framework** | egui/eframe |

## What You'll Build

A unified GUI that launches and manages multiple security tools:
- Tool configuration panels
- Process management (start/stop/monitor)
- Output aggregation
- Task chaining

```
┌────────────────────────────────────────────────────────────────────────────┐
│  SECURITY TOOLKIT LAUNCHER                                       [_][□][X] │
├────────────────────────────────────────────────────────────────────────────┤
│  ┌─ Available Tools ─────────────────────────────────────────────────────┐ │
│  │  [x] Port Scanner      [ ] Network Enum     [ ] DNS Lookup            │ │
│  │  [ ] Hash Calculator   [x] Web Scanner      [ ] Whois                 │ │
│  │  [ ] File Monitor      [ ] Log Parser       [ ] OSINT Collector       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌─ Tool Configuration ──────────────────────────────────────────────────┐ │
│  │  Port Scanner                                                         │ │
│  │  ────────────────────────────────────────────────────────────────     │ │
│  │  Target: [192.168.1.1__________]  Ports: [1-1000_____]               │ │
│  │  Threads: [100___]  Timeout: [1000ms___]                              │ │
│  │                                                                       │ │
│  │  Web Scanner                                                          │ │
│  │  ────────────────────────────────────────────────────────────────     │ │
│  │  URL: [https://example.com_____]  Wordlist: [common.txt___]          │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  ┌─ Task Chain ──────────────────────────────────────────────────────────┐ │
│  │  1. Port Scanner → 2. Web Scanner → 3. Export Results                 │ │
│  │  [Add Step ▼]                                [Clear Chain]            │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  [▶ Run Selected]  [▶▶ Run Chain]  [⏹ Stop All]                           │
│                                                                            │
│  ┌─ Output ──────────────────────────────────────────────────────────────┐ │
│  │  [12:00:01] Port Scanner: Started                                     │ │
│  │  [12:00:02] Port Scanner: Found 22/tcp open (SSH)                     │ │
│  │  [12:00:03] Port Scanner: Found 80/tcp open (HTTP)                    │ │
│  │  [12:00:04] Port Scanner: Completed - 5 open ports                    │ │
│  │  [12:00:05] Web Scanner: Starting...                                  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  Status: Running Port Scanner (2/3 tools)                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. Tool Registry
Define available tools and their configurations:

```rust
#[derive(Clone)]
struct ToolDefinition {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    executable: &'static str,  // Path or command
    config_fields: &'static [ConfigField],
}

#[derive(Clone)]
struct ConfigField {
    name: &'static str,
    field_type: FieldType,
    default: &'static str,
    required: bool,
}

#[derive(Clone)]
enum FieldType {
    Text,
    Number,
    FilePath,
    Dropdown(&'static [&'static str]),
    Checkbox,
}
```

### 2. Process Management
Run tools as subprocesses and capture output:

```rust
use std::process::{Command, Stdio, Child};
use std::io::{BufRead, BufReader};
use std::sync::mpsc;
use std::thread;

struct RunningTool {
    name: String,
    child: Child,
    output_rx: mpsc::Receiver<String>,
}

impl RunningTool {
    fn spawn(tool: &ToolDefinition, args: Vec<String>) -> Result<Self, String> {
        let mut child = Command::new(tool.executable)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start {}: {}", tool.name, e))?;

        let (tx, rx) = mpsc::channel();

        // Capture stdout in background thread
        if let Some(stdout) = child.stdout.take() {
            let tx = tx.clone();
            let name = tool.name.to_string();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().flatten() {
                    tx.send(format!("[{}] {}", name, line)).ok();
                }
            });
        }

        Ok(RunningTool {
            name: tool.name.to_string(),
            child,
            output_rx: rx,
        })
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_none()
    }

    fn kill(&mut self) {
        self.child.kill().ok();
    }
}
```

### 3. Task Chaining
Execute tools in sequence:

```rust
struct TaskChain {
    steps: Vec<ChainStep>,
    current_step: usize,
    running: bool,
}

struct ChainStep {
    tool_id: String,
    config: HashMap<String, String>,
    completed: bool,
}

impl TaskChain {
    fn advance(&mut self) -> Option<&ChainStep> {
        if self.current_step < self.steps.len() {
            self.steps[self.current_step].completed = true;
            self.current_step += 1;
        }
        self.steps.get(self.current_step)
    }
}
```

---

## Use Cases

### Automated Reconnaissance
1. Port scan target
2. For each open web port, run directory brute force
3. Export combined results

### Continuous Monitoring
1. File integrity check every hour
2. Alert on changes
3. Log all events

### Incident Response
1. Collect system info
2. Dump running processes
3. Check network connections
4. Package for analysis

---

## Exercises

1. Add tool presets (save/load configurations)
2. Implement parallel tool execution
3. Add result export (JSON, CSV, HTML report)
4. Create tool dependency system (tool B needs output from tool A)

---

[← G11 Google Dorking](../G11_Google_Dorking/README.md) | [Next: G13 Recon Dashboard →](../G13_Recon_Dashboard/README.md)
