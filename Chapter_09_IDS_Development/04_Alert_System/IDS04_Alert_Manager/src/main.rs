//! IDS04_Alert_Manager - Alert Generation and Management System
//!
//! This module implements a comprehensive alert management system for IDS:
//!
//! - **Alert Generation**: Create structured alerts from detection events
//! - **Deduplication**: Prevent alert fatigue from repeated events
//! - **Correlation**: Group related alerts into incidents
//! - **Prioritization**: Rank alerts by severity and confidence
//! - **Persistence**: Store alerts in SQLite database
//! - **Queuing**: Async alert processing with rate limiting
//!
//! # Alert Lifecycle
//! 1. Detection event triggers alert creation
//! 2. Alert is deduplicated against recent alerts
//! 3. Alert is correlated with related events
//! 4. Alert is prioritized and queued
//! 5. Alert is persisted and dispatched to handlers
//!
//! # IDS Alert Concepts
//! - **Severity**: Impact level (critical, high, medium, low, info)
//! - **Confidence**: Detection accuracy (0-100%)
//! - **Classification**: Attack type categorization
//! - **Context**: Network/system context when alert occurred

use async_channel::{Receiver, Sender};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use dashmap::DashMap;
use priority_queue::PriorityQueue;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum AlertError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Channel error: {0}")]
    ChannelError(String),

    #[error("Alert not found: {0}")]
    NotFound(String),

    #[error("Invalid severity: {0}")]
    InvalidSeverity(String),
}

// =============================================================================
// Alert Severity
// =============================================================================

/// Alert severity levels (following CVSS-like scale)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Critical - Active exploitation, immediate response required
    Critical = 5,
    /// High - Significant threat, urgent response needed
    High = 4,
    /// Medium - Moderate threat, timely response
    Medium = 3,
    /// Low - Minor threat, routine response
    Low = 2,
    /// Informational - For auditing/logging only
    Info = 1,
}

impl Severity {
    pub fn from_str(s: &str) -> Result<Self, AlertError> {
        match s.to_lowercase().as_str() {
            "critical" | "crit" | "5" => Ok(Severity::Critical),
            "high" | "4" => Ok(Severity::High),
            "medium" | "med" | "3" => Ok(Severity::Medium),
            "low" | "2" => Ok(Severity::Low),
            "info" | "informational" | "1" => Ok(Severity::Info),
            _ => Err(AlertError::InvalidSeverity(s.to_string())),
        }
    }

    pub fn as_color(&self) -> colored::Color {
        match self {
            Severity::Critical => colored::Color::Red,
            Severity::High => colored::Color::BrightRed,
            Severity::Medium => colored::Color::Yellow,
            Severity::Low => colored::Color::Blue,
            Severity::Info => colored::Color::White,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// =============================================================================
// Alert Classification
// =============================================================================

/// Attack classification types (following Snort classification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Classification {
    // Network-based attacks
    AttemptedAdmin,
    AttemptedUser,
    AttemptedDos,
    AttemptedRecon,
    SuccessfulAdmin,
    SuccessfulUser,
    SuccessfulDos,
    SuccessfulRecon,

    // Web attacks
    WebApplicationAttack,
    WebApplicationActivity,

    // Malware
    TrojanActivity,
    MalwareCommand,
    MalwareDownload,
    PotentiallyUnwanted,

    // Policy violations
    PolicyViolation,
    SensitiveData,
    UnusualActivity,

    // Protocol anomalies
    ProtocolAnomaly,
    BadTraffic,

    // Misc
    MiscAttack,
    MiscActivity,
    NotSuspicious,

    // Custom
    Custom(String),
}

impl Default for Classification {
    fn default() -> Self {
        Classification::MiscActivity
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Classification::Custom(s) => write!(f, "{}", s),
            other => write!(f, "{:?}", other),
        }
    }
}

// =============================================================================
// Network Context
// =============================================================================

/// Network context for the alert
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkContext {
    /// Source IP address
    pub src_ip: Option<IpAddr>,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination IP address
    pub dst_ip: Option<IpAddr>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Protocol (TCP, UDP, ICMP, etc.)
    pub protocol: Option<String>,
    /// Interface where traffic was captured
    pub interface: Option<String>,
    /// Direction (inbound, outbound, internal)
    pub direction: Option<String>,
    /// Packet/flow ID
    pub flow_id: Option<u64>,
    /// Bytes in flow
    pub bytes: Option<u64>,
    /// Packets in flow
    pub packets: Option<u64>,
}

// =============================================================================
// Alert Structure
// =============================================================================

/// Alert status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
    Escalated,
}

impl Default for AlertStatus {
    fn default() -> Self {
        AlertStatus::New
    }
}

/// Complete alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert identifier
    pub id: Uuid,
    /// Creation timestamp
    pub timestamp: DateTime<Utc>,
    /// Alert severity
    pub severity: Severity,
    /// Detection confidence (0-100)
    pub confidence: u8,
    /// Alert message/title
    pub message: String,
    /// Detailed description
    pub description: Option<String>,
    /// Classification type
    pub classification: Classification,
    /// Rule/signature ID that triggered alert
    pub signature_id: Option<u32>,
    /// Rule/signature name
    pub signature_name: Option<String>,
    /// Network context
    pub network: NetworkContext,
    /// Raw payload that triggered alert (hex encoded)
    pub payload: Option<String>,
    /// Alert status
    pub status: AlertStatus,
    /// Count of deduplicated alerts
    pub count: u32,
    /// First occurrence timestamp (for deduplicated alerts)
    pub first_seen: DateTime<Utc>,
    /// Last occurrence timestamp
    pub last_seen: DateTime<Utc>,
    /// Correlated incident ID (if grouped)
    pub incident_id: Option<Uuid>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl Alert {
    /// Create a new alert
    pub fn new(severity: Severity, message: impl Into<String>) -> Self {
        let now = Utc::now();
        Alert {
            id: Uuid::new_v4(),
            timestamp: now,
            severity,
            confidence: 100,
            message: message.into(),
            description: None,
            classification: Classification::default(),
            signature_id: None,
            signature_name: None,
            network: NetworkContext::default(),
            payload: None,
            status: AlertStatus::New,
            count: 1,
            first_seen: now,
            last_seen: now,
            incident_id: None,
            metadata: HashMap::new(),
            tags: Vec::new(),
        }
    }

    /// Builder pattern methods
    pub fn with_classification(mut self, classification: Classification) -> Self {
        self.classification = classification;
        self
    }

    pub fn with_signature(mut self, id: u32, name: impl Into<String>) -> Self {
        self.signature_id = Some(id);
        self.signature_name = Some(name.into());
        self
    }

    pub fn with_network(mut self, network: NetworkContext) -> Self {
        self.network = network;
        self
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_payload(mut self, payload: &[u8]) -> Self {
        self.payload = Some(hex::encode(payload));
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Calculate priority score (for queue ordering)
    pub fn priority_score(&self) -> u32 {
        let severity_score = (self.severity as u32) * 20;
        let confidence_score = self.confidence as u32;
        let count_bonus = (self.count.min(10)) * 2;

        severity_score + confidence_score + count_bonus
    }

    /// Generate deduplication key
    pub fn dedup_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.signature_id.unwrap_or(0),
            self.network.src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            self.network.dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            self.network.dst_port.unwrap_or(0),
            self.classification
        )
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} - {} (SID: {:?}, Confidence: {}%)",
            self.severity,
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            self.message,
            self.signature_id,
            self.confidence
        )
    }
}

// =============================================================================
// Alert Queue
// =============================================================================

/// Priority for queue ordering (higher = more urgent)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct AlertPriority(u32);

impl Ord for AlertPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for AlertPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority-based alert queue
pub struct AlertQueue {
    queue: RwLock<PriorityQueue<Uuid, AlertPriority>>,
    alerts: DashMap<Uuid, Alert>,
    max_size: usize,
}

impl AlertQueue {
    pub fn new(max_size: usize) -> Self {
        AlertQueue {
            queue: RwLock::new(PriorityQueue::new()),
            alerts: DashMap::new(),
            max_size,
        }
    }

    /// Add alert to queue
    pub fn push(&self, alert: Alert) -> bool {
        let id = alert.id;
        let priority = AlertPriority(alert.priority_score());

        // Check capacity
        {
            let queue = self.queue.read().unwrap();
            if queue.len() >= self.max_size {
                // Check if new alert has higher priority than lowest
                if let Some((_, lowest_priority)) = queue.peek() {
                    if priority <= *lowest_priority {
                        return false;
                    }
                }
            }
        }

        // Add to queue
        self.alerts.insert(id, alert);
        let mut queue = self.queue.write().unwrap();
        queue.push(id, priority);

        // Remove lowest priority if over capacity
        while queue.len() > self.max_size {
            if let Some((removed_id, _)) = queue.pop() {
                self.alerts.remove(&removed_id);
            }
        }

        true
    }

    /// Get highest priority alert
    pub fn pop(&self) -> Option<Alert> {
        let mut queue = self.queue.write().unwrap();
        if let Some((id, _)) = queue.pop() {
            self.alerts.remove(&id).map(|(_, v)| v)
        } else {
            None
        }
    }

    /// Peek at highest priority alert
    pub fn peek(&self) -> Option<Alert> {
        let queue = self.queue.read().unwrap();
        if let Some((id, _)) = queue.peek() {
            self.alerts.get(id).map(|r| r.value().clone())
        } else {
            None
        }
    }

    /// Get queue length
    pub fn len(&self) -> usize {
        self.queue.read().unwrap().len()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.read().unwrap().is_empty()
    }
}

// =============================================================================
// Alert Deduplicator
// =============================================================================

/// Deduplicates similar alerts within a time window
pub struct AlertDeduplicator {
    /// Recent alerts by dedup key
    recent: DashMap<String, (Alert, DateTime<Utc>)>,
    /// Deduplication window
    window: Duration,
}

impl AlertDeduplicator {
    pub fn new(window_seconds: i64) -> Self {
        AlertDeduplicator {
            recent: DashMap::new(),
            window: Duration::seconds(window_seconds),
        }
    }

    /// Check if alert is duplicate and either merge or return it
    pub fn check(&self, mut alert: Alert) -> Option<Alert> {
        let key = alert.dedup_key();
        let now = Utc::now();

        // Clean old entries
        self.cleanup(now);

        // Check for existing
        if let Some(mut entry) = self.recent.get_mut(&key) {
            let (existing, _) = entry.value_mut();

            // Update existing alert
            existing.count += 1;
            existing.last_seen = now;

            // Keep highest severity
            if alert.severity > existing.severity {
                existing.severity = alert.severity;
            }

            // Keep highest confidence
            if alert.confidence > existing.confidence {
                existing.confidence = alert.confidence;
            }

            debug!("Deduplicated alert, count now: {}", existing.count);
            None
        } else {
            // New unique alert
            alert.first_seen = now;
            alert.last_seen = now;
            self.recent.insert(key, (alert.clone(), now));
            Some(alert)
        }
    }

    /// Clean expired entries
    fn cleanup(&self, now: DateTime<Utc>) {
        let cutoff = now - self.window;
        self.recent.retain(|_, (_, timestamp)| *timestamp > cutoff);
    }

    /// Get current dedup stats
    pub fn stats(&self) -> (usize, u32) {
        let total_count: u32 = self.recent.iter()
            .map(|r| r.value().0.count)
            .sum();
        (self.recent.len(), total_count)
    }

    /// Flush all deduplicated alerts
    pub fn flush(&self) -> Vec<Alert> {
        let alerts: Vec<_> = self.recent.iter()
            .map(|r| r.value().0.clone())
            .collect();
        self.recent.clear();
        alerts
    }
}

// =============================================================================
// Alert Correlator
// =============================================================================

/// Incident (group of correlated alerts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    pub alert_count: u32,
    pub alert_ids: Vec<Uuid>,
    pub status: AlertStatus,
    pub tags: Vec<String>,
}

/// Correlation rule
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub name: String,
    pub description: String,
    /// Minimum alerts to trigger correlation
    pub min_alerts: u32,
    /// Time window for correlation
    pub window_seconds: i64,
    /// Severity threshold
    pub min_severity: Severity,
    /// Match function
    pub matcher: Arc<dyn Fn(&Alert, &Alert) -> bool + Send + Sync>,
}

/// Correlates related alerts into incidents
pub struct AlertCorrelator {
    rules: Vec<CorrelationRule>,
    incidents: DashMap<Uuid, Incident>,
    /// Alerts pending correlation
    pending: DashMap<String, Vec<Alert>>,
}

impl AlertCorrelator {
    pub fn new() -> Self {
        let mut correlator = AlertCorrelator {
            rules: Vec::new(),
            incidents: DashMap::new(),
            pending: DashMap::new(),
        };

        // Add default correlation rules
        correlator.add_default_rules();
        correlator
    }

    fn add_default_rules(&mut self) {
        // Same source IP attacking multiple targets
        self.rules.push(CorrelationRule {
            name: "Multi-Target Attack".to_string(),
            description: "Same source attacking multiple destinations".to_string(),
            min_alerts: 3,
            window_seconds: 300,
            min_severity: Severity::Low,
            matcher: Arc::new(|a, b| {
                a.network.src_ip.is_some() &&
                a.network.src_ip == b.network.src_ip &&
                a.network.dst_ip != b.network.dst_ip
            }),
        });

        // Same target being attacked from multiple sources
        self.rules.push(CorrelationRule {
            name: "Multi-Source Attack".to_string(),
            description: "Multiple sources attacking same target".to_string(),
            min_alerts: 5,
            window_seconds: 300,
            min_severity: Severity::Low,
            matcher: Arc::new(|a, b| {
                a.network.dst_ip.is_some() &&
                a.network.dst_ip == b.network.dst_ip &&
                a.network.src_ip != b.network.src_ip
            }),
        });

        // Attack chain (multiple stages)
        self.rules.push(CorrelationRule {
            name: "Attack Chain".to_string(),
            description: "Possible multi-stage attack".to_string(),
            min_alerts: 3,
            window_seconds: 600,
            min_severity: Severity::Medium,
            matcher: Arc::new(|a, b| {
                a.network.src_ip.is_some() &&
                a.network.src_ip == b.network.src_ip &&
                a.network.dst_ip == b.network.dst_ip
            }),
        });
    }

    /// Add a custom correlation rule
    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    /// Process alert for correlation
    pub fn correlate(&self, alert: Alert) -> Option<Uuid> {
        let mut matched_incident: Option<Uuid> = None;

        for rule in &self.rules {
            if alert.severity < rule.min_severity {
                continue;
            }

            let key = format!("{}:{:?}:{:?}",
                rule.name,
                alert.network.src_ip,
                alert.network.dst_ip);

            let mut pending_alerts = self.pending.entry(key.clone())
                .or_insert_with(Vec::new);

            // Clean old alerts
            let cutoff = Utc::now() - Duration::seconds(rule.window_seconds);
            pending_alerts.retain(|a| a.timestamp > cutoff);

            // Check for matches
            let matches: Vec<_> = pending_alerts.iter()
                .filter(|a| (rule.matcher)(a, &alert))
                .collect();

            if matches.len() >= (rule.min_alerts - 1) as usize {
                // Create or update incident
                let incident_id = if let Some(id) = matched_incident {
                    id
                } else {
                    let id = Uuid::new_v4();
                    let incident = Incident {
                        id,
                        created: Utc::now(),
                        updated: Utc::now(),
                        severity: alert.severity,
                        title: format!("{}: {}", rule.name, alert.message),
                        description: Some(rule.description.clone()),
                        alert_count: matches.len() as u32 + 1,
                        alert_ids: matches.iter().map(|a| a.id).chain(std::iter::once(alert.id)).collect(),
                        status: AlertStatus::New,
                        tags: vec![rule.name.clone()],
                    };
                    self.incidents.insert(id, incident);
                    id
                };

                matched_incident = Some(incident_id);
                info!("Alert correlated into incident: {}", incident_id);
            }

            pending_alerts.push(alert.clone());
        }

        matched_incident
    }

    /// Get incident by ID
    pub fn get_incident(&self, id: &Uuid) -> Option<Incident> {
        self.incidents.get(id).map(|r| r.value().clone())
    }

    /// List all active incidents
    pub fn list_incidents(&self) -> Vec<Incident> {
        self.incidents.iter()
            .map(|r| r.value().clone())
            .collect()
    }
}

impl Default for AlertCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Alert Database
// =============================================================================

/// SQLite-based alert persistence
pub struct AlertDatabase {
    conn: Arc<AsyncMutex<Connection>>,
}

impl AlertDatabase {
    /// Open or create database
    pub fn open(path: &PathBuf) -> Result<Self, AlertError> {
        let conn = Connection::open(path)?;

        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                message TEXT NOT NULL,
                description TEXT,
                classification TEXT NOT NULL,
                signature_id INTEGER,
                signature_name TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                payload TEXT,
                status INTEGER NOT NULL,
                count INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                incident_id TEXT,
                metadata TEXT,
                tags TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created TEXT NOT NULL,
                updated TEXT NOT NULL,
                severity INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                alert_count INTEGER NOT NULL,
                alert_ids TEXT,
                status INTEGER NOT NULL,
                tags TEXT
            )",
            [],
        )?;

        info!("Opened alert database: {}", path.display());

        Ok(AlertDatabase {
            conn: Arc::new(AsyncMutex::new(conn)),
        })
    }

    /// Open in-memory database (for testing)
    pub fn open_memory() -> Result<Self, AlertError> {
        let conn = Connection::open_in_memory()?;

        // Create same tables as file-based
        conn.execute(
            "CREATE TABLE alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                message TEXT NOT NULL,
                description TEXT,
                classification TEXT NOT NULL,
                signature_id INTEGER,
                signature_name TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                payload TEXT,
                status INTEGER NOT NULL,
                count INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                incident_id TEXT,
                metadata TEXT,
                tags TEXT
            )",
            [],
        )?;

        Ok(AlertDatabase {
            conn: Arc::new(AsyncMutex::new(conn)),
        })
    }

    /// Save alert to database
    pub async fn save_alert(&self, alert: &Alert) -> Result<(), AlertError> {
        let conn = self.conn.lock().await;

        conn.execute(
            "INSERT OR REPLACE INTO alerts (
                id, timestamp, severity, confidence, message, description,
                classification, signature_id, signature_name, src_ip, src_port,
                dst_ip, dst_port, protocol, payload, status, count,
                first_seen, last_seen, incident_id, metadata, tags
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
            params![
                alert.id.to_string(),
                alert.timestamp.to_rfc3339(),
                alert.severity as i32,
                alert.confidence as i32,
                alert.message,
                alert.description,
                alert.classification.to_string(),
                alert.signature_id,
                alert.signature_name,
                alert.network.src_ip.map(|ip| ip.to_string()),
                alert.network.src_port.map(|p| p as i32),
                alert.network.dst_ip.map(|ip| ip.to_string()),
                alert.network.dst_port.map(|p| p as i32),
                alert.network.protocol,
                alert.payload,
                alert.status as i32,
                alert.count as i32,
                alert.first_seen.to_rfc3339(),
                alert.last_seen.to_rfc3339(),
                alert.incident_id.map(|id| id.to_string()),
                serde_json::to_string(&alert.metadata)?,
                serde_json::to_string(&alert.tags)?,
            ],
        )?;

        Ok(())
    }

    /// Get alert by ID
    pub async fn get_alert(&self, id: &Uuid) -> Result<Option<Alert>, AlertError> {
        let conn = self.conn.lock().await;

        let mut stmt = conn.prepare(
            "SELECT * FROM alerts WHERE id = ?1"
        )?;

        let result = stmt.query_row(params![id.to_string()], |row| {
            self.row_to_alert(row)
        });

        match result {
            Ok(alert) => Ok(Some(alert)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AlertError::DatabaseError(e)),
        }
    }

    /// Query alerts
    pub async fn query_alerts(
        &self,
        min_severity: Option<Severity>,
        status: Option<AlertStatus>,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Alert>, AlertError> {
        let conn = self.conn.lock().await;

        let mut sql = "SELECT * FROM alerts WHERE 1=1".to_string();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(sev) = min_severity {
            sql.push_str(" AND severity >= ?");
            params.push(Box::new(sev as i32));
        }

        if let Some(st) = status {
            sql.push_str(" AND status = ?");
            params.push(Box::new(st as i32));
        }

        if let Some(ip) = src_ip {
            sql.push_str(" AND src_ip = ?");
            params.push(Box::new(ip.to_string()));
        }

        if let Some(ip) = dst_ip {
            sql.push_str(" AND dst_ip = ?");
            params.push(Box::new(ip.to_string()));
        }

        sql.push_str(" ORDER BY timestamp DESC LIMIT ?");
        params.push(Box::new(limit as i32));

        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let alerts = stmt.query_map(param_refs.as_slice(), |row| {
            self.row_to_alert(row)
        })?;

        let mut result = Vec::new();
        for alert in alerts {
            result.push(alert?);
        }

        Ok(result)
    }

    /// Get alert statistics
    pub async fn get_stats(&self) -> Result<AlertStats, AlertError> {
        let conn = self.conn.lock().await;

        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts",
            [],
            |row| row.get(0)
        )?;

        let by_severity: Vec<(i32, i64)> = {
            let mut stmt = conn.prepare(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            )?;
            stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?.filter_map(|r| r.ok()).collect()
        };

        let new_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE status = 0",
            [],
            |row| row.get(0)
        )?;

        Ok(AlertStats {
            total_alerts: total as u64,
            new_alerts: new_count as u64,
            critical_count: by_severity.iter().find(|(s, _)| *s == 5).map(|(_, c)| *c as u64).unwrap_or(0),
            high_count: by_severity.iter().find(|(s, _)| *s == 4).map(|(_, c)| *c as u64).unwrap_or(0),
            medium_count: by_severity.iter().find(|(s, _)| *s == 3).map(|(_, c)| *c as u64).unwrap_or(0),
            low_count: by_severity.iter().find(|(s, _)| *s == 2).map(|(_, c)| *c as u64).unwrap_or(0),
            info_count: by_severity.iter().find(|(s, _)| *s == 1).map(|(_, c)| *c as u64).unwrap_or(0),
        })
    }

    fn row_to_alert(&self, row: &rusqlite::Row) -> Result<Alert, rusqlite::Error> {
        let id_str: String = row.get(0)?;
        let timestamp_str: String = row.get(1)?;
        let severity_int: i32 = row.get(2)?;
        let first_seen_str: String = row.get(17)?;
        let last_seen_str: String = row.get(18)?;

        Ok(Alert {
            id: Uuid::parse_str(&id_str).unwrap_or_default(),
            timestamp: DateTime::parse_from_rfc3339(&timestamp_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            severity: match severity_int {
                5 => Severity::Critical,
                4 => Severity::High,
                3 => Severity::Medium,
                2 => Severity::Low,
                _ => Severity::Info,
            },
            confidence: row.get::<_, i32>(3)? as u8,
            message: row.get(4)?,
            description: row.get(5)?,
            classification: Classification::Custom(row.get::<_, String>(6)?),
            signature_id: row.get::<_, Option<i32>>(7)?.map(|v| v as u32),
            signature_name: row.get(8)?,
            network: NetworkContext {
                src_ip: row.get::<_, Option<String>>(9)?.and_then(|s| s.parse().ok()),
                src_port: row.get::<_, Option<i32>>(10)?.map(|p| p as u16),
                dst_ip: row.get::<_, Option<String>>(11)?.and_then(|s| s.parse().ok()),
                dst_port: row.get::<_, Option<i32>>(12)?.map(|p| p as u16),
                protocol: row.get(13)?,
                ..Default::default()
            },
            payload: row.get(14)?,
            status: match row.get::<_, i32>(15)? {
                0 => AlertStatus::New,
                1 => AlertStatus::Acknowledged,
                2 => AlertStatus::InProgress,
                3 => AlertStatus::Resolved,
                4 => AlertStatus::FalsePositive,
                _ => AlertStatus::Escalated,
            },
            count: row.get::<_, i32>(16)? as u32,
            first_seen: DateTime::parse_from_rfc3339(&first_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen: DateTime::parse_from_rfc3339(&last_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            incident_id: row.get::<_, Option<String>>(19)?
                .and_then(|s| Uuid::parse_str(&s).ok()),
            metadata: row.get::<_, Option<String>>(20)?
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
            tags: row.get::<_, Option<String>>(21)?
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
        })
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStats {
    pub total_alerts: u64,
    pub new_alerts: u64,
    pub critical_count: u64,
    pub high_count: u64,
    pub medium_count: u64,
    pub low_count: u64,
    pub info_count: u64,
}

// =============================================================================
// Alert Manager
// =============================================================================

/// Comprehensive alert management system
pub struct AlertManager {
    /// Alert queue
    queue: Arc<AlertQueue>,
    /// Deduplicator
    deduplicator: Arc<AlertDeduplicator>,
    /// Correlator
    correlator: Arc<AlertCorrelator>,
    /// Database
    database: Option<Arc<AlertDatabase>>,
    /// Alert channel for async processing
    alert_tx: Sender<Alert>,
    /// Alert receiver
    alert_rx: Receiver<Alert>,
    /// Handler callbacks
    handlers: Arc<RwLock<Vec<Box<dyn Fn(&Alert) + Send + Sync>>>>,
    /// Statistics
    stats: Arc<RwLock<ManagerStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct ManagerStats {
    pub alerts_received: u64,
    pub alerts_deduplicated: u64,
    pub alerts_correlated: u64,
    pub alerts_dispatched: u64,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(db_path: Option<PathBuf>) -> Result<Self, AlertError> {
        let (alert_tx, alert_rx) = async_channel::bounded(10000);

        let database = if let Some(path) = db_path {
            Some(Arc::new(AlertDatabase::open(&path)?))
        } else {
            None
        };

        Ok(AlertManager {
            queue: Arc::new(AlertQueue::new(10000)),
            deduplicator: Arc::new(AlertDeduplicator::new(60)),
            correlator: Arc::new(AlertCorrelator::new()),
            database,
            alert_tx,
            alert_rx,
            handlers: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(ManagerStats::default())),
        })
    }

    /// Register an alert handler
    pub fn add_handler<F>(&self, handler: F)
    where
        F: Fn(&Alert) + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().unwrap();
        handlers.push(Box::new(handler));
    }

    /// Submit an alert for processing
    pub async fn submit(&self, alert: Alert) -> Result<Option<Uuid>, AlertError> {
        {
            let mut stats = self.stats.write().unwrap();
            stats.alerts_received += 1;
        }

        // Deduplication
        let alert = match self.deduplicator.check(alert) {
            Some(a) => a,
            None => {
                let mut stats = self.stats.write().unwrap();
                stats.alerts_deduplicated += 1;
                return Ok(None);
            }
        };

        // Correlation
        let incident_id = self.correlator.correlate(alert.clone());
        let mut alert = alert;
        alert.incident_id = incident_id;

        if incident_id.is_some() {
            let mut stats = self.stats.write().unwrap();
            stats.alerts_correlated += 1;
        }

        let alert_id = alert.id;

        // Queue and dispatch
        self.queue.push(alert.clone());

        // Persist if database is available
        if let Some(ref db) = self.database {
            db.save_alert(&alert).await?;
        }

        // Send to channel for async handlers
        self.alert_tx.send(alert.clone()).await
            .map_err(|e| AlertError::ChannelError(e.to_string()))?;

        // Call sync handlers
        {
            let handlers = self.handlers.read().unwrap();
            for handler in handlers.iter() {
                handler(&alert);
            }

            let mut stats = self.stats.write().unwrap();
            stats.alerts_dispatched += 1;
        }

        Ok(Some(alert_id))
    }

    /// Get next alert from queue
    pub fn next_alert(&self) -> Option<Alert> {
        self.queue.pop()
    }

    /// Get alert receiver for async processing
    pub fn receiver(&self) -> Receiver<Alert> {
        self.alert_rx.clone()
    }

    /// Get manager statistics
    pub fn stats(&self) -> ManagerStats {
        self.stats.read().unwrap().clone()
    }

    /// Get queue length
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Get deduplication stats
    pub fn dedup_stats(&self) -> (usize, u32) {
        self.deduplicator.stats()
    }

    /// List recent incidents
    pub fn list_incidents(&self) -> Vec<Incident> {
        self.correlator.list_incidents()
    }

    /// Query alerts from database
    pub async fn query_alerts(
        &self,
        min_severity: Option<Severity>,
        status: Option<AlertStatus>,
        limit: usize,
    ) -> Result<Vec<Alert>, AlertError> {
        if let Some(ref db) = self.database {
            db.query_alerts(min_severity, status, None, None, limit).await
        } else {
            Ok(Vec::new())
        }
    }
}

// =============================================================================
// CLI Interface
// =============================================================================

#[derive(Parser)]
#[command(name = "ids04_alert_manager")]
#[command(about = "Alert generation and management system for IDS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate test alerts
    Generate {
        /// Number of alerts to generate
        #[arg(short, long, default_value = "10")]
        count: usize,
        /// Database path
        #[arg(short, long)]
        database: Option<PathBuf>,
    },
    /// Query alerts from database
    Query {
        /// Database path
        database: PathBuf,
        /// Minimum severity
        #[arg(short, long)]
        severity: Option<String>,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show database statistics
    Stats {
        /// Database path
        database: PathBuf,
    },
    /// Run interactive demo
    Demo,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { count, database } => {
            println!("{}", "Alert Manager - Generate Test Alerts".cyan().bold());
            println!("{}", "=".repeat(60));

            let manager = AlertManager::new(database)?;

            // Add console handler
            manager.add_handler(|alert| {
                let color = alert.severity.as_color();
                println!(
                    "  {} [{}] {} (SID: {:?})",
                    "[ALERT]".color(color).bold(),
                    alert.severity.to_string().color(color),
                    alert.message,
                    alert.signature_id
                );
            });

            // Generate test alerts
            let severities = [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
            ];

            let messages = [
                ("SQL Injection Attempt", 1000001, Classification::WebApplicationAttack),
                ("Port Scan Detected", 1000002, Classification::AttemptedRecon),
                ("Malware C2 Communication", 1000003, Classification::MalwareCommand),
                ("SSH Brute Force", 1000004, Classification::AttemptedAdmin),
                ("DNS Tunnel Detected", 1000005, Classification::PolicyViolation),
            ];

            println!("\n{}", "Generating alerts...".yellow());

            for i in 0..count {
                let severity = severities[i % severities.len()];
                let (msg, sid, class) = &messages[i % messages.len()];

                let alert = Alert::new(severity, *msg)
                    .with_signature(*sid, *msg)
                    .with_classification(class.clone())
                    .with_confidence(85 + (i % 15) as u8)
                    .with_network(NetworkContext {
                        src_ip: Some(format!("192.168.1.{}", i % 255).parse()?),
                        src_port: Some(12345 + i as u16),
                        dst_ip: Some("10.0.0.1".parse()?),
                        dst_port: Some(80),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    });

                manager.submit(alert).await?;

                // Small delay to see deduplication
                if i > 0 && i % 5 == 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }

            println!("\n{}", "Statistics".cyan().bold());
            let stats = manager.stats();
            println!("  Received: {}", stats.alerts_received);
            println!("  Deduplicated: {}", stats.alerts_deduplicated);
            println!("  Correlated: {}", stats.alerts_correlated);
            println!("  Dispatched: {}", stats.alerts_dispatched);

            let (unique, total) = manager.dedup_stats();
            println!("  Unique patterns: {} (total count: {})", unique, total);

            let incidents = manager.list_incidents();
            if !incidents.is_empty() {
                println!("\n{}", "Incidents Created".cyan().bold());
                for incident in incidents {
                    println!("  - {}: {} ({} alerts)",
                        incident.id, incident.title, incident.alert_count);
                }
            }
        }

        Commands::Query { database, severity, limit, json } => {
            let db = AlertDatabase::open(&database)?;

            let min_severity = severity.map(|s| Severity::from_str(&s)).transpose()?;

            let alerts = db.query_alerts(min_severity, None, None, None, limit).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&alerts)?);
            } else {
                println!("{}", "Alert Query Results".cyan().bold());
                println!("{}", "=".repeat(60));
                println!("Found {} alerts\n", alerts.len());

                for alert in &alerts {
                    let color = alert.severity.as_color();
                    println!(
                        "[{}] {} - {} (count: {})",
                        alert.severity.to_string().color(color),
                        alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        alert.message.yellow(),
                        alert.count
                    );
                    if let Some(src) = &alert.network.src_ip {
                        println!("  Source: {}:{:?}", src, alert.network.src_port);
                    }
                    if let Some(dst) = &alert.network.dst_ip {
                        println!("  Dest: {}:{:?}", dst, alert.network.dst_port);
                    }
                }
            }
        }

        Commands::Stats { database } => {
            let db = AlertDatabase::open(&database)?;
            let stats = db.get_stats().await?;

            println!("{}", "Alert Database Statistics".cyan().bold());
            println!("{}", "=".repeat(60));
            println!("  Total Alerts: {}", stats.total_alerts);
            println!("  New Alerts: {}", stats.new_alerts);
            println!();
            println!("  By Severity:");
            println!("    {}: {}", "Critical".red(), stats.critical_count);
            println!("    {}: {}", "High".bright_red(), stats.high_count);
            println!("    {}: {}", "Medium".yellow(), stats.medium_count);
            println!("    {}: {}", "Low".blue(), stats.low_count);
            println!("    {}: {}", "Info".white(), stats.info_count);
        }

        Commands::Demo => {
            println!("{}", "Alert Manager Interactive Demo".cyan().bold());
            println!("{}", "=".repeat(60));
            println!();
            println!("This demo shows the alert management pipeline:");
            println!("  1. Alert generation");
            println!("  2. Deduplication");
            println!("  3. Correlation");
            println!("  4. Priority queuing");
            println!();

            let manager = AlertManager::new(None)?;

            // Add verbose handler
            manager.add_handler(|alert| {
                let color = alert.severity.as_color();
                println!(
                    "  {} [{}] {} - Confidence: {}%, Count: {}",
                    "->".color(color),
                    alert.severity.to_string().color(color),
                    alert.message,
                    alert.confidence,
                    alert.count
                );
            });

            println!("{}", "Simulating attack scenario...".yellow());
            println!();

            // Simulate multi-source attack
            println!("Phase 1: Multiple sources attacking same target");
            for i in 0..5 {
                let alert = Alert::new(Severity::High, "Port scan detected")
                    .with_signature(1000001, "PORT_SCAN")
                    .with_network(NetworkContext {
                        src_ip: Some(format!("192.168.1.{}", 10 + i).parse()?),
                        dst_ip: Some("10.0.0.100".parse()?),
                        dst_port: Some(22),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    });
                manager.submit(alert).await?;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            // Simulate repeated attack (should deduplicate)
            println!("\nPhase 2: Repeated attacks (deduplication)");
            for _ in 0..3 {
                let alert = Alert::new(Severity::Medium, "SQL Injection")
                    .with_signature(1000002, "SQLI")
                    .with_network(NetworkContext {
                        src_ip: Some("192.168.1.50".parse()?),
                        dst_ip: Some("10.0.0.100".parse()?),
                        dst_port: Some(80),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    });
                manager.submit(alert).await?;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            // Simulate attack chain
            println!("\nPhase 3: Attack chain (correlation)");
            let attacker = "192.168.1.100";
            let target = "10.0.0.50";

            let stages = [
                (Severity::Low, "Reconnaissance scan"),
                (Severity::Medium, "Vulnerability probe"),
                (Severity::High, "Exploitation attempt"),
                (Severity::Critical, "Successful compromise"),
            ];

            for (sev, msg) in stages {
                let alert = Alert::new(sev, msg)
                    .with_signature(2000000 + sev as u32, msg)
                    .with_network(NetworkContext {
                        src_ip: Some(attacker.parse()?),
                        dst_ip: Some(target.parse()?),
                        dst_port: Some(443),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    });
                manager.submit(alert).await?;
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            // Show final stats
            println!("\n{}", "Final Statistics".cyan().bold());
            let stats = manager.stats();
            println!("  Total received: {}", stats.alerts_received);
            println!("  Deduplicated: {}", stats.alerts_deduplicated);
            println!("  Correlated: {}", stats.alerts_correlated);
            println!("  Unique in queue: {}", manager.queue_len());

            let incidents = manager.list_incidents();
            if !incidents.is_empty() {
                println!("\n{}", "Incidents Detected".red().bold());
                for incident in incidents {
                    println!("  {} {}: {} ({} alerts)",
                        "*".red(),
                        incident.id.to_string()[..8].to_string(),
                        incident.title,
                        incident.alert_count);
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(Severity::High, "Test alert")
            .with_confidence(95)
            .with_signature(1000001, "TEST_SIG");

        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.confidence, 95);
        assert_eq!(alert.signature_id, Some(1000001));
    }

    #[test]
    fn test_alert_priority() {
        let low = Alert::new(Severity::Low, "Low priority");
        let high = Alert::new(Severity::High, "High priority");
        let critical = Alert::new(Severity::Critical, "Critical priority");

        assert!(critical.priority_score() > high.priority_score());
        assert!(high.priority_score() > low.priority_score());
    }

    #[test]
    fn test_alert_queue() {
        let queue = AlertQueue::new(10);

        let low = Alert::new(Severity::Low, "Low");
        let high = Alert::new(Severity::High, "High");

        queue.push(low);
        queue.push(high);

        // High priority should come out first
        let first = queue.pop().unwrap();
        assert_eq!(first.severity, Severity::High);
    }

    #[test]
    fn test_deduplication() {
        let dedup = AlertDeduplicator::new(60);

        let alert1 = Alert::new(Severity::Medium, "Test")
            .with_signature(1000001, "TEST")
            .with_network(NetworkContext {
                src_ip: Some("192.168.1.1".parse().unwrap()),
                dst_ip: Some("10.0.0.1".parse().unwrap()),
                dst_port: Some(80),
                ..Default::default()
            });

        let alert2 = alert1.clone();

        // First should pass through
        assert!(dedup.check(alert1).is_some());

        // Second should be deduplicated
        assert!(dedup.check(alert2).is_none());

        let (unique, total) = dedup.stats();
        assert_eq!(unique, 1);
        assert_eq!(total, 2);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[tokio::test]
    async fn test_alert_manager() {
        let manager = AlertManager::new(None).unwrap();

        let alert = Alert::new(Severity::High, "Test alert")
            .with_signature(1000001, "TEST");

        let result = manager.submit(alert).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        let stats = manager.stats();
        assert_eq!(stats.alerts_received, 1);
        assert_eq!(stats.alerts_dispatched, 1);
    }

    #[tokio::test]
    async fn test_database_persistence() {
        let db = AlertDatabase::open_memory().unwrap();

        let alert = Alert::new(Severity::High, "Test alert")
            .with_signature(1000001, "TEST")
            .with_network(NetworkContext {
                src_ip: Some("192.168.1.1".parse().unwrap()),
                ..Default::default()
            });

        let id = alert.id;
        db.save_alert(&alert).await.unwrap();

        let retrieved = db.get_alert(&id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().message, "Test alert");
    }

    #[test]
    fn test_dedup_key_generation() {
        let alert1 = Alert::new(Severity::High, "Test")
            .with_signature(1000001, "TEST")
            .with_network(NetworkContext {
                src_ip: Some("192.168.1.1".parse().unwrap()),
                dst_ip: Some("10.0.0.1".parse().unwrap()),
                dst_port: Some(80),
                ..Default::default()
            });

        let alert2 = Alert::new(Severity::Medium, "Different msg")
            .with_signature(1000001, "TEST")
            .with_network(NetworkContext {
                src_ip: Some("192.168.1.1".parse().unwrap()),
                dst_ip: Some("10.0.0.1".parse().unwrap()),
                dst_port: Some(80),
                ..Default::default()
            });

        // Same key despite different message/severity
        assert_eq!(alert1.dedup_key(), alert2.dedup_key());
    }
}
