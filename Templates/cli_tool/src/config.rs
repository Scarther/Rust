//! Configuration management for the CLI tool

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Application configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// General settings
    #[serde(default)]
    pub general: GeneralConfig,

    /// Scan settings
    #[serde(default)]
    pub scan: ScanConfig,

    /// Output settings
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GeneralConfig {
    /// Number of worker threads
    #[serde(default = "default_threads")]
    pub threads: usize,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Enable verbose output
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Rate limit (requests per second)
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,

    /// Retry failed operations
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// User agent string
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct OutputConfig {
    /// Output directory
    #[serde(default = "default_output_dir")]
    pub directory: String,

    /// Include timestamps in filenames
    #[serde(default = "default_true")]
    pub timestamps: bool,

    /// Compress output files
    #[serde(default)]
    pub compress: bool,
}

// Default value functions
fn default_threads() -> usize { 4 }
fn default_timeout() -> u64 { 30 }
fn default_rate_limit() -> u32 { 100 }
fn default_retries() -> u32 { 3 }
fn default_user_agent() -> String { "SecurityTool/1.0".to_string() }
fn default_output_dir() -> String { "./output".to_string() }
fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            scan: ScanConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

/// Load configuration from a file
pub fn load(path: &Path) -> Result<Config> {
    let content = fs::read_to_string(path)?;

    let config: Config = if path.extension().map_or(false, |ext| ext == "json") {
        serde_json::from_str(&content)?
    } else {
        // Assume TOML if not JSON
        toml::from_str(&content)?
    };

    Ok(config)
}

/// Save configuration to a file
pub fn save(config: &Config, path: &Path) -> Result<()> {
    let content = if path.extension().map_or(false, |ext| ext == "json") {
        serde_json::to_string_pretty(config)?
    } else {
        toml::to_string_pretty(config)?
    };

    fs::write(path, content)?;
    Ok(())
}

/// Generate a sample configuration file
pub fn generate_sample() -> String {
    let config = Config::default();
    toml::to_string_pretty(&config).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.threads, 4);
        assert_eq!(config.general.timeout, 30);
    }

    #[test]
    fn test_load_json_config() {
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(file, r#"{{"general": {{"threads": 8}}}}"#).unwrap();

        let config = load(file.path()).unwrap();
        assert_eq!(config.general.threads, 8);
    }

    #[test]
    fn test_save_and_load() {
        let config = Config::default();
        let file = NamedTempFile::with_suffix(".json").unwrap();

        save(&config, file.path()).unwrap();
        let loaded = load(file.path()).unwrap();

        assert_eq!(config.general.threads, loaded.general.threads);
    }
}
