use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub dlp: DlpConfig,
    pub anomaly: AnomalyConfig,
}

/// Default ingest payload cap: 256 KiB.
fn default_max_payload_bytes() -> usize {
    256 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Allowed CORS origins. Empty = no cross-origin browser access.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Maximum accepted request body size in bytes. Larger requests are
    /// rejected with `413 Payload Too Large`.
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8585,
            cors_allowed_origins: vec![],
            max_payload_bytes: default_max_payload_bytes(),
        }
    }
}

/// Default event retention window in days.
fn default_retention_days() -> u32 {
    90
}

/// Default interval between background pruning passes (seconds).
fn default_prune_interval_secs() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
    /// Events/alerts older than this many days are pruned.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// Seconds between background pruning passes.
    #[serde(default = "default_prune_interval_secs")]
    pub prune_interval_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            path: "sentiel.db".to_string(),
            retention_days: default_retention_days(),
            prune_interval_secs: default_prune_interval_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    pub enabled: bool,
    pub block_on_violation: bool,
    pub max_redactions: usize,
}

impl Default for DlpConfig {
    fn default() -> Self {
        DlpConfig {
            enabled: true,
            block_on_violation: true,
            max_redactions: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
    pub spending_spike_threshold: f64,
    pub denial_rate_threshold: f64,
    pub off_hours_start: u32,
    pub off_hours_end: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        AnomalyConfig {
            spending_spike_threshold: 5.0,
            denial_rate_threshold: 0.5,
            off_hours_start: 22,
            off_hours_end: 6,
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_defaults_match_documented_retention() {
        let db = DatabaseConfig::default();
        assert_eq!(db.retention_days, 90);
        assert_eq!(db.prune_interval_secs, 3600);
    }

    #[test]
    fn retention_config_parses_from_toml() {
        let config: Config = toml::from_str(
            "[server]\nhost=\"127.0.0.1\"\nport=1\n\
             [database]\npath=\"x.db\"\nretention_days=7\n\
             [dlp]\nenabled=true\nblock_on_violation=false\nmax_redactions=5\n[anomaly]\nspending_spike_threshold=5.0\ndenial_rate_threshold=0.5\noff_hours_start=22\noff_hours_end=6\n",
        )
        .unwrap();
        assert_eq!(config.database.retention_days, 7);
        // Interval falls back to its default when omitted.
        assert_eq!(config.database.prune_interval_secs, 3600);
    }

    #[test]
    fn server_payload_limit_default_is_256kib() {
        assert_eq!(ServerConfig::default().max_payload_bytes, 256 * 1024);
    }
}
