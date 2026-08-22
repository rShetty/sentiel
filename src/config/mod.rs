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
    /// Tamper-evident storage: hash-chain every event row (see the `audit`
    /// module). Off by default; enabling adds per-insert hashing cost and
    /// makes event rows immutable-by-detection (verify via
    /// `/api/integrity`).
    #[serde(default)]
    pub chain_events: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            path: "sentiel.db".to_string(),
            retention_days: default_retention_days(),
            prune_interval_secs: default_prune_interval_secs(),
            chain_events: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    pub enabled: bool,
    /// When true, ingest rejects (`422`) any event whose DLP violations meet
    /// or exceed the block severity instead of storing it. When false,
    /// violations are recorded on the event but the payload is stored as-is.
    pub block_on_violation: bool,
    /// Lowest violation severity that triggers blocking when
    /// `block_on_violation` is enabled. One of `low`, `medium`, `high`,
    /// `critical` (default: `critical`).
    #[serde(default = "default_block_severity")]
    pub block_severity: String,
    /// Cap on violations recorded per event (guards unbounded growth).
    #[serde(default = "default_max_redactions")]
    pub max_redactions: usize,
}

fn default_block_severity() -> String {
    "critical".to_string()
}

fn default_max_redactions() -> usize {
    100
}

impl Default for DlpConfig {
    fn default() -> Self {
        DlpConfig {
            enabled: true,
            block_on_violation: true,
            block_severity: default_block_severity(),
            max_redactions: default_max_redactions(),
        }
    }
}

/// Rank a DLP severity so block decisions can use `>=` comparisons.
/// Unknown severities rank below `low` (never block on their own).
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        "low" => 0,
        _ => 0,
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

    #[test]
    fn dlp_config_defaults_block_critical() {
        let dlp = DlpConfig::default();
        assert!(dlp.block_on_violation);
        assert_eq!(dlp.block_severity, "critical");
        assert_eq!(dlp.max_redactions, 100);
    }

    #[test]
    fn dlp_config_parses_block_fields_from_toml() {
        let config: Config = toml::from_str(
            "[server]\nhost=\"127.0.0.1\"\nport=1\n\
             [database]\npath=\"x.db\"\n\
             [dlp]\nenabled=true\nblock_on_violation=true\nblock_severity=\"high\"\nmax_redactions=7\n\
             [anomaly]\nspending_spike_threshold=5.0\ndenial_rate_threshold=0.5\noff_hours_start=22\noff_hours_end=6\n",
        )
        .unwrap();
        assert_eq!(config.dlp.block_severity, "high");
        assert_eq!(config.dlp.max_redactions, 7);
        // Omitted block fields fall back to safe defaults.
        let minimal: Config = toml::from_str(
            "[server]\nhost=\"127.0.0.1\"\nport=1\n\
             [database]\npath=\"x.db\"\n\
             [dlp]\nenabled=true\nblock_on_violation=false\n\
             [anomaly]\nspending_spike_threshold=5.0\ndenial_rate_threshold=0.5\noff_hours_start=22\noff_hours_end=6\n",
        )
        .unwrap();
        assert_eq!(minimal.dlp.block_severity, "critical");
        assert_eq!(minimal.dlp.max_redactions, 100);
    }

    #[test]
    fn severity_rank_orders_known_levels() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert_eq!(severity_rank("low"), 0);
        // Unknown severities never rank above the floor.
        assert_eq!(severity_rank("bogus"), 0);
    }

    #[test]
    fn chain_events_defaults_off_and_parses_from_toml() {
        // Omitted -> opt-in feature stays disabled.
        let config: Config = toml::from_str(
            "[server]\nhost=\"127.0.0.1\"\nport=1\n\
             [database]\npath=\"x.db\"\n\
             [dlp]\nenabled=true\nblock_on_violation=false\n\
             [anomaly]\nspending_spike_threshold=5.0\ndenial_rate_threshold=0.5\noff_hours_start=22\noff_hours_end=6\n",
        )
        .unwrap();
        assert!(!config.database.chain_events);

        let config: Config = toml::from_str(
            "[server]\nhost=\"127.0.0.1\"\nport=1\n\
             [database]\npath=\"x.db\"\nchain_events=true\n\
             [dlp]\nenabled=true\nblock_on_violation=false\n\
             [anomaly]\nspending_spike_threshold=5.0\ndenial_rate_threshold=0.5\noff_hours_start=22\noff_hours_end=6\n",
        )
        .unwrap();
        assert!(config.database.chain_events);
    }
}
