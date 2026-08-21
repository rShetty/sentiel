use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub dlp: DlpConfig,
    pub anomaly: AnomalyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8585,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            path: "sentiel.db".to_string(),
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

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            dlp: DlpConfig::default(),
            anomaly: AnomalyConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}
