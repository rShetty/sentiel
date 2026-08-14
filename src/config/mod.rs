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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    pub enabled: bool,
    pub block_on_violation: bool,
    pub max_redactions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
    pub spending_spike_threshold: f64,
    pub denial_rate_threshold: f64,
    pub off_hours_start: u32,
    pub off_hours_end: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8585,
            },
            database: DatabaseConfig {
                path: "sentiel.db".to_string(),
            },
            dlp: DlpConfig {
                enabled: true,
                block_on_violation: true,
                max_redactions: 100,
            },
            anomaly: AnomalyConfig {
                spending_spike_threshold: 5.0,
                denial_rate_threshold: 0.5,
                off_hours_start: 22,
                off_hours_end: 6,
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}
