use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub id: Option<Uuid>,
    pub source: String,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub principal_id: Option<String>,
    pub event_type: String,
    pub severity: String,
    pub data: serde_json::Value,
    pub dlp_violations: Option<Vec<DlpViolation>>,
    pub anomaly_flags: Option<Vec<String>>,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpViolation {
    pub pattern_name: String,
    pub matched_text: String,
    pub severity: String,
    pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEvent {
    pub source: String,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub principal_id: Option<String>,
    pub event_type: String,
    pub severity: Option<String>,
    pub data: serde_json::Value,
}

impl CreateEvent {
    pub fn to_agent_event(&self) -> AgentEvent {
        AgentEvent {
            id: None,
            source: self.source.clone(),
            session_id: self.session_id.clone(),
            agent_id: self.agent_id.clone(),
            principal_id: self.principal_id.clone(),
            event_type: self.event_type.clone(),
            severity: self.severity.clone().unwrap_or_else(|| "info".to_string()),
            data: self.data.clone(),
            dlp_violations: None,
            anomaly_flags: None,
            timestamp: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQuery {
    pub source: Option<String>,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub event_type: Option<String>,
    pub severity: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
}
