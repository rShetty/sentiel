use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Sources permitted to emit events. Anything else is rejected at ingest.
pub const ALLOWED_SOURCES: &[&str] = &["miser", "patroclus", "relay"];

/// Event types accepted by the ingest API. Anything else is rejected.
pub const ALLOWED_EVENT_TYPES: &[&str] = &["llm_cost", "authz_decision", "tool_call"];

/// Severity levels accepted on ingest (defaults to `info` when omitted).
pub const ALLOWED_SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];

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
    /// Strict schema validation for the ingest API.
    ///
    /// Collects *every* violation (rather than failing fast) so callers get a
    /// complete picture of what was wrong with their payload. Required fields
    /// and JSON types are enforced by `serde` during deserialization; this
    /// adds the semantic checks:
    ///
    /// - `source` must be one of [`ALLOWED_SOURCES`]
    /// - `event_type` must be one of [`ALLOWED_EVENT_TYPES`]
    /// - `severity`, when present, must be one of [`ALLOWED_SEVERITIES`]
    /// - `data` must be a JSON object (not a scalar, array, or null)
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if !ALLOWED_SOURCES.contains(&self.source.as_str()) {
            errors.push(format!(
                "invalid source {:?}: must be one of {}",
                self.source,
                ALLOWED_SOURCES.join(", ")
            ));
        }

        if !ALLOWED_EVENT_TYPES.contains(&self.event_type.as_str()) {
            errors.push(format!(
                "invalid event_type {:?}: must be one of {}",
                self.event_type,
                ALLOWED_EVENT_TYPES.join(", ")
            ));
        }

        if let Some(severity) = &self.severity
            && !ALLOWED_SEVERITIES.contains(&severity.as_str())
        {
            errors.push(format!(
                "invalid severity {:?}: must be one of {}",
                severity,
                ALLOWED_SEVERITIES.join(", ")
            ));
        }

        if !self.data.is_object() {
            errors.push(format!(
                "invalid data: expected a JSON object, got {}",
                json_type_name(&self.data)
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

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

/// Human-readable name for a JSON value's type, used in validation errors.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_event() -> CreateEvent {
        CreateEvent {
            source: "miser".to_string(),
            session_id: Some("s-1".to_string()),
            agent_id: None,
            principal_id: None,
            event_type: "llm_cost".to_string(),
            severity: None,
            data: json!({"cost": 0.01}),
        }
    }

    #[test]
    fn valid_event_passes_validation() {
        assert!(valid_event().validate().is_ok());
    }

    #[test]
    fn unknown_source_is_rejected_with_allowed_values() {
        let mut event = valid_event();
        event.source = "rogue-agent".to_string();
        let errors = event.validate().unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("invalid source"));
        assert!(errors[0].contains("miser, patroclus, relay"));
    }

    #[test]
    fn unknown_event_type_is_rejected() {
        let mut event = valid_event();
        event.event_type = "keyboard_event".to_string();
        let errors = event.validate().unwrap_err();
        assert!(errors[0].contains("invalid event_type"));
    }

    #[test]
    fn invalid_severity_is_rejected() {
        let mut event = valid_event();
        event.severity = Some("catastrophic".to_string());
        let errors = event.validate().unwrap_err();
        assert!(errors[0].contains("invalid severity"));
    }

    #[test]
    fn non_object_data_is_rejected() {
        for bad in [json!("text"), json!([1, 2]), json!(null), json!(42)] {
            let mut event = valid_event();
            event.data = bad;
            let errors = event.validate().unwrap_err();
            assert_eq!(errors.len(), 1, "data: {errors:?}");
            assert!(errors[0].contains("expected a JSON object"));
        }
    }

    #[test]
    fn all_violations_are_collected_together() {
        let mut event = valid_event();
        event.source = "nope".to_string();
        event.event_type = "also-nope".to_string();
        event.severity = Some("loud".to_string());
        event.data = json!("not an object");
        let errors = event.validate().unwrap_err();
        assert_eq!(errors.len(), 4);
    }
}
