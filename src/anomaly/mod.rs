use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AnomalyConfig;
use crate::events::AgentEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub acknowledged: bool,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

pub struct AnomalyEngine {
    config: AnomalyConfig,
}

impl AnomalyEngine {
    pub fn new(config: AnomalyConfig) -> Self {
        AnomalyEngine { config }
    }

    pub fn check_event(&self, event: &AgentEvent, recent_events: &[AgentEvent]) -> Vec<Alert> {
        let mut alerts = Vec::new();

        if let Some(alert) = self.check_spending_spike(event, recent_events) {
            alerts.push(alert);
        }

        if let Some(alert) = self.check_denial_rate(event, recent_events) {
            alerts.push(alert);
        }

        if let Some(alert) = self.check_off_hours(event) {
            alerts.push(alert);
        }

        if let Some(alert) = self.check_bulk_data_export(event, recent_events) {
            alerts.push(alert);
        }

        if let Some(alert) = self.check_dlp_escalation(event) {
            alerts.push(alert);
        }

        alerts
    }

    fn check_spending_spike(&self, event: &AgentEvent, recent: &[AgentEvent]) -> Option<Alert> {
        if event.event_type != "llm_cost" {
            return None;
        }

        let current_cost = event
            .data
            .get("cost")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let recent_cost: f64 = recent
            .iter()
            .filter(|e| e.event_type == "llm_cost")
            .map(|e| e.data.get("cost").and_then(|v| v.as_f64()).unwrap_or(0.0))
            .sum();

        let avg_cost = if recent.iter().any(|e| e.event_type == "llm_cost") {
            let count = recent.iter().filter(|e| e.event_type == "llm_cost").count();
            recent_cost / count as f64
        } else {
            0.0
        };

        if avg_cost > 0.0 && current_cost > avg_cost * self.config.spending_spike_threshold {
            return Some(Alert {
                id: Uuid::now_v7(),
                session_id: event.session_id.clone(),
                agent_id: event.agent_id.clone(),
                alert_type: "spending_spike".to_string(),
                severity: "high".to_string(),
                message: format!(
                    "Spending spike: ${:.6} vs avg ${:.6} ({}x threshold)",
                    current_cost, avg_cost, self.config.spending_spike_threshold
                ),
                data: Some(serde_json::json!({
                    "current_cost": current_cost,
                    "avg_cost": avg_cost,
                    "threshold_multiplier": self.config.spending_spike_threshold,
                })),
                acknowledged: false,
                created_at: Utc::now(),
                acknowledged_at: None,
            });
        }

        None
    }

    fn check_denial_rate(&self, event: &AgentEvent, recent: &[AgentEvent]) -> Option<Alert> {
        if event.source != "patroclus" || event.event_type != "authz_decision" {
            return None;
        }

        let authz_events: Vec<&AgentEvent> = recent
            .iter()
            .filter(|e| e.source == "patroclus" && e.event_type == "authz_decision")
            .collect();

        if authz_events.len() < 5 {
            return None;
        }

        let denials = authz_events
            .iter()
            .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("deny"))
            .count();

        let rate = denials as f64 / authz_events.len() as f64;
        if rate > self.config.denial_rate_threshold {
            return Some(Alert {
                id: Uuid::now_v7(),
                session_id: event.session_id.clone(),
                agent_id: event.agent_id.clone(),
                alert_type: "high_denial_rate".to_string(),
                severity: "medium".to_string(),
                message: format!(
                    "High denial rate: {:.0}% ({} of {} requests denied)",
                    rate * 100.0,
                    denials,
                    authz_events.len()
                ),
                data: Some(serde_json::json!({
                    "denial_rate": rate,
                    "threshold": self.config.denial_rate_threshold,
                    "total_requests": authz_events.len(),
                    "denials": denials,
                })),
                acknowledged: false,
                created_at: Utc::now(),
                acknowledged_at: None,
            });
        }

        None
    }

    fn check_off_hours(&self, event: &AgentEvent) -> Option<Alert> {
        let now = Utc::now();
        let hour = now.format("%H").to_string().parse::<u32>().unwrap_or(12);

        let is_off_hours = if self.config.off_hours_start > self.config.off_hours_end {
            hour >= self.config.off_hours_start || hour < self.config.off_hours_end
        } else {
            hour >= self.config.off_hours_start && hour < self.config.off_hours_end
        };

        if is_off_hours && event.severity == "critical" {
            return Some(Alert {
                id: Uuid::now_v7(),
                session_id: event.session_id.clone(),
                agent_id: event.agent_id.clone(),
                alert_type: "off_hours_critical".to_string(),
                severity: "medium".to_string(),
                message: format!(
                    "Critical event at off-hours ({}:{:02} UTC)",
                    hour,
                    now.format("%M").to_string().parse::<u32>().unwrap_or(0)
                ),
                data: Some(serde_json::json!({
                    "hour": hour,
                    "off_hours_start": self.config.off_hours_start,
                    "off_hours_end": self.config.off_hours_end,
                })),
                acknowledged: false,
                created_at: Utc::now(),
                acknowledged_at: None,
            });
        }

        None
    }

    fn check_bulk_data_export(&self, event: &AgentEvent, recent: &[AgentEvent]) -> Option<Alert> {
        if event.event_type != "tool_call" {
            return None;
        }

        let tool = event
            .data
            .get("tool")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !tool.contains("export") && !tool.contains("download") && !tool.contains("list") {
            return None;
        }

        let recent_tool_calls = recent
            .iter()
            .filter(|e| e.event_type == "tool_call")
            .count();

        if recent_tool_calls > 20 {
            return Some(Alert {
                id: Uuid::now_v7(),
                session_id: event.session_id.clone(),
                agent_id: event.agent_id.clone(),
                alert_type: "bulk_data_export".to_string(),
                severity: "high".to_string(),
                message: format!(
                    "Bulk data export: {} tool calls in recent session",
                    recent_tool_calls
                ),
                data: Some(serde_json::json!({
                    "tool": tool,
                    "recent_calls": recent_tool_calls,
                })),
                acknowledged: false,
                created_at: Utc::now(),
                acknowledged_at: None,
            });
        }

        None
    }

    fn check_dlp_escalation(&self, event: &AgentEvent) -> Option<Alert> {
        let violations = event.dlp_violations.as_ref()?;
        let critical_count = violations
            .iter()
            .filter(|v| v.severity == "critical")
            .count();

        if critical_count > 0 {
            return Some(Alert {
                id: Uuid::now_v7(),
                session_id: event.session_id.clone(),
                agent_id: event.agent_id.clone(),
                alert_type: "dlp_critical".to_string(),
                severity: "critical".to_string(),
                message: format!(
                    "Critical DLP violation: {} sensitive data pattern(s) detected",
                    critical_count
                ),
                data: Some(serde_json::json!({
                    "violations": violations,
                    "critical_count": critical_count,
                })),
                acknowledged: false,
                created_at: Utc::now(),
                acknowledged_at: None,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_event(event_type: &str, source: &str, data: serde_json::Value) -> AgentEvent {
        AgentEvent {
            id: None,
            source: source.to_string(),
            session_id: Some("test-session".to_string()),
            agent_id: Some("test-agent".to_string()),
            principal_id: None,
            event_type: event_type.to_string(),
            severity: "info".to_string(),
            data,
            dlp_violations: None,
            anomaly_flags: None,
            timestamp: Some(Utc::now()),
        }
    }

    #[test]
    fn test_spending_spike_detection() {
        let config = AnomalyConfig {
            spending_spike_threshold: 3.0,
            denial_rate_threshold: 0.5,
            off_hours_start: 22,
            off_hours_end: 6,
        };
        let engine = AnomalyEngine::new(config);

        let recent = vec![
            make_event("llm_cost", "miser", json!({"cost": 0.0001})),
            make_event("llm_cost", "miser", json!({"cost": 0.0001})),
            make_event("llm_cost", "miser", json!({"cost": 0.0001})),
        ];
        let event = make_event("llm_cost", "miser", json!({"cost": 0.001}));

        let alerts = engine.check_event(&event, &recent);
        assert!(alerts.iter().any(|a| a.alert_type == "spending_spike"));
    }

    #[test]
    fn test_denial_rate_detection() {
        let config = AnomalyConfig {
            spending_spike_threshold: 5.0,
            denial_rate_threshold: 0.5,
            off_hours_start: 22,
            off_hours_end: 6,
        };
        let engine = AnomalyEngine::new(config);

        let recent: Vec<AgentEvent> = (0..6)
            .map(|i| {
                let decision = if i < 4 { "deny" } else { "allow" };
                make_event("authz_decision", "patroclus", json!({"decision": decision}))
            })
            .collect();
        let event = make_event("authz_decision", "patroclus", json!({"decision": "deny"}));

        let alerts = engine.check_event(&event, &recent);
        assert!(alerts.iter().any(|a| a.alert_type == "high_denial_rate"));
    }

    #[test]
    fn test_dlp_escalation() {
        let config = AnomalyConfig {
            spending_spike_threshold: 5.0,
            denial_rate_threshold: 0.5,
            off_hours_start: 22,
            off_hours_end: 6,
        };
        let engine = AnomalyEngine::new(config);

        let mut event = make_event("tool_call", "relay", json!({"tool": "export_data"}));
        event.dlp_violations = Some(vec![crate::events::DlpViolation {
            pattern_name: "ssn".to_string(),
            matched_text: "...".to_string(),
            severity: "critical".to_string(),
            field: "content".to_string(),
        }]);

        let alerts = engine.check_event(&event, &[]);
        assert!(alerts.iter().any(|a| a.alert_type == "dlp_critical"));
    }

    #[test]
    fn test_no_spike_when_low_cost() {
        let config = AnomalyConfig {
            spending_spike_threshold: 5.0,
            denial_rate_threshold: 0.5,
            off_hours_start: 22,
            off_hours_end: 6,
        };
        let engine = AnomalyEngine::new(config);

        let recent = vec![
            make_event("llm_cost", "miser", json!({"cost": 0.0001})),
            make_event("llm_cost", "miser", json!({"cost": 0.0001})),
        ];
        let event = make_event("llm_cost", "miser", json!({"cost": 0.0001}));

        let alerts = engine.check_event(&event, &recent);
        assert!(!alerts.iter().any(|a| a.alert_type == "spending_spike"));
    }
}
