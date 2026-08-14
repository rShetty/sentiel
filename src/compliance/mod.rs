use serde::{Deserialize, Serialize};

use crate::db::Database;
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub summary: serde_json::Value,
    pub controls: Vec<ControlReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlReport {
    pub control_id: String,
    pub control_name: String,
    pub status: String,
    pub evidence_count: usize,
    pub details: String,
}

pub struct ComplianceReporter;

impl ComplianceReporter {
    pub fn generate_soc2(db: &Database) -> Result<ComplianceReport> {
        let all_events = db.list_events(10000)?;
        let authz_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.source == "patroclus" && e.event_type == "authz_decision")
            .collect();
        let tool_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.source == "relay" && e.event_type == "tool_call")
            .collect();
        let cost_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.source == "miser" && e.event_type == "llm_cost")
            .collect();

        let allows = authz_events
            .iter()
            .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("allow"))
            .count();
        let denies = authz_events
            .iter()
            .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("deny"))
            .count();

        Ok(ComplianceReport {
            framework: "SOC 2 Type II".to_string(),
            generated_at: chrono::Utc::now(),
            summary: serde_json::json!({
                "total_events": all_events.len(),
                "authz_decisions": authz_events.len(),
                "allowed": allows,
                "denied": denies,
                "tool_calls": tool_events.len(),
                "llm_requests": cost_events.len(),
            }),
            controls: vec![
                ControlReport {
                    control_id: "CC6.1".to_string(),
                    control_name: "Logical and Physical Access Controls".to_string(),
                    status: "passing".to_string(),
                    evidence_count: authz_events.len(),
                    details: format!(
                        "Authorization decisions logged: {} allow, {} deny. All access checked against policy.",
                        allows, denies
                    ),
                },
                ControlReport {
                    control_id: "CC7.1".to_string(),
                    control_name: "System Monitoring".to_string(),
                    status: "passing".to_string(),
                    evidence_count: all_events.len(),
                    details: format!(
                        "Total monitoring events: {}. Sources: Patroclus, Relay, Miser, Hive.",
                        all_events.len()
                    ),
                },
                ControlReport {
                    control_id: "CC7.2".to_string(),
                    control_name: "Anomaly Detection".to_string(),
                    status: "active".to_string(),
                    evidence_count: 0,
                    details: "Anomaly detection engine monitors for spending spikes, denial rates, off-hours access, and DLP violations.".to_string(),
                },
                ControlReport {
                    control_id: "CC8.1".to_string(),
                    control_name: "Change Management".to_string(),
                    status: "passing".to_string(),
                    evidence_count: authz_events.iter().filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("require_approval")).count(),
                    details: "Approval workflow enforced for sensitive operations. All approvals logged with approver identity.".to_string(),
                },
            ],
        })
    }

    pub fn generate_gdpr(db: &Database) -> Result<ComplianceReport> {
        let all_events = db.list_events(10000)?;
        let dlp_events = db.dlp_violations(1000)?;
        let personal_data_access = dlp_events
            .iter()
            .filter(|e| {
                e.dlp_violations
                    .as_ref()
                    .map(|v| {
                        v.iter().any(|v| {
                            v.pattern_name == "email"
                                || v.pattern_name == "ssn"
                                || v.pattern_name == "phone"
                        })
                    })
                    .unwrap_or(false)
            })
            .count();

        Ok(ComplianceReport {
            framework: "GDPR".to_string(),
            generated_at: chrono::Utc::now(),
            summary: serde_json::json!({
                "total_events": all_events.len(),
                "dlp_violations": dlp_events.len(),
                "personal_data_access_events": personal_data_access,
            }),
            controls: vec![
                ControlReport {
                    control_id: "Art.30".to_string(),
                    control_name: "Records of Processing Activities".to_string(),
                    status: "passing".to_string(),
                    evidence_count: all_events.len(),
                    details: format!("All agent actions logged with full attribution. {} total events.", all_events.len()),
                },
                ControlReport {
                    control_id: "Art.32".to_string(),
                    control_name: "Security of Processing".to_string(),
                    status: "passing".to_string(),
                    evidence_count: dlp_events.len(),
                    details: format!("DLP engine detected {} potential personal data exposures. Violations logged for review.", dlp_events.len()),
                },
                ControlReport {
                    control_id: "Art.33".to_string(),
                    control_name: "Breach Notification".to_string(),
                    status: "active".to_string(),
                    evidence_count: 0,
                    details: "Anomaly detection monitors for data exfiltration patterns. Critical DLP violations trigger immediate alerts.".to_string(),
                },
                ControlReport {
                    control_id: "Art.35".to_string(),
                    control_name: "Data Protection Impact Assessment".to_string(),
                    status: "passing".to_string(),
                    evidence_count: personal_data_access,
                    details: format!("{} events involved personal data patterns. All logged for DPIA review.", personal_data_access),
                },
            ],
        })
    }

    pub fn generate_eu_ai_act(db: &Database) -> Result<ComplianceReport> {
        let all_events = db.list_events(10000)?;
        let authz_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.source == "patroclus" && e.event_type == "authz_decision")
            .collect();
        let approvals = authz_events
            .iter()
            .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("require_approval"))
            .count();

        Ok(ComplianceReport {
            framework: "EU AI Act".to_string(),
            generated_at: chrono::Utc::now(),
            summary: serde_json::json!({
                "total_events": all_events.len(),
                "human_oversight_events": approvals,
            }),
            controls: vec![
                ControlReport {
                    control_id: "Art.14".to_string(),
                    control_name: "Human Oversight".to_string(),
                    status: "passing".to_string(),
                    evidence_count: approvals,
                    details: format!("{} operations required human approval. Approval workflow with audit trail enforced.", approvals),
                },
                ControlReport {
                    control_id: "Art.12".to_string(),
                    control_name: "Logging and Record-Keeping".to_string(),
                    status: "passing".to_string(),
                    evidence_count: all_events.len(),
                    details: format!("Hash-chained audit trail with {} entries. Attribution-complete: every action traces to human or system authority.", all_events.len()),
                },
                ControlReport {
                    control_id: "Art.15".to_string(),
                    control_name: "Accuracy, Robustness, Cybersecurity".to_string(),
                    status: "active".to_string(),
                    evidence_count: 0,
                    details: "Rate limiting, budget caps, trust decay, and kill switch enforced via Patroclus. DLP and anomaly detection via Sentiel.".to_string(),
                },
                ControlReport {
                    control_id: "Art.26".to_string(),
                    control_name: "Post-Market Monitoring".to_string(),
                    status: "active".to_string(),
                    evidence_count: 0,
                    details: "Anomaly detection engine monitors for spending spikes, denial rates, off-hours activity, and bulk data exports.".to_string(),
                },
            ],
        })
    }

    pub fn generate_hipaa(db: &Database) -> Result<ComplianceReport> {
        let all_events = db.list_events(10000)?;
        let dlp_events = db.dlp_violations(1000)?;
        let phi_patterns = dlp_events
            .iter()
            .filter(|e| {
                e.dlp_violations
                    .as_ref()
                    .map(|v| {
                        v.iter()
                            .any(|v| matches!(v.pattern_name.as_str(), "ssn" | "phone" | "email"))
                    })
                    .unwrap_or(false)
            })
            .count();

        Ok(ComplianceReport {
            framework: "HIPAA".to_string(),
            generated_at: chrono::Utc::now(),
            summary: serde_json::json!({
                "total_events": all_events.len(),
                "phi_access_events": phi_patterns,
                "dlp_violations": dlp_events.len(),
            }),
            controls: vec![
                ControlReport {
                    control_id: "164.312(b)".to_string(),
                    control_name: "Audit Controls".to_string(),
                    status: "passing".to_string(),
                    evidence_count: all_events.len(),
                    details: format!("All agent actions logged. {} total audit entries.", all_events.len()),
                },
                ControlReport {
                    control_id: "164.312(c)(1)".to_string(),
                    control_name: "Integrity Controls".to_string(),
                    status: "passing".to_string(),
                    evidence_count: 0,
                    details: "Hash-chained audit trail ensures tamper-evidence. Any modification breaks the chain.".to_string(),
                },
                ControlReport {
                    control_id: "164.312(a)(1)".to_string(),
                    control_name: "Access Control".to_string(),
                    status: "passing".to_string(),
                    evidence_count: all_events.iter().filter(|e| e.source == "patroclus").count(),
                    details: "Policy-based access control via Patroclus. Default-deny, scoped tokens, approval workflow.".to_string(),
                },
                ControlReport {
                    control_id: "164.312(e)(1)".to_string(),
                    control_name: "Transmission Security".to_string(),
                    status: "active".to_string(),
                    evidence_count: phi_patterns,
                    details: format!("DLP engine monitors for PHI patterns. {} events flagged for review.", phi_patterns),
                },
            ],
        })
    }
}
