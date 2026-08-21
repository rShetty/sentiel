use serde::{Deserialize, Serialize};

use crate::db::Database;
use crate::errors::Result;
use crate::events::EventQuery;

/// Status of a mapped control, derived strictly from available evidence.
///
/// Deliberately excludes verdicts like "passing" or "compliant": automated
/// telemetry can show that a control is monitored, that its evidence needs
/// human review, or that no evidence exists — nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    /// Matching evidence exists in the store and the producing checks run.
    Monitored,
    /// Evidence exists, but deciding compliance requires human judgement.
    RequiresReview,
    /// No matching evidence in the retained event window.
    NoEvidence,
}

impl ControlStatus {
    /// Honest status for a control backed solely by `matching` evidence rows.
    fn from_count(matching: usize) -> Self {
        if matching == 0 {
            ControlStatus::NoEvidence
        } else {
            ControlStatus::Monitored
        }
    }
}

/// Reference to the evidence backing one control: a replayable event query
/// and/or a dedicated endpoint that returns the raw records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// What this evidence demonstrates for the control.
    pub description: String,
    /// Dedicated API endpoint returning the raw records, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Structured event query; replayable against `POST /api/events/query`.
    pub query: EventQuery,
}

/// One mapped control inside a framework report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub name: String,
    pub status: ControlStatus,
    pub evidence: Vec<EvidenceRef>,
}

/// Supporting counts attached to a report. Raw numbers are evidence, not
/// findings, so they never appear in the report body itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceAttachment {
    pub name: String,
    pub description: String,
    pub counts: serde_json::Value,
}

/// The report body: framework → controls with evidence references and an
/// explicit data-completeness disclaimer. Summary counts deliberately live
/// in [`ComplianceExport::attachments`], not here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub disclaimer: String,
    pub controls: Vec<Control>,
}

/// Full export served by the API: the report body plus evidence attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceExport {
    pub report: ComplianceReport,
    pub attachments: Vec<EvidenceAttachment>,
}

/// Explicit data-completeness disclaimer included in every report.
fn completeness_disclaimer() -> String {
    "Data-completeness disclaimer: this report maps events captured by Sentiel \
     onto control activities. It is NOT an audit opinion, attestation, or \
     certification. Coverage is limited to events successfully ingested within \
     the configured retention window — ingestion gaps, clock skew, rejected \
     payloads, or pruned history all reduce completeness. Attached counts are \
     raw evidence for reviewer inspection, not findings."
        .to_string()
}

/// Empty event query with a sane evidence-retrieval limit.
fn base_query() -> EventQuery {
    EventQuery {
        source: None,
        session_id: None,
        agent_id: None,
        event_type: None,
        severity: None,
        from: None,
        to: None,
        limit: Some(1000),
    }
}

fn attachment(name: &str, description: &str, counts: serde_json::Value) -> EvidenceAttachment {
    EvidenceAttachment {
        name: name.to_string(),
        description: description.to_string(),
        counts,
    }
}

pub struct ComplianceReporter;

impl ComplianceReporter {
    pub fn generate_soc2(db: &Database) -> Result<ComplianceExport> {
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
        let approvals = authz_events
            .iter()
            .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("require_approval"))
            .count();

        let mut authz_query = base_query();
        authz_query.source = Some("patroclus".to_string());
        authz_query.event_type = Some("authz_decision".to_string());

        let mut tool_query = base_query();
        tool_query.source = Some("relay".to_string());
        tool_query.event_type = Some("tool_call".to_string());

        let mut critical_query = base_query();
        critical_query.severity = Some("critical".to_string());

        Ok(ComplianceExport {
            report: ComplianceReport {
                framework: "SOC 2 Type II".to_string(),
                generated_at: chrono::Utc::now(),
                disclaimer: completeness_disclaimer(),
                controls: vec![
                    Control {
                        id: "CC6.1".to_string(),
                        name: "Logical and Physical Access Controls".to_string(),
                        status: ControlStatus::from_count(authz_events.len()),
                        evidence: vec![EvidenceRef {
                            description: "Authorization decisions recorded by Patroclus \
                                          (allow/deny/require_approval). Presence of decisions \
                                          shows access checks ran; correctness needs review."
                                .to_string(),
                            endpoint: None,
                            query: authz_query.clone(),
                        }],
                    },
                    Control {
                        id: "CC7.1".to_string(),
                        name: "System Monitoring".to_string(),
                        status: ControlStatus::from_count(all_events.len()),
                        evidence: vec![EvidenceRef {
                            description: "Governance events across all configured sources \
                                          (Patroclus, Relay, Miser)."
                                .to_string(),
                            endpoint: None,
                            query: base_query(),
                        }],
                    },
                    Control {
                        id: "CC7.2".to_string(),
                        name: "Anomaly Detection".to_string(),
                        status: ControlStatus::RequiresReview,
                        evidence: vec![EvidenceRef {
                            description: "The anomaly engine flags spending spikes, denial \
                                          rates, off-hours access, and DLP violations; every \
                                          critical-severity event requires analyst triage \
                                          before any conclusion can be drawn."
                                .to_string(),
                            endpoint: Some("/api/alerts".to_string()),
                            query: critical_query,
                        }],
                    },
                    Control {
                        id: "CC8.1".to_string(),
                        name: "Change Management".to_string(),
                        status: ControlStatus::from_count(approvals),
                        evidence: vec![EvidenceRef {
                            description: "Authz decisions with decision=require_approval \
                                          (filter client-side on the query results) show the \
                                          approval workflow logged sensitive operations."
                                .to_string(),
                            endpoint: None,
                            query: authz_query,
                        }],
                    },
                ],
            },
            attachments: vec![attachment(
                "summary_counts",
                "Raw event counts observed in the retention window.",
                serde_json::json!({
                    "total_events": all_events.len(),
                    "authz_decisions": authz_events.len(),
                    "tool_calls": tool_events.len(),
                    "llm_requests": cost_events.len(),
                }),
            )],
        })
    }

    pub fn generate_gdpr(db: &Database) -> Result<ComplianceExport> {
        let all_events = db.list_events(10000)?;
        let dlp_events = db.dlp_violations(1000)?;
        let personal_data_access = count_personal_data(&dlp_events);

        let mut all_query = base_query();
        all_query.limit = Some(10_000);

        let mut critical_query = base_query();
        critical_query.severity = Some("critical".to_string());

        Ok(ComplianceExport {
            report: ComplianceReport {
                framework: "GDPR".to_string(),
                generated_at: chrono::Utc::now(),
                disclaimer: completeness_disclaimer(),
                controls: vec![
                    Control {
                        id: "Art.30".to_string(),
                        name: "Records of Processing Activities".to_string(),
                        status: ControlStatus::from_count(all_events.len()),
                        evidence: vec![EvidenceRef {
                            description: "Agent actions logged with source, agent, session, \
                                          and principal attribution."
                                .to_string(),
                            endpoint: None,
                            query: all_query,
                        }],
                    },
                    Control {
                        id: "Art.32".to_string(),
                        name: "Security of Processing".to_string(),
                        status: if dlp_events.is_empty() {
                            ControlStatus::NoEvidence
                        } else {
                            ControlStatus::RequiresReview
                        },
                        evidence: vec![EvidenceRef {
                            description: "DLP detections of potential personal-data \
                                          exposure. Each finding needs human review; zero \
                                          findings may also mean DLP saw no traffic."
                                .to_string(),
                            endpoint: Some("/api/dlp/violations".to_string()),
                            query: base_query(),
                        }],
                    },
                    Control {
                        id: "Art.33".to_string(),
                        name: "Breach Notification".to_string(),
                        status: ControlStatus::RequiresReview,
                        evidence: vec![EvidenceRef {
                            description: "Critical-severity events feed breach assessment; \
                                          notification decisions remain a human process."
                                .to_string(),
                            endpoint: Some("/api/alerts".to_string()),
                            query: critical_query,
                        }],
                    },
                    Control {
                        id: "Art.35".to_string(),
                        name: "Data Protection Impact Assessment".to_string(),
                        status: if personal_data_access == 0 {
                            ControlStatus::NoEvidence
                        } else {
                            ControlStatus::RequiresReview
                        },
                        evidence: vec![EvidenceRef {
                            description: "Events whose DLP violations include email, SSN, or \
                                          phone patterns — inputs for DPIA review."
                                .to_string(),
                            endpoint: Some("/api/dlp/violations".to_string()),
                            query: base_query(),
                        }],
                    },
                ],
            },
            attachments: vec![attachment(
                "summary_counts",
                "Raw event counts observed in the retention window.",
                serde_json::json!({
                    "total_events": all_events.len(),
                    "dlp_violations": dlp_events.len(),
                    "personal_data_access_events": personal_data_access,
                }),
            )],
        })
    }

    pub fn generate_eu_ai_act(db: &Database) -> Result<ComplianceExport> {
        let all_events = db.list_events(10000)?;
        let authz_events: Vec<_> = all_events
            .iter()
            .filter(|e| e.source == "patroclus" && e.event_type == "authz_decision")
            .collect();
        let approvals = authz_events
            .iter()
            .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("require_approval"))
            .count();

        let mut authz_query = base_query();
        authz_query.source = Some("patroclus".to_string());
        authz_query.event_type = Some("authz_decision".to_string());

        let mut all_query = base_query();
        all_query.limit = Some(10_000);

        let mut high_query = base_query();
        high_query.severity = Some("high".to_string());

        Ok(ComplianceExport {
            report: ComplianceReport {
                framework: "EU AI Act".to_string(),
                generated_at: chrono::Utc::now(),
                disclaimer: completeness_disclaimer(),
                controls: vec![
                    Control {
                        id: "Art.14".to_string(),
                        name: "Human Oversight".to_string(),
                        status: ControlStatus::from_count(approvals),
                        evidence: vec![EvidenceRef {
                            description: "Authz decisions with decision=require_approval \
                                          (filter client-side) show human approval gates \
                                          fired and were logged."
                                .to_string(),
                            endpoint: None,
                            query: authz_query,
                        }],
                    },
                    Control {
                        id: "Art.12".to_string(),
                        name: "Logging and Record-Keeping".to_string(),
                        status: ControlStatus::from_count(all_events.len()),
                        evidence: vec![EvidenceRef {
                            description: "Automatically captured logs over the retention \
                                          window; every action traces to a principal where \
                                          attribution was provided at ingest."
                                .to_string(),
                            endpoint: None,
                            query: all_query,
                        }],
                    },
                    Control {
                        id: "Art.15".to_string(),
                        name: "Accuracy, Robustness, Cybersecurity".to_string(),
                        status: ControlStatus::RequiresReview,
                        evidence: vec![EvidenceRef {
                            description: "Rate limiting, budget caps, trust decay, and kill \
                                          switch run in Patroclus; DLP and anomaly detection \
                                          run here. Assessing effectiveness needs review of \
                                          high-severity events."
                                .to_string(),
                            endpoint: Some("/api/alerts".to_string()),
                            query: high_query.clone(),
                        }],
                    },
                    Control {
                        id: "Art.26".to_string(),
                        name: "Post-Market Monitoring".to_string(),
                        status: ControlStatus::RequiresReview,
                        evidence: vec![EvidenceRef {
                            description: "Anomaly monitoring covers spending spikes, denial \
                                          rates, off-hours activity, and bulk exports; \
                                          post-market conclusions need human analysis."
                                .to_string(),
                            endpoint: Some("/api/alerts".to_string()),
                            query: high_query,
                        }],
                    },
                ],
            },
            attachments: vec![attachment(
                "summary_counts",
                "Raw event counts observed in the retention window.",
                serde_json::json!({
                    "total_events": all_events.len(),
                    "human_oversight_events": approvals,
                }),
            )],
        })
    }

    pub fn generate_hipaa(db: &Database) -> Result<ComplianceExport> {
        let all_events = db.list_events(10000)?;
        let dlp_events = db.dlp_violations(1000)?;
        let phi_patterns = count_personal_data(&dlp_events);
        let patroclus_events = all_events
            .iter()
            .filter(|e| e.source == "patroclus")
            .count();

        let mut patroclus_query = base_query();
        patroclus_query.source = Some("patroclus".to_string());

        let mut all_query = base_query();
        all_query.limit = Some(10_000);

        Ok(ComplianceExport {
            report: ComplianceReport {
                framework: "HIPAA".to_string(),
                generated_at: chrono::Utc::now(),
                disclaimer: completeness_disclaimer(),
                controls: vec![
                    Control {
                        id: "164.312(b)".to_string(),
                        name: "Audit Controls".to_string(),
                        status: ControlStatus::from_count(all_events.len()),
                        evidence: vec![EvidenceRef {
                            description: "Audit entries for agent actions over the retention \
                                          window."
                                .to_string(),
                            endpoint: None,
                            query: all_query,
                        }],
                    },
                    Control {
                        id: "164.312(c)(1)".to_string(),
                        name: "Integrity Controls".to_string(),
                        status: ControlStatus::RequiresReview,
                        evidence: vec![EvidenceRef {
                            description: "Event storage is mutable SQLite; tamper-evident \
                                          hash chaining is a config-gated option. Verify it \
                                          is enabled and the chain verifies before relying \
                                          on integrity claims."
                                .to_string(),
                            endpoint: Some("/api/chain/verify".to_string()),
                            query: base_query(),
                        }],
                    },
                    Control {
                        id: "164.312(a)(1)".to_string(),
                        name: "Access Control".to_string(),
                        status: ControlStatus::from_count(patroclus_events),
                        evidence: vec![EvidenceRef {
                            description: "Policy decisions recorded by Patroclus \
                                          (default-deny, scoped tokens, approval workflow)."
                                .to_string(),
                            endpoint: None,
                            query: patroclus_query,
                        }],
                    },
                    Control {
                        id: "164.312(e)(1)".to_string(),
                        name: "Transmission Security".to_string(),
                        status: if phi_patterns == 0 {
                            ControlStatus::NoEvidence
                        } else {
                            ControlStatus::RequiresReview
                        },
                        evidence: vec![EvidenceRef {
                            description: "DLP detections of PHI-like patterns (SSN, phone, \
                                          email). Findings flag events for review; zero \
                                          findings may also mean no inspected traffic."
                                .to_string(),
                            endpoint: Some("/api/dlp/violations".to_string()),
                            query: base_query(),
                        }],
                    },
                ],
            },
            attachments: vec![attachment(
                "summary_counts",
                "Raw event counts observed in the retention window.",
                serde_json::json!({
                    "total_events": all_events.len(),
                    "phi_access_events": phi_patterns,
                    "dlp_violations": dlp_events.len(),
                }),
            )],
        })
    }
}

/// Events whose DLP violations include classic personal-data patterns.
fn count_personal_data(events: &[crate::events::AgentEvent]) -> usize {
    events
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
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AgentEvent, DlpViolation};
    use chrono::Utc;

    fn event(source: &str, event_type: &str, data: serde_json::Value) -> AgentEvent {
        AgentEvent {
            id: None,
            source: source.to_string(),
            session_id: Some("s-1".to_string()),
            agent_id: Some("agent-1".to_string()),
            principal_id: Some("user-1".to_string()),
            event_type: event_type.to_string(),
            severity: "info".to_string(),
            data,
            dlp_violations: None,
            anomaly_flags: None,
            timestamp: Some(Utc::now()),
        }
    }

    fn dlp_event(pattern: &str) -> AgentEvent {
        let mut e = event(
            "relay",
            "tool_call",
            serde_json::json!({"tool": "email_send"}),
        );
        e.severity = "high".to_string();
        e.dlp_violations = Some(vec![DlpViolation {
            pattern_name: pattern.to_string(),
            matched_text: "[REDACTED]".to_string(),
            severity: "high".to_string(),
            field: "body".to_string(),
        }]);
        e
    }

    /// Replay an evidence reference's stored query against the store, the
    /// same way an auditor would via `POST /api/events/query`.
    fn replay(db: &Database, r: &EvidenceRef) -> Result<Vec<AgentEvent>> {
        let q = &r.query;
        db.query_events(
            q.source.as_deref(),
            q.session_id.as_deref(),
            q.agent_id.as_deref(),
            q.event_type.as_deref(),
            q.severity.as_deref(),
            q.limit.unwrap_or(1000),
        )
    }

    #[test]
    fn report_body_has_controls_disclaimer_and_no_counts() {
        let db = Database::new_in_memory().unwrap();
        for framework in [
            ComplianceReporter::generate_soc2(&db).unwrap(),
            ComplianceReporter::generate_gdpr(&db).unwrap(),
            ComplianceReporter::generate_hipaa(&db).unwrap(),
            ComplianceReporter::generate_eu_ai_act(&db).unwrap(),
        ] {
            let report = &framework.report;
            assert!(!report.disclaimer.is_empty());
            assert!(
                report
                    .disclaimer
                    .to_ascii_lowercase()
                    .contains("data-completeness"),
                "disclaimer must be explicit: {}",
                report.disclaimer
            );
            assert!(!report.controls.is_empty(), "{}", report.framework);
            for control in &report.controls {
                assert!(!control.id.is_empty());
                assert!(!control.name.is_empty());
                assert!(!control.evidence.is_empty());
            }

            // The serialized body must not carry summary counts anywhere.
            let body = serde_json::to_value(report).unwrap();
            assert!(body.get("summary").is_none());
            let body_str = serde_json::to_string(&body).unwrap();
            assert!(
                !body_str.contains("total_events"),
                "counts leaked into report body: {body_str}"
            );
            // Counts live only in attachments.
            assert!(!framework.attachments.is_empty());
            assert_eq!(framework.attachments[0].name, "summary_counts");
        }
    }

    #[test]
    fn empty_database_never_claims_monitored() {
        let db = Database::new_in_memory().unwrap();
        for export in [
            ComplianceReporter::generate_soc2(&db).unwrap(),
            ComplianceReporter::generate_gdpr(&db).unwrap(),
            ComplianceReporter::generate_hipaa(&db).unwrap(),
            ComplianceReporter::generate_eu_ai_act(&db).unwrap(),
        ] {
            for control in &export.report.controls {
                assert_ne!(
                    control.status,
                    ControlStatus::Monitored,
                    "{} / {} claimed monitored with no evidence",
                    export.report.framework,
                    control.id
                );
            }
        }
    }

    #[test]
    fn evidence_references_replay_to_real_rows() {
        let db = Database::new_in_memory().unwrap();
        db.insert_event(&event(
            "patroclus",
            "authz_decision",
            serde_json::json!({"decision": "deny"}),
        ))
        .unwrap();

        let export = ComplianceReporter::generate_soc2(&db).unwrap();
        let cc61 = export
            .report
            .controls
            .iter()
            .find(|c| c.id == "CC6.1")
            .unwrap();
        assert_eq!(cc61.status, ControlStatus::Monitored);
        let rows = replay(&db, &cc61.evidence[0]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "patroclus");
    }

    #[test]
    fn dlp_evidence_uses_dedicated_endpoint_and_requires_review() {
        let db = Database::new_in_memory().unwrap();
        db.insert_event(&dlp_event("email")).unwrap();

        let export = ComplianceReporter::generate_gdpr(&db).unwrap();
        let art32 = export
            .report
            .controls
            .iter()
            .find(|c| c.id == "Art.32")
            .unwrap();
        assert_eq!(art32.status, ControlStatus::RequiresReview);
        assert_eq!(
            art32.evidence[0].endpoint.as_deref(),
            Some("/api/dlp/violations")
        );

        let counts = export.attachments[0].counts.clone();
        assert_eq!(counts["dlp_violations"], 1);
        assert_eq!(counts["personal_data_access_events"], 1);
    }

    #[test]
    fn export_serialization_round_trips() {
        let db = Database::new_in_memory().unwrap();
        db.insert_event(&event(
            "miser",
            "llm_cost",
            serde_json::json!({"cost": 0.5}),
        ))
        .unwrap();
        let export = ComplianceReporter::generate_soc2(&db).unwrap();
        let json = serde_json::to_string(&export).unwrap();
        let parsed: ComplianceExport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.report.framework, "SOC 2 Type II");
        assert_eq!(parsed.report.controls.len(), export.report.controls.len());
        assert_eq!(
            parsed.attachments[0].counts["total_events"],
            export.attachments[0].counts["total_events"]
        );
    }
}
