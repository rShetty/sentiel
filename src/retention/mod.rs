//! Event retention: background pruning plus cumulative prune counters.
//!
//! [`pruning_loop`] runs forever on a tokio timer, deleting rows older than
//! the configured retention window and recording what it removed in
//! [`PruneStats`]. The same stats are updated by the manual admin endpoint so
//! `/api/stats` reflects both automatic and manual pruning.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tokio::time::{MissedTickBehavior, interval};

use crate::db::{Database, PruneReport};

/// Cumulative pruning counters shared between the background loop and the
/// manual admin endpoint.
#[derive(Debug, Default)]
pub struct PruneStats {
    events_pruned: Mutex<u64>,
    alerts_pruned: Mutex<u64>,
    last_pruned_at: Mutex<Option<DateTime<Utc>>>,
}

impl PruneStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one pruning pass into the cumulative counters.
    pub fn record(&self, report: &PruneReport) {
        *self.events_pruned.lock() += report.events_deleted as u64;
        *self.alerts_pruned.lock() += report.alerts_deleted as u64;
        *self.last_pruned_at.lock() = Some(Utc::now());
    }

    pub fn events_pruned(&self) -> u64 {
        *self.events_pruned.lock()
    }

    pub fn alerts_pruned(&self) -> u64 {
        *self.alerts_pruned.lock()
    }

    pub fn last_pruned_at(&self) -> Option<DateTime<Utc>> {
        *self.last_pruned_at.lock()
    }
}

/// Background task that prunes expired rows on a fixed interval.
///
/// The first pass runs immediately (tokio intervals fire at t=0), so a fresh
/// start cleans out anything that expired while the service was down.
pub async fn pruning_loop(
    db: Arc<Database>,
    retention_days: u32,
    interval_secs: u64,
    stats: Arc<PruneStats>,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        match db.prune_expired(retention_days) {
            Ok(report) if !report.is_zero() => {
                tracing::info!(
                    "pruned {} events and {} alerts older than {retention_days} days",
                    report.events_deleted,
                    report.alerts_deleted
                );
                stats.record(&report);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("retention pruning failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::Alert;
    use crate::events::AgentEvent;
    use chrono::Duration as ChronoDuration;
    use serde_json::json;

    fn event_at(age_days: i64) -> AgentEvent {
        let mut event = AgentEvent {
            id: None,
            source: "miser".to_string(),
            session_id: None,
            agent_id: None,
            principal_id: None,
            event_type: "llm_cost".to_string(),
            severity: "info".to_string(),
            data: json!({"cost": 0.01}),
            dlp_violations: None,
            anomaly_flags: None,
            timestamp: Some(Utc::now() - ChronoDuration::days(age_days)),
        };
        event.id = Some(uuid::Uuid::now_v7());
        event
    }

    fn alert_at(age_days: i64) -> Alert {
        Alert {
            id: uuid::Uuid::now_v7(),
            session_id: None,
            agent_id: None,
            alert_type: "spending_spike".to_string(),
            severity: "high".to_string(),
            message: "test alert".to_string(),
            data: None,
            acknowledged: false,
            created_at: Utc::now() - ChronoDuration::days(age_days),
            acknowledged_at: None,
        }
    }

    #[test]
    fn prune_deletes_only_rows_older_than_retention() {
        let db = Database::new_in_memory().expect("in-memory db");
        db.insert_event(&event_at(100)).unwrap();
        db.insert_event(&event_at(89)).unwrap();
        db.insert_alert(&alert_at(200)).unwrap();
        db.insert_alert(&alert_at(1)).unwrap();

        let report = db.prune_expired(90).unwrap();

        assert_eq!(report.events_deleted, 1);
        assert_eq!(report.alerts_deleted, 1);
        assert_eq!(db.list_events(100).unwrap().len(), 1);
        assert_eq!(db.alerts_unacknowledged().unwrap().len(), 1);
    }

    #[test]
    fn second_prune_pass_is_a_noop() {
        let db = Database::new_in_memory().expect("in-memory db");
        db.insert_event(&event_at(365)).unwrap();
        db.prune_expired(90).unwrap();

        let report = db.prune_expired(90).unwrap();

        assert!(report.is_zero());
    }

    #[test]
    fn zero_retention_prunes_everything() {
        let db = Database::new_in_memory().expect("in-memory db");
        db.insert_event(&event_at(0)).unwrap();
        db.insert_alert(&alert_at(0)).unwrap();

        let report = db.prune_expired(0).unwrap();

        assert_eq!(report.events_deleted, 1);
        assert_eq!(report.alerts_deleted, 1);
    }

    #[test]
    fn stats_accumulate_across_passes() {
        let stats = PruneStats::new();
        assert_eq!(stats.events_pruned(), 0);
        assert_eq!(stats.last_pruned_at(), None);

        stats.record(&PruneReport {
            events_deleted: 3,
            alerts_deleted: 1,
        });
        stats.record(&PruneReport {
            events_deleted: 2,
            alerts_deleted: 0,
        });

        assert_eq!(stats.events_pruned(), 5);
        assert_eq!(stats.alerts_pruned(), 1);
        assert!(stats.last_pruned_at().is_some());
    }

    #[tokio::test]
    async fn background_loop_prunes_expired_rows() {
        let db = Arc::new(Database::new_in_memory().expect("in-memory db"));
        db.insert_event(&event_at(400)).unwrap();
        db.insert_event(&event_at(0)).unwrap();
        db.insert_alert(&alert_at(400)).unwrap();
        let stats = Arc::new(PruneStats::new());

        // First tick fires immediately; paused time lets the spawned task run.
        let handle = tokio::spawn(pruning_loop(Arc::clone(&db), 90, 3600, Arc::clone(&stats)));
        tokio::time::sleep(Duration::from_secs(1)).await;
        handle.abort();

        assert_eq!(db.list_events(100).unwrap().len(), 1);
        assert_eq!(db.alerts_unacknowledged().unwrap().len(), 0);
        assert_eq!(stats.events_pruned(), 1);
        assert_eq!(stats.alerts_pruned(), 1);
    }
}
