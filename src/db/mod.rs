use std::sync::Arc;

use chrono::{Duration, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::{BreakReason, BrokenLink, ChainVerdict};
use crate::errors::{Result, SentielError};
use crate::events::AgentEvent;

pub struct Database {
    conn: Arc<parking_lot::Mutex<Connection>>,
    /// When true, inserts extend the tamper-evidence hash chain.
    chain_enabled: bool,
}

/// Rows removed by a single pruning pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    pub events_deleted: usize,
    pub alerts_deleted: usize,
}

impl PruneReport {
    /// Whether this pass removed nothing.
    pub fn is_zero(&self) -> bool {
        self.events_deleted == 0 && self.alerts_deleted == 0
    }
}

impl Database {
    /// Cheap liveness probe for the database: runs a trivial query.
    pub fn health_check(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }

    pub fn new(path: &str) -> Result<Self> {
        Self::open(Connection::open(path)?)
    }

    /// Open a transient in-memory database. Intended for tests.
    pub fn new_in_memory() -> Result<Self> {
        Self::open(Connection::open_in_memory()?)
    }

    fn open(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Self::run_migrations(&conn)?;
        Ok(Database {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
            chain_enabled: false,
        })
    }

    /// Enable hash-chained (tamper-evident) event storage.
    ///
    /// Must be called before the first insert; the chain is seeded at row 1
    /// and every chained insert extends it. See [`crate::audit`].
    pub fn with_event_chaining(mut self) -> Self {
        self.chain_enabled = true;
        self
    }

    /// Whether inserts extend the tamper-evidence hash chain.
    pub fn chaining_enabled(&self) -> bool {
        self.chain_enabled
    }

    /// Direct connection access, tests only: lets integration tests simulate
    /// out-of-band tampering (UPDATE/DELETE against stored rows) exactly as
    /// an attacker with database write access would.
    #[cfg(test)]
    pub fn conn_for_tests(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    /// A test-only view of the same connection with chaining switched on,
    /// used to simulate the config flip on an existing database.
    #[cfg(test)]
    pub fn clone_with_chaining_for_tests(self) -> Self {
        Self {
            conn: self.conn,
            chain_enabled: true,
        }
    }

    fn run_migrations(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                session_id TEXT,
                agent_id TEXT,
                principal_id TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                data TEXT NOT NULL,
                dlp_violations TEXT,
                anomaly_flags TEXT,
                timestamp TEXT NOT NULL
            );

            -- Chain columns (`seq`, `prev_hash`, `row_hash`) are added
            -- separately with a column-existence check: `ALTER TABLE ADD
            -- COLUMN` is not idempotent in SQLite and must not fail on the
            -- second startup against an already-migrated file. The `seq`
            -- index is created after those columns exist (see below).

            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                agent_id TEXT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                data TEXT,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
            ",
        )?;
        Self::add_chain_columns(conn)?;
        Ok(())
    }

    /// Ensure the hash-chain columns exist on `events` (idempotent).
    ///
    /// Kept out of the SQL batch because SQLite has no `ADD COLUMN IF NOT
    /// EXISTS`; re-running it on an already-migrated database must not fail
    /// startup.
    fn add_chain_columns(conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare("PRAGMA table_info(events)")?;
        let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
        let mut existing: std::collections::HashSet<String> = std::collections::HashSet::new();
        for name in names {
            existing.insert(name?);
        }

        const CHAIN_COLUMNS: [(&str, &str); 3] = [
            ("seq", "INTEGER"),
            ("prev_hash", "TEXT"),
            ("row_hash", "TEXT"),
        ];
        for (name, col_type) in CHAIN_COLUMNS {
            if !existing.contains(name) {
                conn.execute(
                    &format!("ALTER TABLE events ADD COLUMN {name} {col_type}"),
                    [],
                )?;
            }
        }

        // Only after the columns exist: unique chain positions, ignoring the
        // unchained (NULL-seq) rows.
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_seq
             ON events(seq) WHERE seq IS NOT NULL;",
        )?;
        Ok(())
    }

    /// Insert an event, extending the tamper-evidence hash chain when
    /// chaining is enabled ([`Database::with_event_chaining`]).
    pub fn insert_event(&self, event: &AgentEvent) -> Result<Uuid> {
        let conn = self.conn.lock();
        let id = event.id.unwrap_or_else(Uuid::now_v7);
        let now = event.timestamp.unwrap_or_else(Utc::now);

        // Chain position and hashes. When chaining is off these stay NULL and
        // the insert is byte-for-byte the pre-chain behavior.
        let (seq, prev_hash, row_hash): (Option<i64>, Option<String>, Option<String>) =
            if self.chain_enabled {
                let seq = Self::next_seq(&conn)?;
                let prev = Self::prev_head_hash(&conn, seq)?;
                let data_json = event.data.to_string();
                let dlp_json = event
                    .dlp_violations
                    .as_ref()
                    .map(|v| serde_json::to_string(v).unwrap_or_default())
                    .unwrap_or_default();
                let anomaly_json = event
                    .anomaly_flags
                    .as_ref()
                    .map(|v| serde_json::to_string(v).unwrap_or_default())
                    .unwrap_or_default();
                let ts_rfc3339 = now.to_rfc3339();
                let (_, hash) = crate::audit::ChainInput {
                    seq,
                    prev_hash: &prev,
                    fields: Self::chain_fields(
                        &id.to_string(),
                        event,
                        &data_json,
                        &dlp_json,
                        &anomaly_json,
                        &ts_rfc3339,
                    ),
                }
                .chain_entry();
                (Some(seq as i64), Some(prev), Some(hash))
            } else {
                (None, None, None)
            };

        conn.execute(
            "INSERT INTO events (id, source, session_id, agent_id, principal_id, event_type, severity, data, dlp_violations, anomaly_flags, timestamp, seq, prev_hash, row_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                id.to_string(),
                event.source,
                event.session_id,
                event.agent_id,
                event.principal_id,
                event.event_type,
                event.severity,
                event.data.to_string(),
                event.dlp_violations.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
                event.anomaly_flags.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
                now.to_rfc3339(),
                seq,
                prev_hash,
                row_hash,
            ],
        )?;
        Ok(id)
    }

    /// Next chain position: one past the highest stored `seq` (1 for the
    /// first row). Rows inserted while chaining was disabled carry `seq IS
    /// NULL`, do not occupy a position, and are reported by the verifier.
    fn next_seq(conn: &Connection) -> Result<u64> {
        let max: Option<i64> =
            conn.query_row("SELECT MAX(seq) FROM events", [], |row| row.get(0))?;
        Ok(max.map(|m| (m as u64) + 1).unwrap_or(1))
    }

    /// Hash of the row preceding `seq` (genesis for seq 1).
    fn prev_head_hash(conn: &Connection, seq: u64) -> Result<String> {
        if seq == 1 {
            return Ok(crate::audit::GENESIS.to_string());
        }
        let head: Option<String> = conn.query_row(
            "SELECT row_hash FROM events WHERE seq = ?",
            params![(seq - 1) as i64],
            |row| row.get(0),
        )?;
        head.ok_or_else(|| {
            SentielError::Database(format!(
                "chain predecessor seq {} is missing its row_hash",
                seq - 1
            ))
        })
    }

    /// Stored-field tuple for hashing, in [`crate::audit::HASHED_FIELDS`]
    /// order. Empty string stands in for SQL `NULL` so the canonical bytes
    /// are stable.
    fn chain_fields(
        id: &str,
        event: &AgentEvent,
        data_json: &str,
        dlp_json: &str,
        anomaly_json: &str,
        timestamp_rfc3339: &str,
    ) -> [String; crate::audit::HASHED_FIELDS.len()] {
        [
            id.to_string(),
            event.source.clone(),
            event.session_id.clone().unwrap_or_default(),
            event.agent_id.clone().unwrap_or_default(),
            event.principal_id.clone().unwrap_or_default(),
            event.event_type.clone(),
            event.severity.clone(),
            data_json.to_string(),
            dlp_json.to_string(),
            anomaly_json.to_string(),
            timestamp_rfc3339.to_string(),
        ]
    }

    /// Walk the event hash chain in `seq` order and report the first broken
    /// link.
    ///
    /// For each chained row (in ascending `seq`):
    ///
    /// 1. recompute `row_hash` from the row's stored contents — a mismatch
    ///    means the row was modified after insertion;
    /// 2. check the stored `prev_hash` equals the previous row's `row_hash` —
    ///    a mismatch means rows were deleted or links were re-stamped.
    ///
    /// The first failure wins; later rows are not examined, so the reported
    /// `at_seq` is the earliest evidence of tampering. Rows with `seq IS
    /// NULL` (pre-chain inserts) do not break the walk but are counted in
    /// `unchained_events` so the report covers the whole table.
    pub fn verify_event_chain(&self) -> Result<crate::audit::ChainVerification> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT seq, prev_hash, row_hash,
                    id, source, session_id, agent_id, principal_id, event_type,
                    severity, data, dlp_violations, anomaly_flags, timestamp
             FROM events
             WHERE seq IS NOT NULL
             ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                (
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, String>(13)?,
                ),
            ))
        })?;

        let mut verified: u64 = 0;
        let mut head: String = crate::audit::GENESIS.to_string();
        let mut verdict = None;

        for (position, row) in rows.enumerate() {
            // Chain positions are 1-based; `position` is the 0-based index of
            // the row we expect here, so the expected seq is position + 1.
            let expected_seq = position as u64 + 1;
            let (seq, prev_hash, row_hash, fields) = row?;
            let seq = u64::try_from(seq).map_err(|_| {
                SentielError::Database(format!("negative chain seq {seq} in events table"))
            })?;

            // Gap in the sequence: rows were deleted.
            if seq != expected_seq {
                verdict = Some(ChainVerdict::Broken(BrokenLink {
                    at_seq: expected_seq,
                    kind: BreakReason::LinkMismatch,
                }));
                break;
            }

            let stored_prev = prev_hash.as_deref().unwrap_or("");
            let stored_hash = row_hash.as_deref().unwrap_or("");

            // Link integrity first: does this row claim the right ancestor?
            if stored_prev != head {
                verdict = Some(ChainVerdict::Broken(BrokenLink {
                    at_seq: seq,
                    kind: BreakReason::LinkMismatch,
                }));
                break;
            }

            // Row integrity: does the stored hash match the row's contents?
            let (_, computed) = crate::audit::ChainInput {
                seq,
                prev_hash: stored_prev,
                fields: [
                    fields.0,
                    fields.1,
                    fields.2.unwrap_or_default(),
                    fields.3.unwrap_or_default(),
                    fields.4.unwrap_or_default(),
                    fields.5,
                    fields.6,
                    fields.7,
                    fields.8.unwrap_or_default(),
                    fields.9.unwrap_or_default(),
                    fields.10,
                ],
            }
            .chain_entry();

            if computed != stored_hash {
                verdict = Some(ChainVerdict::Broken(BrokenLink {
                    at_seq: seq,
                    kind: BreakReason::RowModified,
                }));
                break;
            }

            head = stored_hash.to_string();
            verified += 1;
        }

        let total: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        let chained: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE seq IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let unchained = u64::try_from(total - chained).map_err(|_| {
            SentielError::Database("more chained rows than total events".to_string())
        })?;

        let verdict = verdict.unwrap_or(ChainVerdict::Intact {
            verified_rows: verified,
            head_hash: head,
        });

        Ok(crate::audit::ChainVerification {
            total_events: u64::try_from(total)
                .map_err(|_| SentielError::Database("negative event count".to_string()))?,
            unchained_events: unchained,
            verdict,
        })
    }

    pub fn list_events(&self, limit: i64) -> Result<Vec<AgentEvent>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, source, session_id, agent_id, principal_id, event_type, severity, data, dlp_violations, anomaly_flags, timestamp
             FROM events ORDER BY timestamp DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit], Self::row_to_event)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn query_events(
        &self,
        source: Option<&str>,
        session_id: Option<&str>,
        agent_id: Option<&str>,
        event_type: Option<&str>,
        severity: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AgentEvent>> {
        let conn = self.conn.lock();
        let mut sql = String::from(
            "SELECT id, source, session_id, agent_id, principal_id, event_type, severity, data, dlp_violations, anomaly_flags, timestamp
             FROM events WHERE 1=1",
        );
        let mut params_vec: Vec<String> = Vec::new();

        if let Some(v) = source {
            sql.push_str(" AND source = ?");
            params_vec.push(v.to_string());
        }
        if let Some(v) = session_id {
            sql.push_str(" AND session_id = ?");
            params_vec.push(v.to_string());
        }
        if let Some(v) = agent_id {
            sql.push_str(" AND agent_id = ?");
            params_vec.push(v.to_string());
        }
        if let Some(v) = event_type {
            sql.push_str(" AND event_type = ?");
            params_vec.push(v.to_string());
        }
        if let Some(v) = severity {
            sql.push_str(" AND severity = ?");
            params_vec.push(v.to_string());
        }
        sql.push_str(" ORDER BY timestamp DESC LIMIT ?");

        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params_vec
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .chain(std::iter::once(&limit as &dyn rusqlite::ToSql))
            .collect();

        let rows = stmt.query_map(param_refs.as_slice(), Self::row_to_event)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn events_by_session(&self, session_id: &str) -> Result<Vec<AgentEvent>> {
        self.query_events(None, Some(session_id), None, None, None, 1000)
    }

    pub fn events_by_agent(&self, agent_id: &str) -> Result<Vec<AgentEvent>> {
        self.query_events(None, None, Some(agent_id), None, None, 1000)
    }

    pub fn events_by_source(&self, source: &str) -> Result<Vec<AgentEvent>> {
        self.query_events(Some(source), None, None, None, None, 1000)
    }

    pub fn dlp_violations(&self, limit: i64) -> Result<Vec<AgentEvent>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, source, session_id, agent_id, principal_id, event_type, severity, data, dlp_violations, anomaly_flags, timestamp
             FROM events WHERE dlp_violations IS NOT NULL AND dlp_violations != 'null' AND dlp_violations != '[]'
             ORDER BY timestamp DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit], Self::row_to_event)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn alerts_unacknowledged(&self) -> Result<Vec<crate::anomaly::Alert>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, agent_id, alert_type, severity, message, data, acknowledged, created_at, acknowledged_at
             FROM alerts WHERE acknowledged = 0 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let session_id: Option<String> = row.get(1)?;
            let agent_id: Option<String> = row.get(2)?;
            let data_str: Option<String> = row.get(6)?;
            let acked_at: Option<String> = row.get(9)?;
            Ok(crate::anomaly::Alert {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                session_id,
                agent_id,
                alert_type: row.get(3)?,
                severity: row.get(4)?,
                message: row.get(5)?,
                data: data_str.and_then(|s| serde_json::from_str(&s).ok()),
                acknowledged: row.get::<_, i64>(7)? != 0,
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or(Utc::now()),
                acknowledged_at: acked_at
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                    .map(|d| d.with_timezone(&Utc)),
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn insert_alert(&self, alert: &crate::anomaly::Alert) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO alerts (id, session_id, agent_id, alert_type, severity, message, data, acknowledged, created_at, acknowledged_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, NULL)",
            params![
                alert.id.to_string(),
                alert.session_id,
                alert.agent_id,
                alert.alert_type,
                alert.severity,
                alert.message,
                alert.data.as_ref().map(|v| v.to_string()),
                alert.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn acknowledge_alert(&self, id: Uuid) -> Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
            params![now, id.to_string()],
        )?;
        if conn.changes() == 0 {
            return Err(SentielError::NotFound("alert not found".to_string()));
        }
        Ok(())
    }

    /// Delete events and alerts older than `retention_days`.
    ///
    /// DLP violations are stored on events, so pruning events covers them.
    /// Returns how many rows of each kind were removed.
    pub fn prune_expired(&self, retention_days: u32) -> Result<PruneReport> {
        let cutoff = (Utc::now() - Duration::days(i64::from(retention_days))).to_rfc3339();
        let conn = self.conn.lock();
        let events_deleted =
            conn.execute("DELETE FROM events WHERE timestamp < ?", params![cutoff])?;
        let alerts_deleted =
            conn.execute("DELETE FROM alerts WHERE created_at < ?", params![cutoff])?;
        Ok(PruneReport {
            events_deleted,
            alerts_deleted,
        })
    }

    pub fn cost_summary(&self) -> Result<serde_json::Value> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT
                COALESCE(agent_id, 'unknown') as agent,
                COUNT(*) as event_count,
                SUM(CASE WHEN event_type = 'llm_cost' THEN json_extract(data, '$.cost') ELSE 0 END) as total_cost
             FROM events
             GROUP BY COALESCE(agent_id, 'unknown')
             ORDER BY total_cost DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "agent_id": row.get::<_, String>(0)?,
                "event_count": row.get::<_, i64>(1)?,
                "total_cost": row.get::<_, Option<f64>>(2)?.unwrap_or(0.0),
            }))
        })?;
        let mut agents = Vec::new();
        for row in rows {
            agents.push(row?);
        }
        Ok(serde_json::json!({ "agents": agents }))
    }

    pub fn decision_summary(&self) -> Result<serde_json::Value> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT
                json_extract(data, '$.decision') as decision,
                COUNT(*) as count
             FROM events
             WHERE source = 'patroclus' AND event_type = 'authz_decision'
             GROUP BY json_extract(data, '$.decision')",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "decision": row.get::<_, Option<String>>(0)?.unwrap_or("unknown".to_string()),
                "count": row.get::<_, i64>(1)?,
            }))
        })?;
        let mut decisions = Vec::new();
        for row in rows {
            decisions.push(row?);
        }
        Ok(serde_json::json!({ "decisions": decisions }))
    }

    fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AgentEvent> {
        let dlp_str: Option<String> = row.get(8)?;
        let anomaly_str: Option<String> = row.get(9)?;
        let ts_str: String = row.get(10)?;
        Ok(AgentEvent {
            id: Uuid::parse_str(&row.get::<_, String>(0)?).ok(),
            source: row.get(1)?,
            session_id: row.get(2)?,
            agent_id: row.get(3)?,
            principal_id: row.get(4)?,
            event_type: row.get(5)?,
            severity: row.get(6)?,
            data: serde_json::from_str(&row.get::<_, String>(7)?)
                .unwrap_or(serde_json::Value::Null),
            dlp_violations: dlp_str.and_then(|s| serde_json::from_str(&s).ok()),
            anomaly_flags: anomaly_str.and_then(|s| serde_json::from_str(&s).ok()),
            timestamp: chrono::DateTime::parse_from_rfc3339(&ts_str)
                .ok()
                .map(|d| d.with_timezone(&Utc)),
        })
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::audit::BrokenLink;

    fn plain_event(cost: f64) -> AgentEvent {
        AgentEvent {
            id: None,
            source: "miser".to_string(),
            session_id: Some("chain-s".to_string()),
            agent_id: None,
            principal_id: None,
            event_type: "llm_cost".to_string(),
            severity: "info".to_string(),
            data: serde_json::json!({"cost": cost}),
            dlp_violations: None,
            anomaly_flags: None,
            timestamp: None,
        }
    }

    #[test]
    fn chaining_is_off_by_default() {
        let db = Database::new_in_memory().unwrap();
        assert!(!db.chaining_enabled());
        db.insert_event(&plain_event(0.01)).unwrap();

        // No chain metadata written when disabled.
        let conn = db.conn_for_tests();
        let (seq, prev, hash): (Option<i64>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT seq, prev_hash, row_hash FROM events LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(seq.is_none() && prev.is_none() && hash.is_none());
    }

    #[test]
    fn chained_inserts_form_a_verifiable_chain() {
        let db = Database::new_in_memory().unwrap().with_event_chaining();
        for i in 0..5 {
            db.insert_event(&plain_event(0.01 * f64::from(i))).unwrap();
        }
        assert!(db.chaining_enabled());

        let report = db.verify_event_chain().unwrap();
        assert_eq!(report.total_events, 5);
        assert_eq!(report.unchained_events, 0);
        match &report.verdict {
            ChainVerdict::Intact {
                verified_rows,
                head_hash,
            } => {
                assert_eq!(*verified_rows, 5);
                assert_ne!(head_hash, crate::audit::GENESIS);
                assert_eq!(head_hash.len(), 64);
            }
            other => panic!("expected intact chain, got {other:?}"),
        }
        assert!(report.is_intact());
    }

    #[test]
    fn empty_store_verifies_intact() {
        let db = Database::new_in_memory().unwrap();
        let report = db.verify_event_chain().unwrap();
        assert_eq!(report.total_events, 0);
        assert!(report.is_intact());
        match report.verdict {
            ChainVerdict::Intact { verified_rows, .. } => assert_eq!(verified_rows, 0),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn modified_row_is_the_first_reported_break() {
        let db = Database::new_in_memory().unwrap().with_event_chaining();
        for i in 0..4 {
            db.insert_event(&plain_event(f64::from(i))).unwrap();
        }

        // Tamper with row 3 (1-based seq): rewrite its stored payload.
        let n = db
            .conn_for_tests()
            .execute(
                "UPDATE events SET data = ? WHERE seq = 3",
                params![r#"{"cost":42.0}"#],
            )
            .unwrap();
        assert_eq!(n, 1);

        let report = db.verify_event_chain().unwrap();
        assert!(!report.is_intact());
        match report.verdict {
            ChainVerdict::Broken(ref link) => {
                assert_eq!(link.at_seq, 3, "must report first broken link");
                assert_eq!(link.kind, BreakReason::RowModified);
            }
            other => panic!("expected broken verdict, got {other:?}"),
        }
    }

    #[test]
    fn severity_edit_is_detected_without_rehash() {
        let db = Database::new_in_memory().unwrap().with_event_chaining();
        db.insert_event(&plain_event(0.01)).unwrap();
        db.insert_event(&plain_event(0.02)).unwrap();

        db.conn_for_tests()
            .execute("UPDATE events SET severity = 'critical' WHERE seq = 1", [])
            .unwrap();

        let report = db.verify_event_chain().unwrap();
        assert!(
            matches!(
                report.verdict,
                ChainVerdict::Broken(BrokenLink {
                    at_seq: 1,
                    kind: BreakReason::RowModified
                })
            ),
            "severity edit must break the chain: {:?}",
            report.verdict
        );
    }

    #[test]
    fn deleted_middle_row_reports_link_mismatch_at_gap() {
        let db = Database::new_in_memory().unwrap().with_event_chaining();
        for i in 0..4 {
            db.insert_event(&plain_event(f64::from(i))).unwrap();
        }

        let deleted = db
            .conn_for_tests()
            .execute("DELETE FROM events WHERE seq = 2", [])
            .unwrap();
        assert_eq!(deleted, 1);

        let report = db.verify_event_chain().unwrap();
        assert!(!report.is_intact());
        match report.verdict {
            ChainVerdict::Broken(ref link) => {
                // The gap is where seq 2 used to be; the surviving rows
                // renumber to 1..3, so seq 2 now carries a stale prev_hash.
                assert_eq!(link.at_seq, 2);
                assert_eq!(link.kind, BreakReason::LinkMismatch);
            }
            other => panic!("expected broken verdict, got {other:?}"),
        }
    }

    #[test]
    fn deleting_the_head_row_leaves_an_intact_prefix() {
        // Removing only the newest row cannot be detected from inside the
        // chain (nothing references it) — an honest limitation of
        // prev-hash chaining; external notarization covers it.
        let db = Database::new_in_memory().unwrap().with_event_chaining();
        db.insert_event(&plain_event(0.01)).unwrap();
        db.insert_event(&plain_event(0.02)).unwrap();

        db.conn_for_tests()
            .execute("DELETE FROM events WHERE seq = 2", [])
            .unwrap();

        let report = db.verify_event_chain().unwrap();
        match report.verdict {
            ChainVerdict::Intact { verified_rows, .. } => assert_eq!(verified_rows, 1),
            other => panic!("head deletion is undetectable by design: {other:?}"),
        }
        assert_eq!(report.total_events, 1);
    }

    #[test]
    fn unchained_rows_are_counted_not_ignored() {
        // Simulate chaining being enabled on an existing database that
        // already holds rows.
        let db = Database::new_in_memory().unwrap();
        db.insert_event(&plain_event(0.01)).unwrap();
        db.insert_event(&plain_event(0.02)).unwrap();
        let chained = db.clone_with_chaining_for_tests();
        chained.insert_event(&plain_event(0.03)).unwrap();

        let report = chained.verify_event_chain().unwrap();
        assert_eq!(report.total_events, 3);
        assert_eq!(report.unchained_events, 2);
        assert!(
            !report.is_intact(),
            "store with unchained rows must not claim intact"
        );
        // The chained suffix itself verifies.
        match report.verdict {
            ChainVerdict::Intact { verified_rows, .. } => assert_eq!(verified_rows, 1),
            other => panic!("chained suffix should verify: {other:?}"),
        }
    }

    #[test]
    fn restart_against_existing_file_keeps_extending_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.db");
        let path_str = path.to_str().unwrap();

        {
            let db = Database::new(path_str).unwrap().with_event_chaining();
            db.insert_event(&plain_event(0.01)).unwrap();
            db.insert_event(&plain_event(0.02)).unwrap();
        }
        // "Restart": reopen the same file, keep chaining.
        {
            let db = Database::new(path_str).unwrap().with_event_chaining();
            db.insert_event(&plain_event(0.03)).unwrap();

            let report = db.verify_event_chain().unwrap();
            assert_eq!(report.total_events, 3);
            assert!(
                matches!(
                    report.verdict,
                    ChainVerdict::Intact {
                        verified_rows: 3,
                        ..
                    }
                ),
                "chain must continue across restarts: {:?}",
                report.verdict
            );
        }
        // And once more without chaining enabled — verifier still walks.
        {
            let db = Database::new(path_str).unwrap();
            assert!(!db.chaining_enabled());
            let report = db.verify_event_chain().unwrap();
            assert_eq!(report.total_events, 3);
            assert_eq!(report.unchained_events, 0);
        }
    }

    #[test]
    fn migrations_are_idempotent_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("migrate.db");
        let path_str = path.to_str().unwrap();
        Database::new(path_str).unwrap();
        Database::new(path_str).unwrap();
        let db = Database::new(path_str).unwrap().with_event_chaining();
        db.insert_event(&plain_event(0.01)).unwrap();
        assert!(db.verify_event_chain().unwrap().is_intact());
    }
}
