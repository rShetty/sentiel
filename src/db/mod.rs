use std::sync::Arc;

use chrono::Utc;
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::errors::{Result, SentielError};
use crate::events::AgentEvent;

pub struct Database {
    conn: Arc<parking_lot::Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| SentielError::Database(format!("failed to open database: {}", e)))?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Self::run_migrations(&conn)?;
        Ok(Database {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        })
    }

    /// Open a transient in-memory database. Intended for tests.
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| SentielError::Database(format!("failed to open database: {}", e)))?;
        Self::run_migrations(&conn)?;
        Ok(Database {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        })
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
        Ok(())
    }

    pub fn insert_event(&self, event: &AgentEvent) -> Result<Uuid> {
        let conn = self.conn.lock();
        let id = event.id.unwrap_or_else(Uuid::now_v7);
        let now = event.timestamp.unwrap_or_else(Utc::now);
        conn.execute(
            "INSERT INTO events (id, source, session_id, agent_id, principal_id, event_type, severity, data, dlp_violations, anomaly_flags, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            ],
        )?;
        Ok(id)
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
