use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use sentiel::{
    anomaly::AnomalyEngine,
    compliance::ComplianceReporter,
    config::Config,
    db::Database,
    dlp::DlpEngine,
    events::{AgentEvent, CreateEvent},
};

#[derive(Parser)]
#[command(name = "sentiel")]
#[command(about = "Observability, DLP, and compliance for AI agent ecosystems")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    Init,
}

#[derive(Clone)]
struct AppState {
    db: Arc<Database>,
    dlp: Arc<DlpEngine>,
    anomaly: Arc<AnomalyEngine>,
    config: Arc<Config>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentiel=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let config = Config::default();
            let toml = toml::to_string_pretty(&config)?;
            std::fs::write("config.toml", toml)?;
            println!("Created config.toml");
        }
        Commands::Serve { config } => {
            let config = Config::load(&config).unwrap_or_default();
            let db = Database::new(&config.database.path)?;
            let dlp = Arc::new(DlpEngine::new(config.dlp.enabled));
            let anomaly = Arc::new(AnomalyEngine::new(config.anomaly.clone()));

            let state = AppState {
                db: Arc::new(db),
                dlp,
                anomaly,
                config: Arc::new(config.clone()),
            };

            let app = create_router(state);
            let addr = format!("{}:{}", config.server.host, config.server.port);
            tracing::info!("Sentiel starting on {}", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/api/events", post(ingest_event).get(list_events))
        .route("/api/events/query", get(query_events))
        .route("/api/events/session/{session_id}", get(events_by_session))
        .route("/api/events/agent/{agent_id}", get(events_by_agent))
        .route("/api/stats", get(stats))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/{id}/acknowledge", post(acknowledge_alert))
        .route("/api/dlp/inspect", post(dlp_inspect))
        .route("/api/dlp/violations", get(dlp_violations))
        .route("/api/compliance/{framework}", get(compliance_report))
        .route("/api/cost/summary", get(cost_summary))
        .route("/api/decisions/summary", get(decision_summary))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok", "service": "sentiel"})))
}

async fn dashboard() -> (StatusCode, String) {
    (StatusCode::OK, sentiel::dashboard::dashboard_html())
}

async fn ingest_event(
    State(state): State<AppState>,
    Json(req): Json<CreateEvent>,
) -> Result<Json<serde_json::Value>, sentiel::errors::SentielError> {
    let mut event = req.to_agent_event();

    // DLP inspection
    let violations = state.dlp.inspect_json(&event.data);
    if !violations.is_empty() {
        event.dlp_violations = Some(violations.clone());
        if state.dlp.has_critical_violation(&violations) {
            event.severity = "critical".to_string();
        }
    }

    // Anomaly detection
    let recent = state.db.list_events(100).unwrap_or_default();
    let alerts = state.anomaly.check_event(&event, &recent);
    if !alerts.is_empty() {
        event.anomaly_flags = Some(alerts.iter().map(|a| a.alert_type.clone()).collect());
        for alert in &alerts {
            if let Err(e) = state.db.insert_alert(alert) {
                tracing::warn!("Failed to insert alert: {}", e);
            }
        }
    }

    let id = state.db.insert_event(&event)?;
    Ok(Json(serde_json::json!({
        "id": id,
        "dlp_violations": event.dlp_violations.map(|v| v.len()).unwrap_or(0),
        "anomaly_alerts": alerts.len(),
        "severity": event.severity,
    })))
}

async fn list_events(
    State(state): State<AppState>,
    Query(params): Query<EventQueryParams>,
) -> Result<Json<Vec<AgentEvent>>, sentiel::errors::SentielError> {
    let limit = params.limit.unwrap_or(100);
    let events = state.db.query_events(
        params.source.as_deref(),
        params.session_id.as_deref(),
        params.agent_id.as_deref(),
        params.event_type.as_deref(),
        params.severity.as_deref(),
        limit,
    )?;
    Ok(Json(events))
}

#[derive(Deserialize)]
struct EventQueryParams {
    source: Option<String>,
    session_id: Option<String>,
    agent_id: Option<String>,
    event_type: Option<String>,
    severity: Option<String>,
    limit: Option<i64>,
}

async fn query_events(
    State(state): State<AppState>,
    Query(params): Query<EventQueryParams>,
) -> Result<Json<Vec<AgentEvent>>, sentiel::errors::SentielError> {
    list_events(State(state), Query(params)).await
}

async fn events_by_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<AgentEvent>>, sentiel::errors::SentielError> {
    let events = state.db.events_by_session(&session_id)?;
    Ok(Json(events))
}

async fn events_by_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<AgentEvent>>, sentiel::errors::SentielError> {
    let events = state.db.events_by_agent(&agent_id)?;
    Ok(Json(events))
}

async fn stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, sentiel::errors::SentielError> {
    let events = state.db.list_events(100000)?;
    let authz: Vec<_> = events.iter().filter(|e| e.source == "patroclus" && e.event_type == "authz_decision").collect();
    let allows = authz.iter().filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("allow")).count();
    let denies = authz.iter().filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("deny")).count();
    let dlp_count = state.db.dlp_violations(10000)?.len();
    let alerts = state.db.alerts_unacknowledged()?;

    Ok(Json(serde_json::json!({
        "total_events": events.len(),
        "authz_total": authz.len(),
        "allows": allows,
        "denies": denies,
        "dlp_violations": dlp_count,
        "active_alerts": alerts.len(),
    })))
}

async fn list_alerts(
    State(state): State<AppState>,
) -> Result<Json<Vec<sentiel::anomaly::Alert>>, sentiel::errors::SentielError> {
    let alerts = state.db.alerts_unacknowledged()?;
    Ok(Json(alerts))
}

async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, sentiel::errors::SentielError> {
    state.db.acknowledge_alert(id)?;
    Ok(Json(serde_json::json!({"acknowledged": id})))
}

#[derive(Deserialize)]
struct DlpInspectRequest {
    content: String,
}

async fn dlp_inspect(
    State(state): State<AppState>,
    Json(req): Json<DlpInspectRequest>,
) -> Result<Json<serde_json::Value>, sentiel::errors::SentielError> {
    let violations = state.dlp.inspect(&req.content);
    let redacted = state.dlp.redact_content(&req.content);
    Ok(Json(serde_json::json!({
        "violations": violations,
        "violation_count": violations.len(),
        "has_critical": state.dlp.has_critical_violation(&violations),
        "redacted_content": redacted,
    })))
}

async fn dlp_violations(
    State(state): State<AppState>,
) -> Result<Json<Vec<AgentEvent>>, sentiel::errors::SentielError> {
    let events = state.db.dlp_violations(1000)?;
    Ok(Json(events))
}

async fn compliance_report(
    State(state): State<AppState>,
    Path(framework): Path<String>,
) -> Result<Json<serde_json::Value>, sentiel::errors::SentielError> {
    let report = match framework.as_str() {
        "soc2" => ComplianceReporter::generate_soc2(&state.db)?,
        "gdpr" => ComplianceReporter::generate_gdpr(&state.db)?,
        "eu_ai_act" => ComplianceReporter::generate_eu_ai_act(&state.db)?,
        "hipaa" => ComplianceReporter::generate_hipaa(&state.db)?,
        _ => return Err(sentiel::errors::SentielError::NotFound("unknown framework".to_string())),
    };
    Ok(Json(serde_json::to_value(&report).unwrap()))
}

async fn cost_summary(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, sentiel::errors::SentielError> {
    let summary = state.db.cost_summary()?;
    Ok(Json(summary))
}

async fn decision_summary(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, sentiel::errors::SentielError> {
    let summary = state.db.decision_summary()?;
    Ok(Json(summary))
}
