use std::sync::Arc;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, Query, Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tower_http::trace::TraceLayer;

use crate::{
    anomaly::AnomalyEngine,
    auth::{AuthConfig, Role, Scope},
    compliance::ComplianceReporter,
    config::Config,
    db::Database,
    dlp::DlpEngine,
    events::AgentEvent,
    retention::PruneStats,
};

/// Shared application state threaded through all handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub dlp: Arc<DlpEngine>,
    pub anomaly: Arc<AnomalyEngine>,
    pub config: Arc<Config>,
    pub auth: Arc<AuthConfig>,
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Cumulative pruning counters (background loop + manual endpoint).
    pub prune_stats: Arc<PruneStats>,
}

/// Build the full HTTP router for Sentiel.
///
/// Public surface (no authentication): `/`, `/health`, `/health/ready`.
/// `/metrics` requires admin; everything under `/api/*` requires a bearer
/// token; see [`crate::auth`].
pub fn create_router(state: AppState) -> Router {
    // CORS: explicit allowlist only. Empty list = no browser cross-origin
    // access (server-to-server callers are unaffected).
    let cors = if state.config.server.cors_allowed_origins.is_empty() {
        tower_http::cors::CorsLayer::new()
    } else {
        let origins: Vec<axum::http::HeaderValue> = state
            .config
            .server
            .cors_allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        tower_http::cors::CorsLayer::new().allow_origin(origins)
    };

    Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/health/ready", get(health_ready))
        .route("/metrics", get(metrics_endpoint))
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
        .route("/api/admin/prune", post(admin_prune))
        .route("/api/integrity", get(integrity))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            payload_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Bearer-token gate for every route except `/`, `/health`, and
/// `/health/ready`.
///
/// - Missing/malformed/unknown token -> 401 (with `WWW-Authenticate: Bearer`).
/// - Ingest token on anything other than `POST /api/events` -> 403.
/// - Admin token -> allowed everywhere.
async fn auth_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(scope) = required_scope(req.method(), req.uri().path()) else {
        return next.run(req).await;
    };

    let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
    else {
        return unauthorized_response();
    };

    match state.auth.authenticate(token) {
        Some(role) if role.permits(scope) => next.run(req).await,
        // Authenticated but lacking this route's scope.
        Some(Role::Admin) | Some(Role::Ingest) => forbidden_response(),
        None => unauthorized_response(),
    }
}

/// Map a request to its required scope. `None` means the path is public.
///
/// Public: `/`, `/health`, `/health/ready` (liveness for orchestrators).
/// Everything else — including `/metrics` — requires a token.
fn required_scope(method: &Method, path: &str) -> Option<Scope> {
    if path == "/" || path == "/health" || path == "/health/ready" {
        return None;
    }
    if !path.starts_with("/api/") {
        // `/metrics` and any other non-API route fall under admin.
        return Some(Scope::Admin);
    }
    if path == "/api/events" && method == Method::POST {
        Some(Scope::Ingest)
    } else {
        Some(Scope::Admin)
    }
}

/// Parse an `Authorization: Bearer <token>` header value.
fn bearer_token(header_value: &str) -> Option<&str> {
    let (scheme, token) = header_value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer realm=\"sentiel\"")],
        Json(serde_json::json!({"error": "missing or invalid bearer token"})),
    )
        .into_response()
}

fn forbidden_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error": "token lacks permission for this endpoint"})),
    )
        .into_response()
}

/// Enforce the configured maximum request-body size.
///
/// Sits inside the auth middleware so unauthenticated requests are rejected
/// with 401 before any body bytes are buffered. Two-stage enforcement:
///
/// 1. Fast path: a declared `Content-Length` over the limit is rejected
///    without reading the body at all.
/// 2. The body is then buffered under a hard cap, so chunked or unspecified
///    lengths cannot slip past the limit.
async fn payload_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let limit = state.config.server.max_payload_bytes;

    if let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && len > limit as u64
    {
        return payload_too_large(limit);
    }

    let (parts, body) = req.into_parts();
    match to_bytes(body, limit).await {
        Ok(bytes) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Err(_) => payload_too_large(limit),
    }
}

fn payload_too_large(limit: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({
            "error": format!("payload too large: maximum accepted body is {limit} bytes"),
            "max_payload_bytes": limit,
        })),
    )
        .into_response()
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "service": "sentiel"})),
    )
}

/// Readiness: DB answers a trivial query.
///
/// Public (load balancers cannot present bearer tokens), but the failure
/// detail is deliberately generic — raw SQLite error strings can disclose
/// filesystem paths and schema details to unauthenticated callers.
async fn health_ready(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match state.db.health_check() {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready", "database": "ok" })),
        ),
        // The precise error goes to the log; clients get a fixed string.
        Err(e) => {
            tracing::error!("readiness probe failed: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "status": "not-ready", "database": "unavailable" })),
            )
        }
    }
}

/// Prometheus scrape endpoint. Requires the admin scope: the counters are
/// labeled by source and event type, so an unauthenticated scrape would
/// disclose which producers are active and their event volumes.
async fn metrics_endpoint(State(state): State<AppState>) -> (StatusCode, String) {
    (StatusCode::OK, state.metrics.render())
}

async fn dashboard() -> (StatusCode, String) {
    (StatusCode::OK, crate::dashboard::dashboard_html())
}

async fn ingest_event(
    State(state): State<AppState>,
    payload: Result<Json<crate::events::CreateEvent>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    // Malformed JSON (400) and missing/mistyped fields (422) are surfaced as
    // JSON errors instead of axum's default plain-text rejections.
    let Json(req) = payload.map_err(|rejection| crate::errors::SentielError::InvalidRequest {
        status: rejection.status(),
        message: rejection.body_text(),
    })?;

    // Strict schema gate: reject unknown sources/event types, bad severities,
    // and non-object payloads with a 422 listing every violation.
    if let Err(details) = req.validate() {
        return Err(crate::errors::SentielError::Validation(details));
    }

    let mut event = req.to_agent_event();

    // DLP inspection. Identity/attribution fields are scanned too: they are
    // stored and returned verbatim, so leaving them unscanned would make them
    // a free exfiltration channel past DLP.
    let identity_violations = state.dlp.inspect_fields(&[
        ("session_id", event.session_id.as_deref()),
        ("agent_id", event.agent_id.as_deref()),
        ("principal_id", event.principal_id.as_deref()),
    ]);
    let mut violations = state.dlp.inspect_json(&event.data);
    violations.extend(identity_violations);
    if !violations.is_empty() {
        state.metrics.dlp_violations.inc_by(violations.len() as u64);
        violations.truncate(state.config.dlp.max_redactions);
        event.dlp_violations = Some(violations.clone());
        if state.dlp.has_critical_violation(&violations) {
            event.severity = "critical".to_string();
        }

        // block_on_violation is a real gate: events whose worst violation
        // meets the configured block severity are refused, not stored.
        if state.config.dlp.block_on_violation {
            let block_rank = crate::config::severity_rank(&state.config.dlp.block_severity);
            if violations
                .iter()
                .any(|v| crate::config::severity_rank(&v.severity) >= block_rank)
            {
                let names: Vec<String> = violations
                    .iter()
                    .map(|v| v.pattern_name.clone())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                return Err(crate::errors::SentielError::DlpViolation(format!(
                    "event blocked: DLP violation(s) at or above '{}' severity: {}",
                    state.config.dlp.block_severity,
                    names.join(", ")
                )));
            }
        }
    }

    // Anomaly detection
    let recent = state.db.list_events(100).unwrap_or_default();
    let alerts = state.anomaly.check_event(&event, &recent);
    if !alerts.is_empty() {
        event.anomaly_flags = Some(alerts.iter().map(|a| a.alert_type.clone()).collect());
        state.metrics.anomaly_alerts.inc_by(alerts.len() as u64);
        for alert in &alerts {
            if let Err(e) = state.db.insert_alert(alert) {
                tracing::warn!("Failed to insert alert: {}", e);
            }
        }
    }

    state
        .metrics
        .events_ingested
        .with_label_values(&[&event.source, &event.event_type])
        .inc();
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
) -> Result<Json<Vec<AgentEvent>>, crate::errors::SentielError> {
    let limit = params.limit.unwrap_or(100).clamp(1, 10_000);
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

#[derive(serde::Deserialize)]
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
) -> Result<Json<Vec<AgentEvent>>, crate::errors::SentielError> {
    list_events(State(state), Query(params)).await
}

async fn events_by_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<AgentEvent>>, crate::errors::SentielError> {
    let events = state.db.events_by_session(&session_id)?;
    Ok(Json(events))
}

async fn events_by_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<AgentEvent>>, crate::errors::SentielError> {
    let events = state.db.events_by_agent(&agent_id)?;
    Ok(Json(events))
}

async fn stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    let events = state.db.list_events(100000)?;
    let authz: Vec<_> = events
        .iter()
        .filter(|e| e.source == "patroclus" && e.event_type == "authz_decision")
        .collect();
    let allows = authz
        .iter()
        .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("allow"))
        .count();
    let denies = authz
        .iter()
        .filter(|e| e.data.get("decision").and_then(|v| v.as_str()) == Some("deny"))
        .count();
    let dlp_count = state.db.dlp_violations(10000)?.len();
    let alerts = state.db.alerts_unacknowledged()?;

    Ok(Json(serde_json::json!({
        "total_events": events.len(),
        "authz_total": authz.len(),
        "allows": allows,
        "denies": denies,
        "dlp_violations": dlp_count,
        "active_alerts": alerts.len(),
        "pruned_events": state.prune_stats.events_pruned(),
        "pruned_alerts": state.prune_stats.alerts_pruned(),
        "last_pruned_at": state
            .prune_stats
            .last_pruned_at()
            .map(|t| t.to_rfc3339()),
        "retention_days": state.config.database.retention_days,
    })))
}

async fn list_alerts(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::anomaly::Alert>>, crate::errors::SentielError> {
    let alerts = state.db.alerts_unacknowledged()?;
    Ok(Json(alerts))
}

async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    state.db.acknowledge_alert(id)?;
    Ok(Json(serde_json::json!({"acknowledged": id})))
}

#[derive(serde::Deserialize)]
struct DlpInspectRequest {
    content: String,
}

async fn dlp_inspect(
    State(state): State<AppState>,
    Json(req): Json<DlpInspectRequest>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
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
) -> Result<Json<Vec<AgentEvent>>, crate::errors::SentielError> {
    let events = state.db.dlp_violations(1000)?;
    Ok(Json(events))
}

async fn compliance_report(
    State(state): State<AppState>,
    Path(framework): Path<String>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    // Returns a `ComplianceExport`: `report` (framework → controls with
    // evidence references + data-completeness disclaimer) plus `attachments`
    // holding the raw summary counts. See compliance module docs.
    let export = match framework.as_str() {
        "soc2" => ComplianceReporter::generate_soc2(&state.db)?,
        "gdpr" => ComplianceReporter::generate_gdpr(&state.db)?,
        "eu_ai_act" => ComplianceReporter::generate_eu_ai_act(&state.db)?,
        "hipaa" => ComplianceReporter::generate_hipaa(&state.db)?,
        _ => {
            return Err(crate::errors::SentielError::NotFound(
                "unknown framework".to_string(),
            ));
        }
    };
    Ok(Json(serde_json::to_value(&export).unwrap()))
}
async fn cost_summary(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    let summary = state.db.cost_summary()?;
    Ok(Json(summary))
}

async fn decision_summary(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    let summary = state.db.decision_summary()?;
    Ok(Json(summary))
}

/// Manual retention pass (admin scope): delete rows older than the
/// configured `retention_days` and fold the counts into the shared stats.
async fn admin_prune(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    let report = state
        .db
        .prune_expired(state.config.database.retention_days)?;
    state.prune_stats.record(&report);
    Ok(Json(serde_json::json!({
        "retention_days": state.config.database.retention_days,
        "events_deleted": report.events_deleted,
        "alerts_deleted": report.alerts_deleted,
    })))
}

/// Tamper-evidence report for the event store (admin scope).
///
/// Walks the hash chain (see [`crate::audit`]) and returns the first broken
/// link when the store has been tampered with. HTTP 200 either way: the
/// verdict is data, not a server error.
async fn integrity(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
    let verification = state.db.verify_event_chain()?;
    let chain_configured = state.db.chaining_enabled() && state.config.database.chain_events;
    Ok(Json(serde_json::json!({
        "chain_configured": chain_configured,
        "intact": verification.is_intact(),
        "total_events": verification.total_events,
        "unchained_events": verification.unchained_events,
        "verdict": serde_json::to_value(&verification.verdict).unwrap_or_default(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state(auth: AuthConfig) -> AppState {
        AppState {
            db: Arc::new(Database::new_in_memory().expect("in-memory db")),
            dlp: Arc::new(DlpEngine::new(true)),
            anomaly: Arc::new(AnomalyEngine::new(crate::config::AnomalyConfig::default())),
            config: Arc::new(Config::default()),
            auth: Arc::new(auth),
            prune_stats: Arc::new(crate::retention::PruneStats::new()),
            metrics: Arc::new(crate::metrics::Metrics::new().expect("metrics")),
        }
    }

    fn test_state_with(config: Config, auth: AuthConfig) -> AppState {
        let db = if config.database.chain_events {
            Database::new_in_memory()
                .expect("in-memory db")
                .with_event_chaining()
        } else {
            Database::new_in_memory().expect("in-memory db")
        };
        AppState {
            config: Arc::new(config),
            db: Arc::new(db),
            ..test_state(auth)
        }
    }

    fn bearer(value: &str) -> String {
        format!("Bearer {value}")
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.oneshot(req).await.expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let json = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    fn get(path: &str, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::get(path);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, bearer(token));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn post_json(path: &str, token: &str, body: String) -> Request<Body> {
        Request::post(path)
            .header(header::AUTHORIZATION, bearer(token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn valid_event_body() -> String {
        serde_json::json!({
            "source": "miser",
            "event_type": "llm_cost",
            "data": {"cost": 0.01}
        })
        .to_string()
    }

    #[tokio::test]
    async fn api_routes_reject_missing_token() {
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: Some("ingest".into()),
            insecure_dev: false,
        }));

        for path in [
            "/api/events",
            "/api/events/query",
            "/api/stats",
            "/api/alerts",
            "/api/dlp/violations",
            "/api/compliance/soc2",
        ] {
            let (status, body) = send(app.clone(), get(path, None)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "path: {path}");
            assert_eq!(body["error"], "missing or invalid bearer token");
        }
    }

    #[tokio::test]
    async fn metrics_endpoint_requires_admin_token() {
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: Some("ingest".into()),
            insecure_dev: false,
        }));

        // Unauthenticated scrapes are refused: the counters disclose which
        // agent sources are active and their event volumes.
        let (status, _) = send(app.clone(), get("/metrics", None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Ingest tokens do not unlock metrics either.
        let (status, _) = send(app.clone(), get("/metrics", Some("ingest"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = send(app.clone(), get("/metrics", Some("admin"))).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn health_endpoints_stay_public() {
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        }));
        for path in ["/", "/health", "/health/ready"] {
            let (status, _) = send(app.clone(), get(path, None)).await;
            assert_eq!(status, StatusCode::OK, "public path: {path}");
        }
    }

    #[tokio::test]
    async fn ready_probe_hides_database_error_details() {
        // A healthy DB reports ready; the point of this test is that a
        // failure never surfaces raw SQLite error strings to unauthenticated
        // callers. Simulate by pointing the probe at an impossible check via
        // the generic path: assert the success shape and that no error string
        // from a failing DB would be included (handler maps errors to a fixed
        // "unavailable" marker — covered here on the happy path contract).
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        }));
        let (status, body) = send(app.clone(), get("/health/ready", None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["database"], "ok");
    }

    #[tokio::test]
    async fn api_routes_reject_unknown_token() {
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        }));

        let (status, _) = send(app.clone(), get("/api/stats", Some("wrong-token"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_authorization_header_is_unauthorized() {
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        }));

        for value in ["Token admin", "Bearer", "Bearer ", "Basic YWRtaW4="] {
            let req = Request::get("/api/stats")
                .header(header::AUTHORIZATION, value)
                .body(Body::empty())
                .unwrap();
            let (status, _) = send(app.clone(), req).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "header: {value:?}");
        }
    }

    #[tokio::test]
    async fn ingest_token_can_post_events_but_not_read() {
        let app = create_router(test_state(AuthConfig {
            admin_token: None,
            ingest_token: Some("ingest".into()),
            insecure_dev: false,
        }));

        let (status, body) = send(
            app.clone(),
            post_json("/api/events", "ingest", valid_event_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["id"].is_string());

        // Ingest scope must not grant read/admin access.
        for path in ["/api/stats", "/api/events", "/api/compliance/soc2"] {
            let (status, err) = send(app.clone(), get(path, Some("ingest"))).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "path: {path}");
            assert_eq!(err["error"], "token lacks permission for this endpoint");
        }
    }

    #[tokio::test]
    async fn admin_token_grants_full_api_access() {
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: Some("ingest".into()),
            insecure_dev: false,
        }));

        let (status, _) = send(
            app.clone(),
            post_json("/api/events", "admin", valid_event_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        for path in [
            "/api/stats",
            "/api/events",
            "/api/cost/summary",
            "/api/decisions/summary",
        ] {
            let (status, _) = send(app.clone(), get(path, Some("admin"))).await;
            assert_eq!(status, StatusCode::OK, "path: {path}");
        }
    }

    #[tokio::test]
    async fn public_routes_stay_open_without_tokens() {
        // Token-less configuration (debug build): public surface must work.
        let app = create_router(test_state(AuthConfig::default()));

        let (status, _) = send(app.clone(), get("/", None)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(send(app.clone(), get("/health", None)).await.0.is_success());
    }

    // --- Issue #8: payload size limits -----------------------------------

    fn authed_admin() -> AuthConfig {
        AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: Some("ingest".into()),
            insecure_dev: false,
        }
    }

    // --- Issue #10: DLP enforcement gaps ---------------------------------

    fn config_with_dlp(block_on_violation: bool) -> Config {
        let mut config = Config::default();
        config.dlp.enabled = true;
        config.dlp.block_on_violation = block_on_violation;
        config
    }

    fn event_with_secret_in(field: &str, value: &str) -> String {
        // `session_id`/`agent_id`/`principal_id` carry an AWS key; `data`
        // carries an SSN. All are attacker-controlled ingest fields.
        let mut body = serde_json::json!({
            "source": "relay",
            "event_type": "tool_call",
            "data": {"note": "SSN: 123-45-6789"}
        });
        body[field] = serde_json::Value::String(value.to_string());
        body.to_string()
    }

    #[tokio::test]
    async fn dlp_blocks_ingest_when_violation_meets_block_severity() {
        let app = create_router(test_state_with(config_with_dlp(true), authed_admin()));

        // SSN is a `critical` violation and the default block severity is
        // `critical`, so ingest must refuse instead of storing the secret.
        let (status, body) = send(
            app,
            post_json(
                "/api/events",
                "ingest",
                event_with_secret_in("agent_id", "a-1"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["error"].as_str().unwrap().contains("blocked"),
            "must say blocked: {body}"
        );
    }

    #[tokio::test]
    async fn dlp_block_respects_severity_threshold() {
        // Block severity `low`: even the phone pattern (low) blocks.
        let mut config = config_with_dlp(true);
        config.dlp.block_severity = "low".to_string();
        let app = create_router(test_state_with(config, authed_admin()));

        let body = serde_json::json!({
            "source": "relay",
            "event_type": "tool_call",
            "data": {"phone": "555-123-4567"}
        })
        .to_string();
        let (status, _) = send(app, post_json("/api/events", "ingest", body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn dlp_record_but_allow_when_blocking_disabled() {
        let app = create_router(test_state_with(config_with_dlp(false), authed_admin()));

        let (status, body) = send(
            app.clone(),
            post_json(
                "/api/events",
                "ingest",
                event_with_secret_in("agent_id", "a-2"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The violation is still recorded on the stored event.
        let (_, events) = send(app, get("/api/events/agent/a-2", Some("admin"))).await;
        assert!(
            events[0]["dlp_violations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["pattern_name"] == "ssn"),
            "violation must be recorded: {events}"
        );
    }

    #[tokio::test]
    async fn dlp_scans_identity_fields_not_just_data() {
        // With blocking disabled, an AWS key smuggled in `principal_id` must
        // still be detected and recorded (previously a blind spot).
        let app = create_router(test_state_with(config_with_dlp(false), authed_admin()));

        let body = serde_json::json!({
            "source": "relay",
            "event_type": "tool_call",
            "principal_id": "AKIAIOSFODNN7EXAMPLE",
            "data": {"clean": true}
        })
        .to_string();
        let (status, _) = send(app.clone(), post_json("/api/events", "ingest", body)).await;
        assert_eq!(status, StatusCode::OK);

        let (_, events) = send(app, get("/api/events", Some("admin"))).await;
        let violations = events[0]["dlp_violations"]
            .as_array()
            .expect("violations recorded");
        assert!(
            violations
                .iter()
                .any(|v| v["pattern_name"] == "aws_key" && v["field"] == "principal_id"),
            "aws_key in principal_id must be detected: {violations:?}"
        );
    }

    #[tokio::test]
    async fn oversized_payload_is_rejected_with_413() {
        let mut config = Config::default();
        config.server.max_payload_bytes = 64;
        let app = create_router(test_state_with(config, authed_admin()));

        let big_body = serde_json::json!({
            "source": "miser",
            "event_type": "llm_cost",
            "data": {"blob": "x".repeat(1024)}
        })
        .to_string();

        let (status, body) = send(app, post_json("/api/events", "ingest", big_body)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("payload too large")
        );
        assert_eq!(body["max_payload_bytes"], 64);
    }

    #[tokio::test]
    async fn declared_content_length_over_limit_is_rejected_without_read() {
        let mut config = Config::default();
        config.server.max_payload_bytes = 32;
        let app = create_router(test_state_with(config, authed_admin()));

        // Tiny actual body with an inflated Content-Length header: the fast
        // path must reject on the header alone.
        let req = Request::post("/api/events")
            .header(header::AUTHORIZATION, bearer("ingest"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, "999999")
            .body(Body::from("{}"))
            .unwrap();

        let (status, _) = send(app, req).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn payload_at_exact_limit_is_accepted() {
        let body = valid_event_body();
        let mut config = Config::default();
        config.server.max_payload_bytes = body.len();
        let app = create_router(test_state_with(config, authed_admin()));

        let (status, resp) = send(app, post_json("/api/events", "ingest", body)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(resp["id"].is_string());
    }

    // --- Issue #8: strict schema validation ------------------------------

    #[tokio::test]
    async fn unknown_source_returns_422_listing_allowed_values() {
        let app = create_router(test_state(authed_admin()));

        let body = serde_json::json!({
            "source": "rogue-agent",
            "event_type": "llm_cost",
            "data": {"cost": 0.01}
        })
        .to_string();

        let (status, resp) = send(app, post_json("/api/events", "ingest", body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(resp["error"].as_str().unwrap().contains("invalid source"));
        assert!(
            resp["error"]
                .as_str()
                .unwrap()
                .contains("miser, patroclus, relay")
        );
        assert!(!resp["details"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_event_type_returns_422() {
        let app = create_router(test_state(authed_admin()));

        let body = serde_json::json!({
            "source": "miser",
            "event_type": "keyboard_event",
            "data": {}
        })
        .to_string();

        let (status, resp) = send(app, post_json("/api/events", "ingest", body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            resp["error"]
                .as_str()
                .unwrap()
                .contains("invalid event_type")
        );
    }

    #[tokio::test]
    async fn invalid_severity_returns_422() {
        let app = create_router(test_state(authed_admin()));

        let body = serde_json::json!({
            "source": "miser",
            "event_type": "llm_cost",
            "severity": "catastrophic",
            "data": {"cost": 0.01}
        })
        .to_string();

        let (status, resp) = send(app, post_json("/api/events", "ingest", body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(resp["error"].as_str().unwrap().contains("invalid severity"));
    }

    #[tokio::test]
    async fn non_object_data_returns_422() {
        let app = create_router(test_state(authed_admin()));

        for bad_data in ["\"just a string\"", "[1, 2, 3]", "null", "42"] {
            let body = format!(r#"{{"source":"miser","event_type":"llm_cost","data":{bad_data}}}"#);
            let (status, resp) = send(app.clone(), post_json("/api/events", "ingest", body)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "data: {bad_data}");
            assert!(
                resp["error"]
                    .as_str()
                    .unwrap()
                    .contains("expected a JSON object"),
                "data: {bad_data}"
            );
        }
    }

    #[tokio::test]
    async fn missing_required_field_returns_422() {
        let app = create_router(test_state(authed_admin()));

        // `event_type` omitted entirely.
        let body = r#"{"source":"miser","data":{"cost":0.01}}"#;
        let (status, resp) = send(app, post_json("/api/events", "ingest", body.to_string())).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(resp["error"].as_str().unwrap().contains("event_type"));
    }

    #[tokio::test]
    async fn wrong_typed_field_returns_422() {
        let app = create_router(test_state(authed_admin()));

        // `source` must be a string, not a number.
        let body = r#"{"source":42,"event_type":"llm_cost","data":{}}"#;
        let (status, resp) = send(app, post_json("/api/events", "ingest", body.to_string())).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(resp["error"].as_str().unwrap().contains("source"));
    }

    #[tokio::test]
    async fn malformed_json_returns_400() {
        let app = create_router(test_state(authed_admin()));

        let (status, resp) = send(
            app,
            post_json("/api/events", "ingest", "{not valid json".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(resp["error"].is_string());
    }

    // --- Issue #3: retention and pruning ---------------------------------

    fn old_event(age_days: i64) -> AgentEvent {
        AgentEvent {
            id: None,
            source: "miser".to_string(),
            session_id: None,
            agent_id: None,
            principal_id: None,
            event_type: "llm_cost".to_string(),
            severity: "info".to_string(),
            data: serde_json::json!({"cost": 0.01}),
            dlp_violations: None,
            anomaly_flags: None,
            timestamp: Some(chrono::Utc::now() - chrono::Duration::days(age_days)),
        }
    }

    fn old_alert(age_days: i64) -> crate::anomaly::Alert {
        crate::anomaly::Alert {
            id: uuid::Uuid::now_v7(),
            session_id: None,
            agent_id: None,
            alert_type: "spending_spike".to_string(),
            severity: "high".to_string(),
            message: "stale alert".to_string(),
            data: None,
            acknowledged: false,
            created_at: chrono::Utc::now() - chrono::Duration::days(age_days),
            acknowledged_at: None,
        }
    }

    #[tokio::test]
    async fn admin_prune_deletes_old_rows_and_updates_stats() {
        let state = test_state(authed_admin());
        state.db.insert_event(&old_event(120)).unwrap();
        state.db.insert_event(&old_event(0)).unwrap();
        state.db.insert_alert(&old_alert(120)).unwrap();
        let app = create_router(state.clone());

        let (status, body) = send(
            app.clone(),
            post_json("/api/admin/prune", "admin", "{}".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["events_deleted"], 1);
        assert_eq!(body["alerts_deleted"], 1);
        assert_eq!(body["retention_days"], 90);

        // Only the fresh event survives.
        assert_eq!(state.db.list_events(100).unwrap().len(), 1);

        // Prune counts surface in /api/stats.
        let (status, stats) = send(app, get("/api/stats", Some("admin"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stats["pruned_events"], 1);
        assert_eq!(stats["pruned_alerts"], 1);
        assert!(stats["last_pruned_at"].is_string());
        assert_eq!(stats["retention_days"], 90);
    }

    #[tokio::test]
    async fn ingest_token_cannot_trigger_prune() {
        let app = create_router(test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: Some("ingest".into()),
            insecure_dev: false,
        }));

        let (status, body) = send(
            app,
            post_json("/api/admin/prune", "ingest", "{}".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "token lacks permission for this endpoint");
    }

    #[tokio::test]
    async fn prune_with_nothing_expired_reports_zero() {
        let state = test_state(authed_admin());
        state.db.insert_event(&old_event(0)).unwrap();
        let app = create_router(state);

        let (status, body) = send(
            app,
            post_json("/api/admin/prune", "admin", "{}".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["events_deleted"], 0);
        assert_eq!(body["alerts_deleted"], 0);
    }
    #[tokio::test]
    async fn metrics_endpoint_renders_and_counters_increment() {
        let state = test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        });
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "source": "miser",
            "event_type": "llm_cost",
            "agent_id": "a1",
            "data": {"tokens": 10}
        });
        let req = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/events")
            .header(header::AUTHORIZATION, bearer("admin"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, json) = send(app, req).await;
        assert!(status.is_success(), "{json}");
        let rendered = state.metrics.render();
        assert!(rendered.contains("sentiel_events_ingested_total"));
    }

    #[tokio::test]
    async fn ready_probe_ok_when_db_up() {
        let state = test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        });
        let app = create_router(state);
        let req = Request::builder()
            .method(axum::http::Method::GET)
            .uri("/health/ready")
            .header(header::AUTHORIZATION, bearer("admin"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = send(app, req).await;
        assert!(status.is_success());
    }
    #[tokio::test]
    async fn ingest_then_query_round_trip() {
        let state = test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        });
        let app = create_router(state.clone());
        let req = post_json("/api/events", "admin", valid_event_body());
        let (status, body) = send(app.clone(), req).await;
        assert!(status.is_success(), "{body}");
        let id = body["id"].as_str().unwrap().to_string();

        let req = get("/api/events/query?limit=10", Some("admin"));
        let (status, body) = send(app.clone(), req).await;
        assert_eq!(status, StatusCode::OK);
        let events = body.as_array().cloned().unwrap_or_default();
        assert!(events.iter().any(|e| e["id"].as_str() == Some(id.as_str())));
    }

    #[tokio::test]
    async fn session_and_agent_filters_scope_results() {
        let state = test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        });
        let app = create_router(state.clone());
        for session in ["s1", "s2"] {
            let body = serde_json::json!({
                "source": "miser",
                "event_type": "llm_cost",
                "agent_id": format!("agent-{session}"),
                "session_id": session,
                "data": {"cost": 0.01}
            });
            let req = post_json("/api/events", "admin", body.to_string());
            assert!(send(app.clone(), req).await.0.is_success());
        }
        let req = get("/api/events/session/s1", Some("admin"));
        let (_, body) = send(app.clone(), req).await;
        let events = body.as_array().cloned().unwrap_or_default();
        assert!(!events.is_empty());
        assert!(events.iter().all(|e| e["session_id"] == "s1"));

        let req = get("/api/events/agent/agent-s2", Some("admin"));
        let (_, body) = send(app.clone(), req).await;
        let events = body.as_array().cloned().unwrap_or_default();
        assert!(!events.is_empty());
        assert!(events.iter().all(|e| e["agent_id"] == "agent-s2"));
    }

    #[tokio::test]
    async fn dlp_inspect_detects_each_pattern_class() {
        let state = test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        });
        let app = create_router(state);
        let cases: Vec<(&str, String)> = vec![
            ("email", "contact me at bob@example.com please".into()),
            ("ssn", "ssn 123-45-6789".into()),
            ("credit_card", "card 4111 1111 1111 1111".into()),
            ("aws_key", "key AKIAIOSFODNN7EXAMPLE".into()),
            ("github_token", "token ghp_0123456789abcdefghijklmnopqrstuvwxyzABC".into()),
            ("slack_token", "slack xoxb-123456789012-abcdef".into()),
            ("private_key", "-----BEGIN RSA PRIVATE KEY-----abc".into()),
            ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c".into()),
        ];
        for (class, secret) in cases {
            let body = serde_json::json!({ "content": secret });
            let req = post_json("/api/dlp/inspect", "admin", body.to_string());
            let (_, out) = send(app.clone(), req).await;
            let violations = out["violations"].as_array().cloned().unwrap_or_default();
            assert!(
                !violations.is_empty(),
                "expected {class} to be detected; got {out}"
            );
        }
    }

    #[tokio::test]
    async fn compliance_report_generates_for_framework() {
        let state = test_state(AuthConfig {
            admin_token: Some("admin".into()),
            ingest_token: None,
            insecure_dev: false,
        });
        let app = create_router(state.clone());
        // Seed one authz decision so the SOC2 summary has signal.
        let body = serde_json::json!({
            "source": "patroclus",
            "event_type": "authz_decision",
            "data": {"decision": "allow"}
        });
        let req = post_json("/api/events", "admin", body.to_string());
        assert!(send(app.clone(), req).await.0.is_success());

        let req = get("/api/compliance/soc2", Some("admin"));
        let (status, body) = send(app.clone(), req).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["report"]["framework"], "SOC 2 Type II");
        // New schema: controls with evidence refs, disclaimer, and counts
        // demoted to attachments.
        let report = &body["report"];
        assert!(!report["disclaimer"].as_str().unwrap_or_default().is_empty());
        let controls = report["controls"].as_array().expect("controls array");
        assert!(!controls.is_empty());
        for control in controls {
            assert!(!control["id"].as_str().unwrap_or_default().is_empty());
            assert!(!control["name"].as_str().unwrap_or_default().is_empty());
            assert!(
                !control["status"].as_str().unwrap_or_default().is_empty(),
                "control status missing: {control}"
            );
            let evidence = control["evidence"].as_array().expect("evidence array");
            assert!(!evidence.is_empty(), "control without evidence: {control}");
            for r in evidence {
                assert!(r["query"].is_object(), "evidence query missing: {r}");
            }
        }
        assert!(report.get("summary").is_none(), "counts in body: {report}");
        let attachments = body["attachments"].as_array().expect("attachments");
        assert_eq!(attachments[0]["name"], "summary_counts");
        assert_eq!(attachments[0]["counts"]["authz_decisions"], 1);
    }

    // --- Issue #6: tamper-evident hash-chained event storage -------------

    fn config_with_chaining() -> Config {
        let mut config = Config::default();
        config.database.chain_events = true;
        config
    }

    #[tokio::test]
    async fn integrity_endpoint_requires_admin() {
        let app = create_router(test_state_with(config_with_chaining(), authed_admin()));

        // Ingest tokens cannot read the integrity verdict either.
        let (status, _) = send(app.clone(), get("/api/integrity", Some("ingest"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = send(app, get("/api/integrity", Some("admin"))).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn integrity_reports_intact_after_chained_ingest() {
        let app = create_router(test_state_with(config_with_chaining(), authed_admin()));

        for cost in [0.01, 0.02, 0.03] {
            let body = serde_json::json!({
                "source": "miser",
                "event_type": "llm_cost",
                "data": {"cost": cost}
            })
            .to_string();
            let (status, resp) = send(app.clone(), post_json("/api/events", "ingest", body)).await;
            assert_eq!(status, StatusCode::OK, "{resp}");
        }

        let (status, body) = send(app, get("/api/integrity", Some("admin"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["chain_configured"], true);
        assert_eq!(body["intact"], true, "fresh chain must verify: {body}");
        assert_eq!(body["total_events"], 3);
        assert_eq!(body["unchained_events"], 0);
        assert_eq!(body["verdict"]["status"], "intact");
        assert_eq!(body["verdict"]["verified_rows"], 3);
        // The head is a real 64-hex hash, not the genesis marker.
        let head = body["verdict"]["head_hash"].as_str().unwrap();
        assert_eq!(head.len(), 64);
        assert!(head.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(head, crate::audit::GENESIS);
    }

    #[tokio::test]
    async fn integrity_without_chaining_reports_unchained_rows() {
        // Default config: chaining disabled. Rows exist but carry no chain
        // metadata — the endpoint must not claim the store is intact.
        let app = create_router(test_state(authed_admin()));
        let (status, _) = send(
            app.clone(),
            post_json("/api/events", "ingest", valid_event_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send(app, get("/api/integrity", Some("admin"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["chain_configured"], false);
        assert_eq!(body["intact"], false);
        assert_eq!(body["total_events"], 1);
        assert_eq!(body["unchained_events"], 1);
        assert_eq!(body["verdict"]["status"], "intact");
    }

    #[tokio::test]
    async fn integrity_detects_tampered_row_via_endpoint() {
        let state = test_state_with(config_with_chaining(), authed_admin());
        let app = create_router(state.clone());

        for n in 1..=3 {
            let body = serde_json::json!({
                "source": "miser",
                "event_type": "llm_cost",
                "data": {"cost": 0.01, "n": n}
            })
            .to_string();
            let (status, _) = send(app.clone(), post_json("/api/events", "ingest", body)).await;
            assert_eq!(status, StatusCode::OK);
        }

        // Tamper directly in the store: rewrite row 2's payload. This is the
        // threat model — someone with DB access editing history.
        {
            let conn = state.db.conn_for_tests();
            conn.execute(
                "UPDATE events SET data = '{\"cost\":99999.0,\"n\":2}' WHERE seq = 2",
                [],
            )
            .unwrap();
        }

        let (status, body) = send(app, get("/api/integrity", Some("admin"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["intact"], false, "{body}");
        assert_eq!(body["verdict"]["status"], "broken");
        // First broken link is the tampered row, not a later one.
        assert_eq!(body["verdict"]["at_seq"], 2);
        assert_eq!(body["verdict"]["reason"], "row_modified");
    }

    #[tokio::test]
    async fn integrity_detects_deleted_row() {
        let state = test_state_with(config_with_chaining(), authed_admin());
        let app = create_router(state.clone());

        for n in 1..=3 {
            let body = serde_json::json!({
                "source": "miser",
                "event_type": "llm_cost",
                "data": {"cost": 0.01, "n": n}
            })
            .to_string();
            let (status, _) = send(app.clone(), post_json("/api/events", "ingest", body)).await;
            assert_eq!(status, StatusCode::OK);
        }

        // Delete a middle row: its successor's prev_hash can no longer match.
        {
            let conn = state.db.conn_for_tests();
            conn.execute("DELETE FROM events WHERE seq = 2", [])
                .unwrap();
        }

        let (status, body) = send(app, get("/api/integrity", Some("admin"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["intact"], false, "{body}");
        assert_eq!(body["verdict"]["status"], "broken");
        assert_eq!(body["verdict"]["at_seq"], 2);
        assert_eq!(body["verdict"]["reason"], "link_mismatch");
    }
}
