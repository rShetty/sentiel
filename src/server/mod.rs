use std::sync::Arc;

use axum::{
    Json, Router,
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
};

/// Shared application state threaded through all handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub dlp: Arc<DlpEngine>,
    pub anomaly: Arc<AnomalyEngine>,
    #[allow(dead_code)] // consumed by retention/metrics wiring in follow-up hardening
    pub config: Arc<Config>,
    pub auth: Arc<AuthConfig>,
}

/// Build the full HTTP router for Sentiel.
///
/// Public surface (no authentication): `/`, `/health`, static assets.
/// Everything under `/api/*` requires a bearer token; see [`crate::auth`].
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Bearer-token gate for every `/api/*` route.
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
fn required_scope(method: &Method, path: &str) -> Option<Scope> {
    if !path.starts_with("/api/") {
        return None;
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

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "service": "sentiel"})),
    )
}

async fn dashboard() -> (StatusCode, String) {
    (StatusCode::OK, crate::dashboard::dashboard_html())
}

async fn ingest_event(
    State(state): State<AppState>,
    Json(req): Json<crate::events::CreateEvent>,
) -> Result<Json<serde_json::Value>, crate::errors::SentielError> {
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
    let report = match framework.as_str() {
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
    Ok(Json(serde_json::to_value(&report).unwrap()))
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
}
