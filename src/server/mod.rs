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

    fn test_state_with(config: Config, auth: AuthConfig) -> AppState {
        AppState {
            config: Arc::new(config),
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
}
