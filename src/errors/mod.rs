use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentielError {
    #[error("event not found: {0}")]
    EventNotFound(String),

    #[error("DLP violation: {0}")]
    DlpViolation(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("validation failed: {}", .0.join("; "))]
    Validation(Vec<String>),

    /// Request rejected before reaching a handler (malformed JSON, missing or
    /// mistyped fields). Carries the HTTP status the rejection maps to:
    /// 400 for unparsable JSON, 422 for schema violations.
    #[error("invalid request: {message}")]
    InvalidRequest { status: StatusCode, message: String },
}

pub type Result<T> = std::result::Result<T, SentielError>;

impl From<rusqlite::Error> for SentielError {
    fn from(e: rusqlite::Error) -> Self {
        SentielError::Database(e.to_string())
    }
}

impl IntoResponse for SentielError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            SentielError::EventNotFound(_) | SentielError::NotFound(_) => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            SentielError::DlpViolation(_) => (StatusCode::FORBIDDEN, self.to_string()),
            SentielError::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            SentielError::InvalidRequest { status, .. } => (*status, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        let mut body = serde_json::json!({ "error": message });
        if let SentielError::Validation(details) = &self {
            body["details"] = serde_json::json!(details);
        }
        (status, Json(body)).into_response()
    }
}

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
