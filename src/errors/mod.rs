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
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
