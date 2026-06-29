use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),

    #[error("body too large or unreadable")]
    Body,

    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Upstream(e) => {
                tracing::error!(cause = ?e, "upstream request failed");
                StatusCode::BAD_GATEWAY
            }
            AppError::Body => StatusCode::BAD_REQUEST,
            AppError::Internal(e) => {
                tracing::error!(cause = ?e, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = Json(serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": self.to_string(),
        }));
        (status, body).into_response()
    }
}
