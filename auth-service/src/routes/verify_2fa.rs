use axum::response::IntoResponse;
use reqwest::StatusCode;

pub async fn verify_2fa_handler() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
