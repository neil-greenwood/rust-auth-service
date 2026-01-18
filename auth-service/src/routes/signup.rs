use axum::response::IntoResponse;
use reqwest::StatusCode;

pub async fn signup_handler() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
