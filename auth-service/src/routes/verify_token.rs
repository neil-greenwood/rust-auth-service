use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[derive(Deserialize, Serialize)]
pub struct ValidateTokenResponse {
    pub message: String,
}

#[tracing::instrument(name = "Verify JWT Token", skip_all)]
pub async fn verify_token_handler(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<StatusCode, AuthAPIError> {
    match validate_token(&request.token, state.banned_tokens.clone()).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
