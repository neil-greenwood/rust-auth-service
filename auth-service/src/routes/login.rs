use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, UserStoreError},
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct LoginResponse {
    pub message: String,
}

pub async fn login_handler(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let Ok(email) = Email::parse(request.email) else {
        return Err(AuthAPIError::InvalidCredentials);
    };
    let Ok(password) = Password::parse(request.password) else {
        return Err(AuthAPIError::InvalidCredentials);
    };

    let user_store = state.user_store.read().await;

    let result = user_store
        .validate_user(&email.address, &password.password)
        .await;
    if result.is_err() {
        let error = result.unwrap_err();
        if error == UserStoreError::InvalidCredentials || error == UserStoreError::UserNotFound {
            return Err(AuthAPIError::IncorrectCredentials);
        }
        return Err(AuthAPIError::UnexpectedError);
    }

    let response = Json(LoginResponse {
        message: "Authenticated successfully".to_string(),
    });
    Ok((StatusCode::OK, response))
}
