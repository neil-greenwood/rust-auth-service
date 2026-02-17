use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User, UserStoreError},
};

pub async fn signup_handler(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let Ok(email) = Email::parse(request.email) else {
        return Err(AuthAPIError::InvalidCredentials);
    };
    let Ok(password) = Password::parse(request.password) else {
        return Err(AuthAPIError::InvalidCredentials);
    };

    // Create a new `User` instance using the data in the `request`
    let user = User {
        email,
        password,
        requires_2fa: request.requires_2fa,
    };

    let mut user_store = state.user_store.write().await;

    let result = user_store.add_user(user).await;
    if result.is_err() {
        if result.unwrap_err() == UserStoreError::UserAlreadyExists {
            return Err(AuthAPIError::UserAlreadyExists);
        }
        return Err(AuthAPIError::UnexpectedError);
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}
