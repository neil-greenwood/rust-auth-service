use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, UserStoreError},
    utils::auth::generate_auth_cookie,
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

// #[axum::debug_handler]
pub async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Ok(email) = Email::parse(request.email) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };
    let Ok(password) = Password::parse(request.password) else {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let user_store = state.user_store.read().await;

    let result = user_store
        .validate_user(&email.address, &password.password)
        .await;
    if result.is_err() {
        let error = result.unwrap_err();
        if error == UserStoreError::InvalidCredentials || error == UserStoreError::UserNotFound {
            return (jar, Err(AuthAPIError::IncorrectCredentials));
        }
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // call the generate_auth_cookie function.
    let Ok(auth_cookie) = generate_auth_cookie(&email) else {
        return (jar, Err(AuthAPIError::UnexpectedError));
    };

    let updated_jar = jar.add(auth_cookie);

    let response = Json(LoginResponse {
        message: "Authenticated successfully".to_string(),
    });
    (updated_jar, Ok((StatusCode::OK, response)))
}
