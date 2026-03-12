use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Some(cookie) = jar.get(JWT_COOKIE_NAME) else {
        return (jar, Err(AuthAPIError::MissingToken));
    };

    let token = cookie.value().to_owned();
    let banned_tokens = state.banned_tokens.clone();
    let Ok(result) = validate_token(&token, banned_tokens).await else {
        return (jar, Err(AuthAPIError::InvalidToken));
    };
    if state
        .banned_tokens
        .write()
        .await
        .add_token(token.to_owned())
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));
    let mut token_store = state.banned_tokens.write().await;
    if token_store.add_token(token).await.is_err() {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    (jar, Ok(StatusCode::OK))
}
