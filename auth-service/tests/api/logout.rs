use auth_service::utils::constants::JWT_COOKIE_NAME;
use reqwest::Url;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    let _ = app.post_signup(&signup_body).await;
    let response = app.post_login(&login_body).await;
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    let token = auth_cookie.value();

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(auth_cookie.value().is_empty());
    let banned_token_store = app.banned_tokens.read().await;
    let contains_token = banned_token_store
        .check_token(token)
        .await
        .expect("Failed to check that token store contains logged out token");
    assert!(contains_token);
}

#[tokio::test]
async fn should_return_400_if_logout_called_more_than_once() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    let _ = app.post_signup(&signup_body).await;
    let _ = app.post_login(&login_body).await;

    let _ = app.post_logout().await;
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}
