use auth_service::{
    domain::Email,
    utils::{auth::generate_auth_cookie, constants::JWT_COOKIE_NAME},
};
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
    login_random_user(&app).await;

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);
}

async fn login_random_user(app: &TestApp) {
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
}

#[tokio::test]
async fn should_return_400_if_logout_called_more_than_once() {
    let app = TestApp::new().await;
    login_random_user(&app).await;

    let _ = app.post_logout().await;
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}
