use auth_service::utils::constants::JWT_COOKIE_NAME;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({ "password": "password123", }),
        serde_json::json!({ "token": true, }),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_200_if_valid_token() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false,
    });
    app.post_signup(&signup_body).await;
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    let login_response = app.post_login(&login_body).await;
    let auth_cookie = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();
    let verify_token_body = serde_json::json!({
        "token": &token,
    });

    let response = app.post_verify_token(&verify_token_body).await;

    assert_eq!(response.status().as_u16(), 200, "Failed for valid token");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let verify_token_body = serde_json::json!({ "token": "invalid", });

    let response = app.post_verify_token(&verify_token_body).await;

    assert_eq!(response.status().as_u16(), 401, "Failed for invalid token");
}
