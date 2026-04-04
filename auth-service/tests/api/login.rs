use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};
use test_helpers::api_test;

use crate::helpers::TestApp;

#[api_test]
async fn should_return_422_if_malformed_input() {
    let random_email = TestApp::get_random_email();

    let test_cases = [
        serde_json::json!({ "password": "password123", }),
        serde_json::json!({ "email": random_email, }),
        serde_json::json!({ "Email": random_email, "Password": "password123", }),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[api_test]
async fn should_return_400_if_invalid_input() {
    let random_email = TestApp::get_random_email();

    let test_cases = [
        serde_json::json!({
            "email": "invalid",
            "password": "password123",
        }),
        serde_json::json!({
            "email": "",
            "password": "password123",
        }),
        serde_json::json!({
            "email": random_email,
            "password": "",
        }),
        serde_json::json!({
            "email": random_email,
            "password": "short",
        }),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[api_test]
async fn should_return_400_if_credentials_are_not_correct() {
    let random_email = TestApp::get_random_email();
    let signup = serde_json::json!({
        "email": random_email, "password": "passWord123", "requires2FA": false,
    });
    let response = app.post_signup(&signup).await;
    assert_eq!(response.status().as_u16(), 201);

    let test_cases = [
        serde_json::json!({"email": "incorrect@example.com", "password": "passWord123"}),
        serde_json::json!({"email": random_email, "password": "incorrect"}),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_login(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[api_test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let random_email = TestApp::get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[api_test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let random_email = TestApp::get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);
    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");
    assert_eq!(json_body.message, "2FA required".to_owned());
    let two_fa_codes = app.two_fa_codes.read().await;
    let code_tuple = two_fa_codes
        .get_code(&Email::parse(random_email).unwrap())
        .await
        .expect("Failed to get 2FA code");
    assert_eq!(code_tuple.0.as_ref(), json_body.login_attempt_id);
}
