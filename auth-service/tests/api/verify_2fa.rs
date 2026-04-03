use auth_service::{
    domain::{Email, LoginAttemptId, HashedPassword, TwoFACode},
    utils::constants::JWT_COOKIE_NAME,
};
use fake::{faker::internet::en::Password as FakePassword, Fake};

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let login_attempt_id = LoginAttemptId::default();
    let test_cases = [
        serde_json::json!({"loginAttemptId": "attempt1", "2FACode": "123456"}),
        serde_json::json!({"email": random_email, "loginAttemptId": login_attempt_id}),
        serde_json::json!({"email": random_email, "2FACode": "123456"}),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let login_attempt_id = LoginAttemptId::default().as_ref().to_owned();
    let two_fa_code = TwoFACode::default().as_ref().to_owned();
    let test_cases = vec![
        serde_json::json!({"email": "invalid_email", "loginAttemptId": login_attempt_id, "2FACode": two_fa_code}),
        serde_json::json!({"email": random_email, "loginAttemptId": "invalid_login_attempt", "2FACode": two_fa_code}),
        serde_json::json!({"email": random_email, "loginAttemptId": login_attempt_id, "2FACode": "invalid_2FA_code"}),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let password = HashedPassword::parse(FakePassword(10..12).fake()).await.unwrap();
    let signup_request = serde_json::json!({"email": random_email, "password": password.as_ref(), "requires2FA": true});
    let login_request = serde_json::json!({"email": random_email, "password": password.as_ref()});
    app.post_signup(&signup_request).await;
    let _response = app.post_login(&login_request).await;
    let first_code = app
        .two_fa_codes
        .read()
        .await
        .get_code(&Email::parse(random_email.clone()).unwrap())
        .await
        .unwrap();
    let first_attempt_id = first_code.0.as_ref().to_string();
    let invalid_2fa_code = TwoFACode::default().as_ref().to_string();

    let verify_request = serde_json::json!({"email": random_email, "loginAttemptId": first_attempt_id, "2FACode": invalid_2fa_code});
    let response = app.post_verify_2fa(&verify_request).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then attempt to call verify-2fa with the 2FA code from
    // the first login request. This should fail.
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let password = HashedPassword::parse(FakePassword(10..12).fake()).await.unwrap();
    let signup_request = serde_json::json!({"email": random_email, "password": password.as_ref(), "requires2FA": true});
    let login_request = serde_json::json!({"email": random_email, "password": password.as_ref()});
    app.post_signup(&signup_request).await;
    let _response1 = app.post_login(&login_request).await;
    let first_code = app
        .two_fa_codes
        .read()
        .await
        .get_code(&Email::parse(random_email.clone()).unwrap())
        .await
        .unwrap();
    let first_attempt_id = first_code.0.as_ref().to_string();
    let first_2fa_code = first_code.1.as_ref().to_string();
    let _response2 = app.post_login(&login_request).await;
    println!("Attempting to verify with code {:?}", first_2fa_code);
    let verify_request = serde_json::json!({"email": random_email, "loginAttemptId": first_attempt_id, "2FACode": first_2fa_code});

    let response = app.post_verify_2fa(&verify_request).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_credentials_are_valid() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let password = HashedPassword::parse(FakePassword(10..12).fake()).await.unwrap();
    let signup_request = serde_json::json!({"email": random_email, "password": password.as_ref(), "requires2FA": true});
    let login_request = serde_json::json!({"email": random_email, "password": password.as_ref()});
    app.post_signup(&signup_request).await;
    let _response = app.post_login(&login_request).await;
    let first_code = app
        .two_fa_codes
        .read()
        .await
        .get_code(&Email::parse(random_email.clone()).unwrap())
        .await
        .unwrap();
    let first_attempt_id = first_code.0.as_ref().to_string();
    let first_2fa_code = first_code.1.as_ref().to_string();

    let verify_request = serde_json::json!({"email": random_email, "loginAttemptId": first_attempt_id, "2FACode": first_2fa_code});
    let response = app.post_verify_2fa(&verify_request).await;

    assert_eq!(response.status().as_u16(), 200);
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());
    let final_code = app
        .two_fa_codes
        .read()
        .await
        .get_code(&Email::parse(random_email.clone()).unwrap())
        .await;
    assert!(final_code.is_err());
}
