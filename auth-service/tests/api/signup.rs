use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = TestApp::get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123"
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": "foo"
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2fa": false
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&body).await;

    assert_eq!(
        response.status().as_u16(),
        201,
        "Failed to receive 201 for valid signup request"
    );
    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };
    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = TestApp::get_random_email();

    let test_cases = [
        serde_json::json!({
            "email": "invalid",
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": random_email,
            "password": "short",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": random_email,
            "password": "",
            "requires2FA": true,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let _ = app.post_signup(&body).await;
    let response = app.post_signup(&body).await;

    assert_eq!(
        response.status().as_u16(),
        409,
        "Failed to receive 409 for duplicate signup request"
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}
