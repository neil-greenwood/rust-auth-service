use rand::Rng;
use serde::Serialize;
use uuid::Uuid;

use super::User;
use crate::Email;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn check_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug)]
pub enum BannedTokenStoreError {
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        let parsed_value =
            Uuid::parse_str(&id).map_err(|_| "Invalid login attempt ID".to_owned())?;
        Ok(Self(parsed_value.to_string()))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        let _code_as_u32 = code
            .parse::<u32>()
            .map_err(|_| "Invalid 2FA code".to_owned())?;
        if code.len() == 6 {
            Ok(Self(code))
        } else {
            Err("Invalid 2FA code".to_owned())
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        Self(format!("{:06}", rand::rng().random_range(0..=999_999)))
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use fake::{uuid::UUIDv4, Fake};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn login_attempt_id_should_create_a_default() {
        let result = LoginAttemptId::default();

        assert!(Uuid::try_parse(result.as_ref()).is_ok());
    }

    #[test]
    fn login_attempt_id_should_parse_valid_uuids_correctly() {
        let fake_uuid = UUIDv4.fake::<String>();
        let test_cases = [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            fake_uuid.as_str(),
        ];
        for test_case in test_cases {
            assert!(
                LoginAttemptId::parse(test_case.to_string()).is_ok(),
                "Failed for input: {}",
                test_case
            );
        }
    }

    #[test]
    fn login_attempt_id_should_parse_invalid_uuids_correctly() {
        let test_cases = ["", "invalid", "user@example.com"];
        for test_case in test_cases {
            assert!(
                LoginAttemptId::parse(test_case.to_string()).is_err(),
                "Failed for input: {}",
                test_case
            );
        }
    }

    #[test]
    fn two_fa_code_should_create_a_default() {
        let result = TwoFACode::default();

        assert_eq!(result.0.len(), 6);
        assert!(result.0.parse::<u32>().is_ok());
        assert_ne!(result.0, "000000");
        assert_ne!(result.0, "123456");
    }

    #[test]
    fn two_fa_code_should_parse_correctly() {
        let positive_test_cases = ["000000", "012345", "123456", "234876", "999999"];
        let negative_test_cases = ["", "0", "abc", "this is not a valid code"];
        for test_case in positive_test_cases {
            assert!(
                TwoFACode::parse(test_case.to_string()).is_ok(),
                "Failed for input: {}",
                test_case
            );
        }
        for test_case in negative_test_cases {
            assert!(
                TwoFACode::parse(test_case.to_string()).is_err(),
                "Failed for input: {}",
                test_case
            );
        }
    }
}
