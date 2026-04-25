use color_eyre::eyre::{eyre, Context, Report, Result};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use uuid::Uuid;

use super::{Email, User};

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError>;
    async fn check_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
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

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        let parsed_value = Uuid::parse_str(&id).wrap_err("Invalid login attempt ID")?;
        Ok(Self(SecretString::new(
            parsed_value.to_string().into_boxed_str(),
        )))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(SecretString::new(
            Uuid::new_v4().to_string().into_boxed_str(),
        ))
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct TwoFACode(SecretString);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        let _code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;
        if code.len() == 6 {
            Ok(Self(SecretString::new(code.into_boxed_str())))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        Self(SecretString::new(
            format!("{:06}", rand::rng().random_range(0..=999_999)).into_boxed_str(),
        ))
    }
}

impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use fake::{uuid::UUIDv4, Fake};
    use secrecy::ExposeSecret;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn login_attempt_id_should_create_a_default() {
        let result = LoginAttemptId::default();

        assert!(Uuid::try_parse(result.as_ref().expose_secret()).is_ok());
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

        let internal_result = result.0.expose_secret();
        assert_eq!(internal_result.len(), 6);
        assert!(internal_result.parse::<u32>().is_ok());
        assert_ne!(internal_result, "000000");
        assert_ne!(internal_result, "123456");
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
