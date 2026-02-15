use hibp::check;
use std::collections::HashMap;
use validator::{Validate, ValidationError, ValidationErrors, ValidationErrorsKind};

#[derive(Debug, Validate)]
pub struct Password {
    #[validate(length(min = 8))]
    pub password: String,
}

impl Password {
    async fn parse(input: &str) -> Result<Password, ValidationErrors> {
        let in_str = input.to_string();
        let password = Password {
            password: in_str.clone(),
        };
        if let Err(error) = password.validate() {
            return Err(error);
        }
        if let Err(_) = check(in_str).await {
            let error = ValidationError::new("Vulnerable or common password");
            let error_kind = ValidationErrorsKind::Field(vec![error]);
            return Err(ValidationErrors(HashMap::from_iter([(
                std::borrow::Cow::Borrowed("hibp"),
                error_kind,
            )])));
        }
        Ok(password)
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.password
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_reject_short_passwords() {
        let test_cases = ["", "012345", "123456", "1234567", "qW%f3_a"];
        for test_case in test_cases.iter() {
            let result = Password::parse(test_case).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn should_reject_hibp_passwords() {
        let test_cases = ["password123", "qwertyuiop", "asdfghjkl", "itsasecret"];
        for test_case in test_cases.iter() {
            let result = Password::parse(test_case).await;
            assert!(result.is_err(), "Failed for input: {:?}", test_case);
        }
    }
}
