use validator::{Validate, ValidationErrors};

#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct Password {
    #[validate(length(min = 8))]
    pub password: String,
}

impl Password {
    pub fn parse_str(input: &str) -> Result<Password, ValidationErrors> {
        Self::parse(input.to_owned())
    }
    pub fn parse(input: String) -> Result<Password, ValidationErrors> {
        let password = Password { password: input };
        if let Err(errors) = password.validate() {
            return Err(errors);
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
            let result_str = Password::parse_str(test_case);
            let result = Password::parse(test_case.to_string());
            assert!(result_str.is_err());
            assert!(result.is_err());
        }
    }
}
