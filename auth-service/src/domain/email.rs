use validator::{Validate, ValidationErrors};

#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct Email {
    #[validate(email)]
    pub address: String,
}

// TODO wrap validation error with domain-specific error
#[derive(Debug, PartialEq)]
pub enum EmailValidationError {
    Invalid,
}

impl Email {
    pub fn parse_str(input: &str) -> Result<Email, ValidationErrors> {
        Self::parse(input.to_owned())
    }
    pub fn parse(input: String) -> Result<Email, ValidationErrors> {
        let email = Email { address: input };
        match email.validate() {
            Ok(_) => Ok(email),
            Err(e) => Err(e),
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_reject_empty_input() {
        let result_str = Email::parse_str("");
        let result = Email::parse("".to_owned());

        assert!(result_str.is_err());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_reject_missing_at() {
        let result_str = Email::parse_str("input");
        let result = Email::parse("input".to_owned());

        assert!(result_str.is_err());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_accept_valid_email() {
        let result_str = Email::parse_str("user@example.com");
        let result = Email::parse("user@example.com".to_owned());

        assert_eq!(
            result_str.unwrap(),
            Email {
                address: "user@example.com".to_string()
            }
        );
        assert_eq!(
            result.unwrap(),
            Email {
                address: "user@example.com".to_string()
            }
        );
    }
}
