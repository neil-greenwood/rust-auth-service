use validator::{Validate, ValidationErrors};

#[derive(Debug, Validate, PartialEq)]
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
    fn parse(input: &str) -> Result<Email, ValidationErrors> {
        let email = Email {
            address: input.to_string(),
        };
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
        let result = Email::parse("");

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_reject_missing_at() {
        let result = Email::parse("input");

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_accept_valid_email() {
        let result = Email::parse("user@example.com");

        assert_eq!(
            result.unwrap(),
            Email {
                address: "user@example.com".to_string()
            }
        );
    }
}
