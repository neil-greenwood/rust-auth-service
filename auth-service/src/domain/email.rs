use color_eyre::eyre::{eyre, Result};
use validator::ValidateEmail;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(input: String) -> Result<Email> {
        if input.validate_email() {
            Ok(Self(input))
        } else {
            Err(eyre!(format!("{} is not a valid email.", input)))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_reject_empty_input() {
        let result = Email::parse("".to_owned());

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_reject_missing_at() {
        let result = Email::parse("input".to_owned());

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_accept_valid_email() {
        let result = Email::parse("user@example.com".to_owned());

        assert!(result.is_ok());
    }
}
