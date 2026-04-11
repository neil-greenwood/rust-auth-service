use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
}
