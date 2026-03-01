pub enum AuthAPIError {
    UserAlreadyExists,
    IncorrectCredentials,
    InvalidCredentials,
    UnexpectedError,
    MissingToken,
    InvalidToken,
}
