use super::User;

#[async_trait::async_trait]
pub trait UserStore {
    // TODO: Add the `add_user`, `get_user`, and `validate_user` methods.
    // Make sure all methods are async so we can use async user stores in the future
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}
