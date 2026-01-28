use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Default)]
struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let id = user.email.clone();
        if self.users.contains_key(&id) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(id, user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        let result = self.users.get(&email.to_string());
        return match result {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        };
    }

    // FIXME: should not differentiate between missing user and invalid password!
    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;
        if user.password != password.to_string() {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_add_unique_user() {
        let user = User {
            email: "email".to_owned(),
            password: "pwd".to_owned(),
            requires_2fa: true,
        };
        let mut store = HashmapUserStore {
            users: HashMap::new(),
        };

        let result = store.add_user(user);

        assert_eq!(result.unwrap(), ());
    }

    #[tokio::test]
    async fn should_refuse_to_add_duplicate_user() {
        let user = User {
            email: "email".to_owned(),
            password: "pwd".to_owned(),
            requires_2fa: true,
        };
        let mut store = HashmapUserStore {
            users: HashMap::new(),
        };
        store.users.insert(
            "email".to_owned(),
            User {
                email: "".to_owned(),
                password: "".to_owned(),
                requires_2fa: true,
            },
        );

        let result = store.add_user(user);

        assert_eq!(result.unwrap_err(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn should_get_existing_user() {
        let mut store = HashmapUserStore {
            users: HashMap::new(),
        };
        store.users.insert(
            "email".to_owned(),
            User {
                email: "".to_owned(),
                password: "".to_owned(),
                requires_2fa: true,
            },
        );

        let result = store.get_user("email");

        assert_eq!(result.is_ok(), true);
    }

    #[tokio::test]
    async fn should_refuse_to_get_missing_user() {
        let mut store = HashmapUserStore {
            users: HashMap::new(),
        };
        store.users.insert(
            "email".to_owned(),
            User {
                email: "".to_owned(),
                password: "".to_owned(),
                requires_2fa: true,
            },
        );

        let result = store.get_user("id");

        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn should_refuse_to_validate_unknown_user() {
        let mut store = HashmapUserStore {
            users: HashMap::new(),
        };
        store.users.insert(
            "email".to_owned(),
            User {
                email: "".to_owned(),
                password: "".to_owned(),
                requires_2fa: true,
            },
        );

        let result = store.validate_user("unknown", "password");

        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn should_refuse_to_validate_user_with_incorrect_creds() {
        let mut store = HashmapUserStore {
            users: HashMap::new(),
        };
        store.users.insert(
            "email".to_owned(),
            User {
                email: "email".to_owned(),
                password: "secret".to_owned(),
                requires_2fa: true,
            },
        );

        let result = store.validate_user("email", "password");

        assert_eq!(result.unwrap_err(), UserStoreError::InvalidCredentials);
    }
}
