use std::collections::HashMap;

use crate::domain::{User, UserStoreError};
use crate::UserStore;

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let id = user.email.address.clone();
        if self.users.contains_key(&id) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(id, user);
        Ok(())
    }

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        let result = self.users.get(email);
        return match result {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        };
    }

    // FIXME: should not differentiate between missing user and invalid password!
    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.password.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use fake::{
        faker::internet::en::{Password, SafeEmail},
        Fake,
    };

    use super::*;
    use crate::domain::Email;
    use crate::Password as MyPassword;

    #[tokio::test]
    async fn should_add_unique_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = MyPassword::parse(Password(10..12).fake()).unwrap();
        let user = User {
            email,
            password,
            requires_2fa: true,
        };
        let mut store = HashmapUserStore::new();

        let result = store.add_user(user).await;

        assert_eq!(result.unwrap(), ());
    }

    #[tokio::test]
    async fn should_refuse_to_add_duplicate_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = MyPassword::parse(Password(10..12).fake()).unwrap();
        let user = User {
            email: email.clone(),
            password: password.clone(),
            requires_2fa: true,
        };
        let mut store = HashmapUserStore::new();
        store.users.insert(
            email.address.clone(),
            User {
                email,
                password,
                requires_2fa: true,
            },
        );

        let result = store.add_user(user).await;

        assert_eq!(result.unwrap_err(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn should_get_existing_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = MyPassword::parse(Password(10..12).fake()).unwrap();
        let mut store = HashmapUserStore::new();
        store.users.insert(
            "email".to_owned(),
            User {
                email,
                password,
                requires_2fa: true,
            },
        );

        let result = store.get_user("email").await;

        assert_eq!(result.is_ok(), true);
    }

    #[tokio::test]
    async fn should_refuse_to_get_missing_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = MyPassword::parse(Password(10..12).fake()).unwrap();
        let mut store = HashmapUserStore::new();
        store.users.insert(
            "email".to_owned(),
            User {
                email,
                password,
                requires_2fa: true,
            },
        );

        let result = store.get_user("id").await;

        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn should_refuse_to_validate_unknown_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = MyPassword::parse(Password(10..12).fake()).unwrap();
        let mut store = HashmapUserStore::new();
        store.users.insert(
            "email".to_owned(),
            User {
                email,
                password,
                requires_2fa: true,
            },
        );

        let result = store.validate_user("unknown", "password").await;

        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn should_refuse_to_validate_user_with_incorrect_creds() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = MyPassword::parse(Password(10..12).fake()).unwrap();
        let mut store = HashmapUserStore::new();
        store.users.insert(
            "email".to_owned(),
            User {
                email,
                password,
                requires_2fa: true,
            },
        );

        let result = store.validate_user("email", "password").await;

        assert_eq!(result.unwrap_err(), UserStoreError::InvalidCredentials);
    }
}
