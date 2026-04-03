use std::collections::HashMap;

use crate::{
    domain::{User, UserStoreError},
    Email, UserStore,
};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
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
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) => user
                .password
                .verify_raw_password(raw_password)
                .await
                .map_err(|_| UserStoreError::InvalidCredentials),
            None => Err(UserStoreError::InvalidCredentials),
        }
    }
}

#[cfg(test)]
mod tests {
    use fake::{
        faker::internet::en::{Password as FakePassword, SafeEmail},
        Fake,
    };

    use super::*;
    use crate::domain::Email;
    use crate::domain::HashedPassword;

    #[tokio::test]
    async fn should_add_unique_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = HashedPassword::parse(FakePassword(10..12).fake())
            .await
            .unwrap();
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
        let password = HashedPassword::parse(FakePassword(10..12).fake())
            .await
            .unwrap();
        let user = User {
            email: email.clone(),
            password: password.clone(),
            requires_2fa: true,
        };
        let mut store = HashmapUserStore::new();
        store.users.insert(
            email.clone(),
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
        let password = HashedPassword::parse(FakePassword(10..12).fake())
            .await
            .unwrap();
        let mut store = HashmapUserStore::new();
        let user = User {
            email: email.clone(),
            password,
            requires_2fa: true,
        };
        store.users.insert(email.clone(), user.clone());

        let result = store.get_user(&email).await;

        assert_eq!(result.is_ok(), true);
    }

    #[tokio::test]
    async fn should_refuse_to_get_missing_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = HashedPassword::parse(FakePassword(10..12).fake())
            .await
            .unwrap();
        let mut store = HashmapUserStore::new();
        let user = User {
            email: email.clone(),
            password,
            requires_2fa: true,
        };
        store.users.insert(email.clone(), user.clone());

        let result = store
            .get_user(&Email::parse("unknown@example.com".to_owned()).unwrap())
            .await;

        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn should_refuse_to_validate_unknown_user() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = HashedPassword::parse(FakePassword(10..12).fake())
            .await
            .unwrap();
        let mut store = HashmapUserStore::new();
        let user = User {
            email: email.clone(),
            password,
            requires_2fa: true,
        };
        store.users.insert(email.clone(), user.clone());

        let actual_email = Email::parse(SafeEmail().fake()).unwrap();
        let result = store.validate_user(&actual_email, "password").await;

        assert_eq!(result.unwrap_err(), UserStoreError::InvalidCredentials);
    }

    #[tokio::test]
    async fn should_refuse_to_validate_user_with_incorrect_creds() {
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let password = HashedPassword::parse(FakePassword(10..12).fake())
            .await
            .unwrap();
        let mut store = HashmapUserStore::new();
        let user = User {
            email: email.clone(),
            password,
            requires_2fa: true,
        };
        store.users.insert(email.clone(), user.clone());

        let result = store.validate_user(&email, "password").await;

        assert_eq!(result.unwrap_err(), UserStoreError::InvalidCredentials);
    }
}
