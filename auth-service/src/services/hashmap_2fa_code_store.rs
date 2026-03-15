use std::collections::HashMap;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some(result) => Ok(result.clone()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::{faker::internet::en::SafeEmail, Fake};

    #[tokio::test]
    async fn should_add_valid_code_to_2fa_store() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;

        assert!(result.is_ok());
        assert_eq!(store.codes.get(&email), Some(&(login_attempt_id, code)))
    }

    #[tokio::test]
    async fn should_remove_matching_code_from_2fa_store() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store.codes.insert(email.clone(), (login_attempt_id, code));

        let result = store.remove_code(&email).await;

        assert!(result.is_ok());
        assert_eq!(store.codes.get(&email), None);
    }

    #[tokio::test]
    async fn should_not_remove_missing_code_from_2fa_store() {
        let mut store = HashmapTwoFACodeStore::default();
        let stored_email = Email::parse(SafeEmail().fake()).unwrap();
        let attempted_email = Email::parse(SafeEmail().fake()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store
            .codes
            .insert(stored_email, (login_attempt_id.clone(), code.clone()));

        let result = store.remove_code(&attempted_email).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn should_get_matching_code_from_2fa_store() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(SafeEmail().fake()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store
            .codes
            .insert(email.clone(), (login_attempt_id.clone(), code.clone()));

        let result = store.get_code(&email).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (login_attempt_id, code));
    }

    #[tokio::test]
    async fn should_not_get_missing_code_from_2fa_store() {
        let mut store = HashmapTwoFACodeStore::default();
        let stored_email = Email::parse(SafeEmail().fake()).unwrap();
        let attempted_email = Email::parse(SafeEmail().fake()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store.codes.insert(stored_email, (login_attempt_id, code));

        let result = store.get_code(&attempted_email).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }
}
