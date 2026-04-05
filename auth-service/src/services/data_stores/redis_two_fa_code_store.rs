use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let value = TwoFATuple(
            login_attempt_id.as_ref().to_string(),
            code.as_ref().to_string(),
        );
        let tuple_str =
            serde_json::to_string(&value).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let _: () = self
            .conn
            .write()
            .await
            .set_ex(key, tuple_str, TEN_MINUTES_IN_SECONDS)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);
        let _: () = self
            .conn
            .write()
            .await
            .del(&key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);
        let code_str = self
            .conn
            .write()
            .await
            .get::<_, String>(&key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;
        let tuple: TwoFATuple =
            serde_json::from_str(&code_str).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let login_attempt_id =
            LoginAttemptId::parse(tuple.0).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let code = TwoFACode::parse(tuple.1).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        Ok((login_attempt_id, code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
