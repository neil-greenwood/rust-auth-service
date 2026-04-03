use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    token_store: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.token_store.insert(token);
        Ok(())
    }

    async fn check_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.token_store.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut test_store = HashsetBannedTokenStore::default();
        let token = "foobar".to_owned();

        let result = test_store.add_token(token.clone()).await;

        assert!(result.is_ok());
        assert!(test_store.token_store.contains(&token));
    }

    #[tokio::test]
    async fn test_contains_token() {
        let mut test_store = HashsetBannedTokenStore::default();
        let token = "foobar".to_owned();
        test_store.token_store.insert(token.clone());

        let result = test_store.check_token(&token).await;

        assert!(result.unwrap());
    }
}
