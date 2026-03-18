use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{domain::BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<dyn UserStore + Send + Sync>>;
pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;
pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>;
pub type EmailClientType = Arc<RwLock<dyn EmailClient + Send + Sync>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_tokens: BannedTokenStoreType,
    pub two_fa_codes: TwoFACodeStoreType,
    pub email_client: EmailClientType,
}

impl AppState {
    pub fn new(
        user_store: UserStoreType,
        banned_tokens: BannedTokenStoreType,
        two_fa_codes: TwoFACodeStoreType,
        email_client: EmailClientType,
    ) -> Self {
        Self {
            user_store,
            banned_tokens,
            two_fa_codes,
            email_client,
        }
    }
}
