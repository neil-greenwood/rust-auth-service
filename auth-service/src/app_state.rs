use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{domain::BannedTokenStore, TwoFACodeStore, UserStore};

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<dyn UserStore + Send + Sync>>;
pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;
pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_tokens: BannedTokenStoreType,
    pub two_fa_codes: TwoFACodeStoreType,
}

impl AppState {
    pub fn new(
        user_store: UserStoreType,
        banned_tokens: BannedTokenStoreType,
        two_fa_codes: TwoFACodeStoreType,
    ) -> Self {
        Self {
            user_store,
            banned_tokens,
            two_fa_codes,
        }
    }
}
