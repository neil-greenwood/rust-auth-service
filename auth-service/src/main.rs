use auth_service::{
    app_state::AppState, services::hashmap_user_store::HashmapUserStore, Application,
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = HashmapUserStore::new();
    let app_state = AppState::new(Arc::new(RwLock::new(user_store)));

    // Here we are using ip 0.0.0.0 so the service is listening on all the configured network interfaces.
    // This is needed for Docker to work, which we will add later on.
    // See: https://stackoverflow.com/questions/39525820/docker-port-forwarding-not-working
    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");
    app.run().await.expect("Failed to run app");
}
