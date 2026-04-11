use auth_service::{
    app_state::AppState,
    get_postgres_pool, get_redis_client,
    services::data_stores::{
        mock_email_client::MockEmailClient, postgrep_user_store::PostgresUserStore,
        redis_banned_token_store::RedisBannedTokenStore,
        redis_two_fa_code_store::RedisTwoFACodeStore,
    },
    utils::{
        constants::{prod, DATABASE_URL, REDIS_HOST_NAME},
        tracing::init_tracing,
    },
    Application,
};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");
    let redis_connection = Arc::new(RwLock::new(configure_redis()));
    let banned_token_store = RedisBannedTokenStore::new(redis_connection.clone());
    let two_fa_codes = RedisTwoFACodeStore::new(redis_connection);
    let email_client = MockEmailClient {};
    let pg_pool = configure_postgresql().await;
    let user_store = PostgresUserStore::new(pg_pool);
    let app_state = AppState::new(
        Arc::new(RwLock::new(user_store)),
        Arc::new(RwLock::new(banned_token_store)),
        Arc::new(RwLock::new(two_fa_codes)),
        Arc::new(RwLock::new(email_client)),
    );

    // Here we are using ip 0.0.0.0 so the service is listening on all the configured network interfaces.
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");
    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_string())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
