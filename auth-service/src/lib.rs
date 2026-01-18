use axum::{routing::post, serve::Serve, Router};
use std::error::Error;
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

pub mod routes;
use crate::routes::*;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir =
            ServeDir::new("assets").not_found_service(ServeFile::new("assets/index.html"));
        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(signup_handler))
            .route("/login", post(login_handler))
            .route("/verify-2fa", post(verify_2fa_handler))
            .route("/logout", post(logout_handler))
            .route("/verify-token", post(verify_token_handler));

        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
