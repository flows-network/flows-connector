#![recursion_limit = "256"]

use crate::installations::installations;

use axum::{
    routing::{delete, get, post},
    Router,
};

use github_connector::routes::{
    actions::actions, auth::auth, create_hook::create_hook, event::capture_event,
    hook_events::hook_events, installations, post::post_msg, repos::repos,
    revoke_hook::revoke_hook,
};

use std::env;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/actions", post(actions))
        .route("/auth", get(auth))
        .route("/event", post(capture_event))
        .route("/create-hook", post(create_hook))
        .route("/hook-events", post(hook_events))
        .route("/post", post(post_msg))
        .route("/repos", post(repos))
        .route("/revoke-hook", delete(revoke_hook))
        .route("/installations", post(installations));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
