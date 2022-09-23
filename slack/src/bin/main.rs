use axum::{
    routing::{get, post},
    Router, Server,
};

use slack_connector::routes::{
    auth::auth,
    channels::route_channels,
    event::capture_event,
    inter::inter,
    join_channel::join_channel,
    list_actions::list_actions,
    list_events::list_events,
    post::{post_msg, upload_msg},
};
use std::env;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/auth", get(auth))
        .route("/channels", post(route_channels))
        .route("/event", post(capture_event))
        .route("/inter", post(inter))
        .route("/join-channel", post(join_channel))
        .route("/actions", post(list_actions))
        .route("/events", post(list_events))
        .route("/post", post(post_msg).put(upload_msg));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
