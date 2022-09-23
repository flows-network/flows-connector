use axum::response::IntoResponse;
use serde_json::Value;

use crate::{models::Shortcut, utils::post_event_to_reactor};

pub async fn inter(s: String) -> impl IntoResponse {
    let body: Value = serde_urlencoded::from_str(&s).unwrap();
    let payload = body.get("payload").unwrap();
    let shortcut: Shortcut = serde_json::from_str(payload.as_str().unwrap()).unwrap();

    tokio::spawn(post_event_to_reactor(
        shortcut.user.id,
        shortcut.message.text,
        vec![],
        shortcut.channel.id,
        "shortcut".to_string(),
    ));
}
