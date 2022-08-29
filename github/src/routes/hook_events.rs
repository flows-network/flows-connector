use axum::{Json, response::IntoResponse};
use serde_json::json;

use crate::global::EVENTS;

pub async fn hook_events() -> impl IntoResponse {
    Json(json!({
        "list": &*EVENTS
    }))
}

