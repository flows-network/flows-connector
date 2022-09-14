use axum::{response::IntoResponse, Json};

use crate::global::EVENTS;

pub async fn hook_events() -> impl IntoResponse {
    Json(&*EVENTS)
}
