use axum::response::IntoResponse;

use crate::global::EVENTS;

pub async fn list_events() -> impl IntoResponse {
    ([("content-type", "application/json")], *EVENTS)
}
