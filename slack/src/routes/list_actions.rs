use axum::response::IntoResponse;

use crate::global::ACTIONS;

pub async fn list_actions() -> impl IntoResponse {
    ([("content-type", "application/json")], *ACTIONS)
}
