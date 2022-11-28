use axum::{response::IntoResponse, Json};

use codegen::action_gen;

#[action_gen("./github/codegen/openapi/api.github.com.json")]
pub async fn actions() -> impl IntoResponse {}
