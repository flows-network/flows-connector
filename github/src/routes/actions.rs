use axum::response::IntoResponse;

use codegen::actions_gen;

#[actions_gen("./github/codegen/openapi/api.github.com.json")]
pub async fn actions() -> impl IntoResponse {}
