use axum::response::IntoResponse;
use codegen::events_gen;

#[events_gen("./github/codegen/openapi/api.github.com.json")]
pub async fn hook_events() -> impl IntoResponse {}
