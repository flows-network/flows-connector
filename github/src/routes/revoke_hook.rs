use axum::{extract::Query, response::IntoResponse, Json};
use reqwest::{header, StatusCode};

use crate::{
    fetch_github::get_installation_token,
    global::HTTP_CLIENT,
    models::{AuthState, HookReq, HookRoutes, RevokeQuery},
    utils::decrypt,
};

pub async fn revoke_hook(
    Json(req): Json<HookReq>,
    Query(query): Query<RevokeQuery>,
) -> impl IntoResponse {
    if req.routes.event.len() == 0 || req.routes.repo.len() != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            String::from("Bad routes, only one repo is allowed"),
        ));
    }

    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

    match get_installation_token(auth_state.installation_id).await {
        Ok(install_token) => {
            match revoke_hook_inner(&req.routes, &query.hook_id, &install_token).await {
                Ok(()) => Ok(StatusCode::OK),
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            }
        }
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

pub async fn revoke_hook_inner(
    routes: &HookRoutes,
    hook_id: &str,
    install_token: &str,
) -> Result<(), String> {
    let response = HTTP_CLIENT
        .delete(format!(
            "https://api.github.com/repos/{}/hooks/{hook_id}",
            routes.repo[0].field
        ))
        .header(header::ACCEPT, "application/vnd.github.v3+json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .bearer_auth(install_token)
        .send()
        .await;
    if let Ok(_) = response {
        // the status can be 204 or 404
        // so no need to check r.status().is_success()
        // always return ok
        return Ok(());
    }
    Err("Failed to revoke hook".to_string())
}
