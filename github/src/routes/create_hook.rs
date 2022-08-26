use axum::{response::IntoResponse, Json};
use reqwest::StatusCode;
use serde_json::{json, Value};

use crate::{
    fetch_github::get_installation_token,
    global::{HTTP_CLIENT, SERVICE_API_PREFIX},
    models::{AuthState, HookReq, HookRoutes},
    utils::decrypt,
};

pub async fn create_hook(Json(req): Json<HookReq>) -> impl IntoResponse {
    if req.routes.event.len() == 0 || req.routes.repo.len() != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            String::from("Bad routes, only one repo is allowed"),
        ));
    }
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

    match get_installation_token(auth_state.installation_id).await {
        Ok(install_token) => {
            match create_hook_inner(&req.user, &req.flow, &req.routes, &install_token).await {
                Ok(v) => Ok((StatusCode::CREATED, Json(v))),
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            }
        }
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

pub async fn create_hook_inner(
    connector: &str,
    flow_id: &str,
    routes: &HookRoutes,
    install_token: &str,
) -> Result<Value, String> {
    let events: Vec<String> = routes.event.iter().map(|e| e.value.clone()).collect();
    let param = json!({
        "name": "web",
        "active": true,
        "events": events,
        "config": {
            "url": format!("{}/event?connector={connector}&flow={flow_id}", SERVICE_API_PREFIX.as_str()),
            "content_type": "form",
        }
    });
    let response = HTTP_CLIENT
        .post(format!(
            "https://api.github.com/repos/{}/hooks",
            routes.repo[0].field
        ))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "Github Connector of Second State Reactor")
        .bearer_auth(install_token)
        .json(&param)
        .send()
        .await;
    if let Ok(r) = response {
        if r.status().is_success() {
            if let Ok(body) = r.bytes().await {
                let json_body: Value = serde_json::from_slice(&body).unwrap();
                let hook_id = json_body["id"].to_string();
                let result = serde_json::json!({
                    "revoke": format!("{}/revoke-hook?hook_id={hook_id}", SERVICE_API_PREFIX.as_str()),
                });
                return Ok(result);
            }
        } else {
            if let Ok(b) = r.text().await {
                println!("{}", b);
            }
        }
    }
    Err("Failed to create hook".to_string())
}
