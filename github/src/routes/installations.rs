use axum::{response::IntoResponse, Json};

use serde_json::Value;

use crate::{
    fetch_github::get_installations,
    models::{AuthState, RouteReq},
    utils::decrypt,
};

pub async fn installations(Json(body): Json<RouteReq>) -> impl IntoResponse {
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&body.state)).unwrap();

    let ins = get_installations(&auth_state.access_token).await;

    ins.map(|i| {
        serde_json::json!({ "list": i
            .installations
            .iter()
            .map(|ri| {
                serde_json::json!({
                    "field": ri.account.login,
                    "value": ri.id.to_string(),
                })
            })
            .collect::<Vec<Value>>()
        })
        .to_string()
    })
}
