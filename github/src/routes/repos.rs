use axum::{response::IntoResponse, Json};
use reqwest::StatusCode;
use serde_json::Value;

use crate::{
    fetch_github::get_installed_repos,
    global::REPOS_PER_PAGE,
    models::{AuthState, RouteReq},
    utils::decrypt,
};

pub async fn repos(Json(body): Json<RouteReq>) -> impl IntoResponse {
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&body.state)).unwrap();

    // omg...
    let routes = body.routes.unwrap();
    let installations = routes.installation.unwrap();
    let installation_id = &installations.first().unwrap().value;

    let page = body.cursor.unwrap_or_else(|| "1".to_string());

    if let Ok(page) = page.parse::<u32>() {
        match get_installed_repos(&auth_state.access_token, installation_id, page).await {
            Ok(irs) => {
                let mut disabled_count = 0;
                let rs: Vec<Value> = irs
                    .repositories
                    .iter()
                    .map(|ir| {
                        if !ir.permissions.admin {
                            disabled_count = disabled_count + 1;
                        }
                        serde_json::json!({
                            "field": ir.full_name,
                            "value": ir.node_id,
                            "disabled": !ir.permissions.admin
                        })
                    })
                    .collect();
                let message = match disabled_count {
                    0 => "",
                    _ => {
                        "Some Repos are disabled since you don't have permission to manage Webhooks"
                    }
                };

                let result = match irs.total_count > page * REPOS_PER_PAGE {
                    true => {
                        serde_json::json!({
                            "next_cursor": page + 1,
                            "message": message,
                            "list": rs
                        })
                    }
                    false => {
                        serde_json::json!({
                            "message": message,
                            "list": rs
                        })
                    }
                };
                Ok(Json(result))
            }
            Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
        }
    } else {
        Err((StatusCode::BAD_REQUEST, "Invalid cursor".to_string()))
    }
}
