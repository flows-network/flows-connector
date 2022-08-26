use axum::{response::IntoResponse, Json};
use reqwest::StatusCode;
use serde_json::Value;

use crate::{
    fetch_github::{get_installation_token, get_installed_repositories},
    global::REPOS_PER_PAGE,
    models::{AuthState, RouteReq},
    utils::decrypt,
};

pub async fn repos(Json(body): Json<RouteReq>) -> impl IntoResponse {
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&body.state)).unwrap();
    match get_installation_token(auth_state.installation_id).await {
        Ok(install_token) => {
            let page = body.cursor.unwrap_or_else(|| "1".to_string());
            if let Ok(page) = page.parse::<u32>() {
                match get_installed_repositories(&install_token, page).await {
                    Ok(irs) => {
                        let rs: Vec<Value> = irs
                            .repositories
                            .iter()
                            .map(|ir| {
                                serde_json::json!({
                                    "field": ir.full_name,
                                    "value": ir.node_id
                                })
                            })
                            .collect();
                        let result = match irs.total_count > page * REPOS_PER_PAGE {
                            true => {
                                serde_json::json!({
                                    "next_cursor": page + 1,
                                    "list": rs
                                })
                            }
                            false => {
                                serde_json::json!({ "list": rs })
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
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}
