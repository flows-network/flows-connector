use axum::{extract::Query, response::IntoResponse};
use reqwest::{header, StatusCode};

use crate::{
    fetch_github::get_access_token,
    global::{HTTP_CLIENT, REACTOR_API_PREFIX},
    models::{AuthBody, AuthState, GithubUser},
    utils::encrypt,
};

pub async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.eq("") {
        Err((StatusCode::BAD_REQUEST, "No code".to_string()))
    } else {
        match get_access_token(&auth_body.code).await {
            Ok(at) => match get_authed_user(&at.access_token).await {
                Ok(gu) => {
                    let location = format!(
                        "{}/api/connected?authorId={}&authorName={}&authorState={}",
                        REACTOR_API_PREFIX.as_str(),
                        gu.node_id,
                        gu.login,
                        encrypt(
                            &serde_json::to_string(&AuthState {
                                access_token: at.access_token,
                                installation_id: auth_body.installation_id,
                            })
                            .unwrap()
                        )
                    );
                    Ok((StatusCode::FOUND, [(header::LOCATION, location)]))
                }
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            },
            Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
        }
    }
}

pub async fn get_authed_user(access_token: &str) -> Result<GithubUser, String> {
    let response = HTTP_CLIENT
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .send()
        .await;

    match response {
        Ok(res) => {
            let body = res.json::<GithubUser>().await;
            match body {
                Ok(gu) => Ok(gu),
                Err(_) => Err("Failed to get user".to_string()),
            }
        }
        Err(_) => {
            Err("Failed to get user".to_string())
        }
    }
}
