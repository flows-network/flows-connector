use axum::{extract::Query, response::IntoResponse};
use reqwest::StatusCode;
use serde_json::Value;
use urlencoding::encode;

use crate::{
    global::{HTTP_CLIENT, REACTOR_API_PREFIX, SLACK_CLIENT_ID, SLACK_CLIENT_SECRET},
    models::{AuthBody, OAuthAccessBody},
    utils::encrypt,
};

pub async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.eq("") {
        Err((StatusCode::BAD_REQUEST, "No code".to_string()))
    } else {
        match get_access_token(&auth_body.code).await {
            Ok(at) => {
                if at.ok {
                    let authed_user = at.authed_user.unwrap();
                    match get_authed_user(&authed_user.access_token).await {
                        Ok(gu) => {
                            let workspace = get_workspace(&authed_user.access_token).await?;
                            let location = format!(
                                "{}/api/connected?authorId={}&authorName={}&authorState={}",
                                REACTOR_API_PREFIX.as_str(),
                                authed_user.id,
                                encode(format!("{}({})", gu.as_str(), workspace).as_str()),
                                encrypt(at.access_token.unwrap().as_str())
                            );
                            Ok((StatusCode::FOUND, [("Location", location)]))
                        }
                        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
                    }
                } else {
                    Err((StatusCode::BAD_REQUEST, "Invalid code".to_string()))
                }
            }
            Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
        }
    }
}

async fn get_workspace(access_token: &str) -> Result<String, (StatusCode, String)> {
    let response = HTTP_CLIENT
        .post("https://slack.com/api/auth.test")
        .bearer_auth(access_token)
        .send()
        .await;

    match response {
        Ok(r) => {
            let data: Value = r.json().await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get workspace (parse json)".to_string(),
                )
            })?;
            let ok = data.get("ok").unwrap_or(&Value::Bool(false));
            if ok.as_bool().ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get workspace (parse ok)".to_string(),
            ))? {
                let url = data.get("url").unwrap().as_str().ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get workspace (parse url)".to_string(),
                ))?;
                let workspace = url.chars().skip(8).take_while(|&c| c != '.').collect();
                Ok(workspace)
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get workspace (slack denied)".to_string(),
                ))
            }
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get workspace (network)".to_string(),
        )),
    }
}

async fn get_access_token(code: &str) -> Result<OAuthAccessBody, String> {
    let params = [
        ("client_id", SLACK_CLIENT_ID.as_str()),
        ("client_secret", SLACK_CLIENT_SECRET.as_str()),
        ("code", code),
    ];

    let response = HTTP_CLIENT
        .post("https://slack.com/api/oauth.v2.access")
        .form(&params)
        .send()
        .await;
    match response {
        Ok(r) => {
            let oauth_body = r.json::<OAuthAccessBody>().await;
            match oauth_body {
                Ok(at) => Ok(at),
                Err(_) => Err("Failed to get access token".to_string()),
            }
        }
        Err(_) => Err("Failed to get access token".to_string()),
    }
}

async fn get_authed_user(access_token: &str) -> Result<String, String> {
    let response = HTTP_CLIENT
        .get("https://slack.com/api/users.profile.get")
        .bearer_auth(access_token)
        .send()
        .await;

    match response {
        Ok(res) => match res.text().await {
            Ok(body) => serde_json::from_str::<Value>(&body)
                .map(|v| v["profile"]["real_name"].as_str().unwrap().to_string())
                .map_err(|_| "Failed to get user's name".to_string()),
            Err(_) => Err("Failed to get user's profile".to_string()),
        },
        Err(_) => Err("Failed to get user's profile".to_string()),
    }
}
