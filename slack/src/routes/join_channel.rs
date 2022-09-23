use crate::models::ChannelInfo;
use crate::{global::HTTP_CLIENT, models::Channel};
use axum::{response::IntoResponse, Json};
use reqwest::StatusCode;
use serde_json::Value;

use crate::{models::JoinChannelReq, utils::decrypt};

pub async fn join_channel(Json(req): Json<JoinChannelReq>) -> impl IntoResponse {
    let access_token = decrypt(req.state.as_str());

    for chr in req.routes.channels {
        match view_channel(&access_token, &chr.value).await {
            Some(ch) => {
                if ch.is_channel.is_some()
                    && ch.is_channel.unwrap()
                    && (ch.is_member.is_some() && !ch.is_member.unwrap())
                {
                    if let Err(err_msg) = join_channel_inner(&chr.value, &access_token).await {
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg));
                    }
                }
            }
            None => {
                return Err((StatusCode::BAD_REQUEST, "Channel not found".to_string()));
            }
        };
    }
    Ok((StatusCode::OK, Json(())))
}

async fn join_channel_inner(channel: &str, access_token: &str) -> Result<(), String> {
    let param = serde_json::json!({ "channel": channel });
    let response = HTTP_CLIENT
        .post("https://slack.com/api/conversations.join".to_string())
        .bearer_auth(access_token)
        .json(&param)
        .send()
        .await;
    if let Ok(r) = response {
        if r.status().is_success() {
            if let Ok(body) = r.bytes().await {
                let json_body: Value = serde_json::from_slice(&body).unwrap();
                if let Some(ok) = json_body["ok"].as_bool() {
                    if ok {
                        return Ok(());
                    }
                }
            }
        }
    }
    Err("Failed to create hook".to_string())
}

async fn view_channel(access_token: &str, channel: &str) -> Option<Channel> {
    let response = HTTP_CLIENT
        .get(format!(
            "https://slack.com/api/conversations.info?channel={}",
            channel
        ))
        .bearer_auth(access_token)
        .send()
        .await;
    if let Ok(r) = response {
        if let Ok(ci) = r.json::<ChannelInfo>().await {
            if ci.ok {
                return ci.channel;
            }
        }
    }
    None
}
