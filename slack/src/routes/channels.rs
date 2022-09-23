use crate::global::CHANNELS_PER_PAGE;
use crate::global::HTTP_CLIENT;
use crate::models::Channels;
use crate::models::MaybeChannels;
use crate::models::RouteReq;
use axum::{response::IntoResponse, Json};
use reqwest::StatusCode;
use serde_json::Value;

use crate::utils::decrypt;

pub async fn route_channels(Json(body): Json<RouteReq>) -> impl IntoResponse {
    let access_token = decrypt(body.state.as_str());
    let cursor = body.cursor.unwrap_or_default();
    match get_channels(&access_token, cursor).await {
        Ok(mut chs) => {
            let rs: Vec<Value> = chs
				.channels
				.iter_mut()
				.filter_map(|ch| {
					if ch.is_channel.is_some() && ch.is_channel.unwrap() {
						return Some(serde_json::json!({
							"field": format!("# {}", ch.name.take().unwrap_or_else(|| "no name".to_string())),
							"value": ch.id
						}));
					} else if ch.is_im.is_some()
						&& ch.is_im.unwrap() && ch.user.is_some()
						&& ch.user.take().unwrap().eq(&body.user)
					{
						return Some(serde_json::json!({
							"field": "Direct Message with App",
							"value": ch.id
						}));
					}
					None
				})
				.collect();
            let result = match chs.response_metadata.next_cursor.as_str() {
                "" => {
                    serde_json::json!({ "list": rs })
                }
                s => {
                    serde_json::json!({
                        "next_cursor": s,
                        "list": rs
                    })
                }
            };
            Ok(Json(result))
        }
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

async fn get_channels(access_token: &str, cursor: String) -> Result<Channels, String> {
    let response = HTTP_CLIENT
		.get(format!("https://slack.com/api/conversations.list?limit={}&cursor={}&types=public_channel,private_channel,im", CHANNELS_PER_PAGE, cursor))
		.bearer_auth(access_token)
		.send()
		.await;
    match response {
        Ok(r) => {
            if let Ok(maybe) = r.json::<MaybeChannels>().await {
                match maybe {
                    MaybeChannels::Channels(chs) => {
                        if chs.ok {
                            return Ok(chs);
                        }
                    }
                    MaybeChannels::Failure(f) => {
                        // removed: account_inactive
                        // re-installed: invalid_auth
                        if f.error == "account_inactive" || f.error == "invalid_auth" {
                            return Err(
                                "The account is expired. Please authenticate your account again."
                                    .to_string(),
                            );
                        };
                    }
                }
            }
        }
        Err(e) => {
            dbg!(e);
        }
    }
    Err("Failed to get channels".to_string())
}
