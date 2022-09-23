use axum::{response::IntoResponse, Json};
use reqwest::StatusCode;

use crate::{models::EventBody, utils::post_event_to_reactor};

pub async fn capture_event(Json(evt_body): Json<EventBody>) -> impl IntoResponse {
    if let Some(challenge) = evt_body.challenge {
        return (StatusCode::OK, challenge);
    }

    if let Some(evt) = evt_body.event {
        match evt.typ.as_str() {
            "message" => {
                // Only handle message which is sent by user
                if evt.bot_id.is_none() {
                    let user = evt.user.unwrap_or_default();
                    let text = evt.text.unwrap_or_default();
                    let files = evt.files.unwrap_or_default();
                    let channel = evt.channel.unwrap_or_default();
                    tokio::spawn(post_event_to_reactor(
                        user,
                        text,
                        files,
                        channel,
                        "message".to_string(),
                    ));
                }
            }
            "member_joined_channel" => {
                let user = evt.user.unwrap_or_default();
                let channel = evt.channel.unwrap_or_default();
                tokio::spawn(post_event_to_reactor(
                    user.clone(),
                    user,
                    vec![],
                    channel,
                    "member_joined_channel".to_string(),
                ));
            }
            _ => {}
        };
    }

    (StatusCode::OK, String::new())
}
