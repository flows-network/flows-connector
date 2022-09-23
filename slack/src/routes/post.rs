use axum::{
    extract::{ContentLengthLimit, Multipart},
    response::IntoResponse,
    Json,
};
use reqwest::{multipart, StatusCode};
use serde_json::Value;

use crate::{
    global::HTTP_CLIENT,
    models::{ActionValue, ForwardRoutes, PostBody},
    utils::decrypt,
};

// post_msg {{{

pub async fn post_msg(
    Json(msg_body): Json<PostBody>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let action = msg_body.forwards.action.get(0).unwrap();
    match action.value {
        ActionValue::SendMessage => {
            tokio::spawn(async move {
                for ch in msg_body.forwards.channels.iter() {
                    let request = serde_json::json!({
                        "channel": ch.value,
                        "text": msg_body.text,
                    });

                    tokio::spawn(
                        HTTP_CLIENT
                            .post("https://slack.com/api/chat.postMessage")
                            .bearer_auth(decrypt(msg_body.state.as_str()))
                            .json(&request)
                            .send(),
                    );
                }
            });
        }
        ActionValue::SendDM => {
            tokio::spawn(async move {
                let value: Value = serde_json::from_str(&msg_body.text).unwrap();
                let text = value.get("text").unwrap();
                let user = value.get("user").unwrap();
                let request = serde_json::json!({
                    "channel": user,
                    "text": text,
                });

                _ = tokio::spawn(
                    HTTP_CLIENT
                        .post("https://slack.com/api/chat.postMessage")
                        .bearer_auth(decrypt(msg_body.state.as_str()))
                        .json(&request)
                        .send(),
                );
            });
        }
    }

    Ok(StatusCode::OK)
}

// }}}

// upload_msg {{{

pub async fn upload_msg(
    ContentLengthLimit(mut multipart): ContentLengthLimit<
        Multipart,
        {
            10 * 1024 * 1024 /* 250mb */
        },
    >,
) -> impl IntoResponse {
    tokio::spawn(async move {
        let mut user = String::new();
        let mut text = String::new();
        let mut state = String::new();
        let mut forwards = None;

        let mut parts = Vec::new();
        while let Some(field) = multipart.next_field().await.unwrap() {
            let name = field.name().unwrap().to_string();
            match name.as_str() {
                "file" => {
                    let file_name = field.file_name().unwrap().to_string();
                    let content_type = field.content_type().unwrap().to_string();
                    let data = field.bytes().await.unwrap();
                    if let Ok(part) = multipart::Part::bytes(data.to_vec())
                        .file_name(file_name)
                        .mime_str(&content_type)
                    {
                        parts.push(part);
                    }
                }
                "user" => {
                    if let Ok(u) = field.text().await {
                        user = u;
                    }
                }
                "state" => {
                    if let Ok(s) = field.text().await {
                        state = s;
                    }
                }
                "text" => {
                    if let Ok(t) = field.text().await {
                        text = t;
                    }
                }
                "forwards" => {
                    if let Ok(f) = field.text().await {
                        if let Ok(fws) = serde_json::from_str::<ForwardRoutes>(&f) {
                            forwards = Some(fws);
                        }
                    }
                }
                _ => {}
            }
        }

        if user.is_empty() || state.is_empty() {
            return;
        }

        if !parts.is_empty() {
            for part in parts.into_iter() {
                let mut form = multipart::Form::new().text("channels", user.clone());
                form = form.part("file", part);
                upload_file_to_slack(form, state.clone()).await;
            }
        }

        if !text.is_empty() {
            if let Some(fwds) = forwards {
                tokio::spawn(post_msg(Json::from(PostBody {
                    user,
                    state,
                    text,
                    forwards: fwds,
                })));
            }
        }
    });

    StatusCode::OK
}

async fn upload_file_to_slack(form: multipart::Form, access_token: String) {
    let response = HTTP_CLIENT
        .post("https://slack.com/api/files.upload")
        .bearer_auth(decrypt(access_token.as_str()))
        .multipart(form)
        .send()
        .await;
    if let Ok(res) = response {
        if res.status().is_success() {
            // println!("{:?}", res.text().await);
        }
    }
}

// }}}
