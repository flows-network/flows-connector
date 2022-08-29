use axum::{response::IntoResponse, Form, TypedHeader};
use reqwest::{header, StatusCode};
use serde_json::Value;

use crate::{
    fetch_github::get_github_user,
    global::{HTTP_CLIENT, REACTOR_API_PREFIX, REACTOR_AUTH_TOKEN},
    models::{AuthState, Event, GithubEvent},
    utils::decrypt,
};

pub async fn capture_event(
    Form(event): Form<Event>,
    TypedHeader(ge): TypedHeader<GithubEvent>,
) -> impl IntoResponse {
    tokio::spawn(capture_event_inner(event, ge));
    (StatusCode::OK, String::new())
}

pub async fn capture_event_inner(event: Event, ge: GithubEvent) {
    if let Ok(auth_state) = get_author_token_from_reactor(&event.connector).await {
        let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
        let auth_state = serde_json::from_str::<AuthState>(&auth_state).unwrap();
        if let Ok(github_user) = get_github_user(
            payload["sender"]["url"].as_str().unwrap(),
            &auth_state.access_token,
        )
        .await
        {
            if let Some(email) = github_user.email {
                // Because email is fetched by payload["sender"]["url"]
                // so payload["sender"] must be an object
                let sender = payload["sender"].as_object_mut().unwrap();
                sender.insert("email".to_string(), email.into());
            }
            let triggers = serde_json::json!({
                "event": ge.0,
                "repo": payload["repository"]["node_id"].as_str().unwrap(),
            });

            post_event_to_reactor(
                &event.connector,
                &event.flow,
                &payload.to_string(),
                triggers,
            )
            .await;
        }
    }
}

async fn get_author_token_from_reactor(user: &str) -> Result<String, ()> {
    let request = serde_json::json!({ "author": user });

    let response = HTTP_CLIENT
        .post(format!(
            "{}/api/_funcs/_author_state",
            REACTOR_API_PREFIX.as_str()
        ))
        .header(header::AUTHORIZATION, REACTOR_AUTH_TOKEN.as_str())
        .json(&request)
        .send()
        .await;

    if let Ok(res) = response {
        if res.status().is_success() {
            if let Ok(body) = res.text().await {
                return Ok(decrypt(&body));
            }
        }
    }
    Err(())
}

async fn post_event_to_reactor(user: &str, flow: &str, text: &str, triggers: Value) {
    let request = serde_json::json!({
        "user": user,
        "flow": flow,
        "text": text,
        "triggers": triggers,
    });

    let response = HTTP_CLIENT
        .post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
        .header(header::AUTHORIZATION, REACTOR_AUTH_TOKEN.as_str())
        .json(&request)
        .send()
        .await;
    if let Err(e) = response {
        println!("{:?}", e);
    }
}
