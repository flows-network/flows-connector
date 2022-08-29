use crate::{
    fetch_github::get_repo_namewithowner,
    models::{AuthState, PostBody},
    utils::decrypt,
};

use axum::Json;
use itertools::iproduct;

use reqwest::{header, StatusCode};
use serde_json::{json, Value};

use crate::global::HTTP_CLIENT;

pub async fn post_msg(
    Json(msg_body): Json<PostBody>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    tokio::spawn(post_msg_inner(msg_body));
    Ok(StatusCode::OK)
}

pub async fn post_msg_inner(msg_body: PostBody) {
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&msg_body.state)).unwrap();
    let access_token = auth_state.access_token.to_owned();

    let fwds = msg_body.forwards;
    let msg_text = msg_body.text;

    for (repo, action) in iproduct!(fwds.repo, fwds.action) {
        let rnwo = get_repo_namewithowner(&repo.value, &access_token);
        if let Ok(repo_name) = rnwo.await {
            let req = action_req(&repo_name, &action.value, &access_token, &msg_text);
            if let Some(r) = req {
                _ = r.send().await;
            }
        }
    }
}

pub fn action_req(
    repo_name: &str,
    action: &str,
    access_token: &str,
    msg_text: &str,
) -> Option<reqwest::RequestBuilder> {
    let api_base = format!("https://api.github.com/repos/{}", repo_name);

    match action {
        "create-issue" => Some(
            HTTP_CLIENT
                .post(format!("{api_base}/issues"))
                .json(&json!({ "title": msg_text })),
        ),
        // shared by issue & pr
        "create-comment" => {
            let msg: Value = serde_json::from_str(&msg_text).unwrap();
            let issue_number = msg["issue_number"].as_u64().unwrap();
            let body = msg["body"].as_str().unwrap();
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues/{}/comments", issue_number))
                    .json(&json!({
                        "body": body,
                    })),
            )
        }
        "add-labels" => {
            let msg: Value = serde_json::from_str(&msg_text).unwrap();
            let issue_number = msg["issue_number"].as_u64().unwrap();
            let labels = msg["labels"].as_array().unwrap();
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues/{}/labels", issue_number))
                    .json(&json!({
                        "labels": labels,
                    })),
            )
        }
        "add-assignees" => {
            let msg: Value = serde_json::from_str(&msg_text).unwrap();
            let issue_number = msg["issue_number"].as_u64().unwrap();
            let assignees = msg["assignees"].as_array().unwrap();
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues/{}/assignees", issue_number))
                    .json(&json!({
                        "assignees": assignees,
                    })),
            )
        }
        _ => None,
    }
    .and_then(|r| {
        Some(
            r.header(header::ACCEPT, "application/vnd.github.v3+json")
                .header(
                    header::USER_AGENT,
                    "Github Connector of Second State Reactor",
                )
                .bearer_auth(access_token),
        )
    })
}
