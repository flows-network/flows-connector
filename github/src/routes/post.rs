use crate::{
    fetch_github::get_repo_namewithowner,
    models::{AuthState, PostBody},
    utils::decrypt,
};

use axum::Json;
use itertools::iproduct;

use reqwest::{header, StatusCode};
use serde_json::Value;

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
        post_action(&repo.value, &action.value, &access_token, &msg_text).await;
    }
}

pub async fn post_action(node_id: &str, action: &str, access_token: &str, msg_text: &str) {
    if let Ok(ref repo_name) = get_repo_namewithowner(node_id, access_token).await {
        let rb = post_meg_inner(repo_name, msg_text, access_token, action).await;

        if let Some(r) = rb {
            _ = r.send().await
        }
    }
}

async fn post_meg_inner(
    repo_name: &str,
    msg_text: &str,
    access_token: &str,
    action: &str,
) -> Option<reqwest::RequestBuilder> {
    let api_base = format!("https://api.github.com/repos/{}", repo_name);
    match action {
        "merge-pull" => {
            let msg: Value = serde_json::from_str(msg_text).unwrap();
            let pull_number = msg["pull_number"].as_u64().unwrap();
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/pulls/{pull_number}/merge"))
                    .header(header::CONTENT_TYPE, "application/vnd.github+json"),
            )
        }
        "create-issue" => {
            // The outbound data and format are the same as the GitHub API, so pass them directly here
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(msg_text.to_string()),
            )
        }
        // shared by issue & pr
        "create-comment" => {
            let msg: Value = serde_json::from_str(msg_text).unwrap();
            let issue_number = msg["issue_number"].as_u64().unwrap();
            let body = msg["body"].as_str().unwrap();
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues/{issue_number}/comments"))
                    .json(&serde_json::json!({
                        "body": body,
                    })),
            )
        }
        "add-labels" => {
            let msg: Value = serde_json::from_str(msg_text).unwrap();
            let issue_number = msg["issue_number"].as_u64().unwrap();
            let labels = msg["labels"].as_array().unwrap();
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues/{}/labels", issue_number))
                    .json(&serde_json::json!({
                        "labels": labels,
                    })),
            )
        }
        "add-assignees" => {
            let msg: Value = serde_json::from_str(msg_text).unwrap();
            let issue_number = msg["issue_number"].as_u64().unwrap();
            let assignees = msg["assignees"].as_array().unwrap();
            Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues/{}/assignees", issue_number))
                    .json(&serde_json::json!({
                        "assignees": assignees,
                    })),
            )
        }
        _ => None,
    }
    .map(|r| {
        r.header(header::ACCEPT, "application/vnd.github.v3+json")
            .header(
                header::USER_AGENT,
                "Github Connector of Second State Reactor",
            )
            .bearer_auth(access_token)
    })
}
