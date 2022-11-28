use crate::{
    fetch_github::get_repo_namewithowner,
    models::{AuthState, PostBody},
    utils::decrypt,
};

use axum::Json;
use itertools::iproduct;

use codegen::reqs_gen;

use reqwest::{header, Client, RequestBuilder, StatusCode};
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
            _ = r.send().await;
        }
    }
}

async fn post_meg_inner(
    repo_name: &str,
    msg_text: &str,
    access_token: &str,
    action: &str,
) -> Option<reqwest::RequestBuilder> {
    let mut msg: Value = serde_json::from_str(msg_text).unwrap();

    let mut rn = repo_name.split('/');
    let name = rn.next().unwrap().to_string();
    let repo = rn.next().unwrap().to_string();

    let injection = serde_json::json!({
        "repo": repo,
        "owner": name,
    });

    merge(&mut msg, &injection);

    build_builder(&*HTTP_CLIENT, action, msg).map(|r| {
        r.header(header::ACCEPT, "application/vnd.github.v3+json")
            .header(
                header::USER_AGENT,
                "Github Connector of Second State Reactor",
            )
            .bearer_auth(access_token)
    })
}

#[reqs_gen("./github/codegen/openapi/api.github.com.json")]
fn build_builder(client: &Client, action: &str, msg: serde_json::Value) -> Option<RequestBuilder> {}

fn merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (&mut Value::Object(ref mut a), &Value::Object(ref b)) => {
            for (k, v) in b {
                merge(a.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (a, b) => {
            *a = b.clone();
        }
    }
}
