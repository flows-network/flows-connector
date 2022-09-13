use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::header;
use serde_json::{json, Value};

use crate::{
    global::{
        GITHUB_APP_ID, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_PRIVATE_KEY, HTTP_CLIENT,
        REPOS_PER_PAGE,
    },
    models::{AccessTokenBody, GithubUser, InstallationTokenBody, InstalledRepos},
    utils::get_now,
};

pub async fn get_repo_namewithowner(node_id: &str, access_token: &str) -> Result<String, String> {
    // use GraphQL to query the repo's nameWithOwner
    let query = format!(
        r#"{{"query":"query {{\n  node(id:\"{}\") {{\n   ... on Repository {{\n       nameWithOwner\n    }}\n  }}\n}}"}}"#,
        node_id
    );
    let response = HTTP_CLIENT
        .post("https://api.github.com/graphql")
        .header(header::ACCEPT, "application/vnd.github.v3+json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .bearer_auth(access_token)
        .json(&serde_json::from_str::<Value>(&query).unwrap())
        .send()
        .await;
    if let Ok(r) = response {
        if r.status().is_success() {
            if let Ok(b) = serde_json::from_str::<Value>(&r.text().await.unwrap()) {
                if let Some(name) = b["data"]["node"]["nameWithOwner"].as_str() {
                    return Ok(String::from(name));
                }
            }
        } else {
            println!("{:?}", r.text().await);
        }
    }
    Err("Repository not found".to_string())
}

pub async fn get_access_token(code: &str) -> Result<AccessTokenBody, String> {
    let params = [
        ("client_id", GITHUB_CLIENT_ID.as_ref()),
        ("client_secret", GITHUB_CLIENT_SECRET.as_ref()),
        ("code", code),
    ];

    let response = HTTP_CLIENT
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .form(&params)
        .send()
        .await;
    match response {
        Ok(r) => {
            let token_body = r.json::<AccessTokenBody>().await;
            match token_body {
                Ok(at) => Ok(at),
                Err(_) => Err("Failed to get access token".to_string()),
            }
        }
        Err(_) => Err("Failed to get access token".to_string()),
    }
}

pub async fn get_installation_token(installation_id: u64) -> Result<String, String> {
    let now = get_now();
    let jwt_payload = json!({
        "iat": now - 60,
        "exp": now + 10 * 60,
        "iss": GITHUB_APP_ID.as_ref() as &str,
    });
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &jwt_payload,
        &EncodingKey::from_rsa_pem(GITHUB_PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap();

    let response = HTTP_CLIENT
        .post(format!(
            "https://api.github.com/app/installations/{installation_id}/access_tokens"
        ))
        .header(header::ACCEPT, "application/vnd.github.v3+json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .bearer_auth(jwt)
        .send()
        .await;
    match response {
        Ok(r) => {
            let token_body = r.json::<InstallationTokenBody>().await;
            match token_body {
                Ok(at) => Ok(at.token),
                Err(_) => Err("Failed to get installation token".to_string()),
            }
        }
        Err(_) => Err("Failed to get installation token".to_string()),
    }
}

pub async fn get_installed_repositories(
    install_token: &str,
    page: u32,
) -> Result<InstalledRepos, String> {
    let response = HTTP_CLIENT
        .get(format!(
            "https://api.github.com/installation/repositories?per_page={}&page={}",
            REPOS_PER_PAGE, page
        ))
        .header(header::ACCEPT, "application/vnd.github.v3+json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .bearer_auth(install_token)
        .send()
        .await;
    match response {
        Ok(r) => match r.json::<InstalledRepos>().await {
            Ok(repos) => Ok(repos),
            Err(_) => Err("Failed to get installed repositories".to_string()),
        },
        Err(_) => Err("Failed to get installed repositories".to_string()),
    }
}

pub async fn get_github_user(api_url: &str, access_token: &str) -> Result<GithubUser, ()> {
    let response = HTTP_CLIENT
        .get(api_url)
        .bearer_auth(access_token)
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .send()
        .await;

    if let Ok(res) = response {
        if let Ok(gu) = res.json::<GithubUser>().await {
            return Ok(gu);
        }
    }
    Err(())
}
