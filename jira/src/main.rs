use axum::{
    extract::{Json, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptTrait};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use std::{collections::HashMap, env};
use std::{collections::HashSet, net::SocketAddr};

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    // static ref HAIKU_AUTH_TOKEN: String =
    //     env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
    static ref JIRA_APP_CLIENT_ID: String =
        env::var("JIRA_APP_CLIENT_ID").expect("Env variable JIRA_APP_CLIENT_ID not set");
    static ref JIRA_APP_CLIENT_SECRET: String =
        env::var("JIRA_APP_CLIENT_SECRET").expect("Env variable JIRA_APP_CLIENT_SECRET not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    static ref CRYPT: MagicCrypt256 = new_magic_crypt!(
        env::var("RSA_RAND_SEED").expect("Env variable RSA_RAND_SEED not set").as_str(),
        256
    );

    static ref REDIRECT_URL: String = format!("{}/auth", &*SERVICE_API_PREFIX);
    static ref SCOPES: &'static str = "read:me read:jira-work write:jira-work offline_access";
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}

fn encrypt<S: AsRef<str>>(data: S) -> String {
    CRYPT.encrypt_str_to_base64(data)
}

fn decrypt<S: AsRef<str>>(data: S) -> String {
    CRYPT
        .decrypt_base64_to_string(data)
        .map_err(|e| println!("decrypt failed: {}", e.to_string()))
        .unwrap_or_default()
}

async fn connect() -> impl IntoResponse {
    let location = format!(
        "https://auth.atlassian.com/authorize?client_id={}&redirect_uri={}&scope={}&audience=api.atlassian.com&response_type=code&prompt=consent",
        &*JIRA_APP_CLIENT_ID,
        urlencoding::encode(&*REDIRECT_URL),
        urlencoding::encode(&*SCOPES)
    );
    (StatusCode::FOUND, [(header::LOCATION, location)])
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
    code: String,
}

async fn auth(req: Query<AuthBody>) -> impl IntoResponse {
    let at = get_access_token(AuthMode::Code(req.code.to_owned()))
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    get_authed_user(&at.access_token)
        .await
        .map(|user| {
            let location = format!(
                "{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
                HAIKU_API_PREFIX.as_str(),
                user.account_id,
                format!("{} ({})", user.nickname, user.email),
                urlencoding::encode(&encrypt(&at.access_token)),
                urlencoding::encode(&encrypt(&at.refresh_token))
            );

            (StatusCode::FOUND, [(header::LOCATION, location)])
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Debug, Serialize, Deserialize)]
struct Object {
    id: String,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct AccessToken {
    access_token: String,
    refresh_token: String,
}

enum AuthMode {
    Code(String),
    Refresh(String),
}

async fn get_access_token(auth_type: AuthMode) -> Result<AccessToken, String> {
    let params = match auth_type {
        AuthMode::Code(code) => [
            ("client_id", JIRA_APP_CLIENT_ID.to_string()),
            ("client_secret", JIRA_APP_CLIENT_SECRET.to_string()),
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("redirect_uri", REDIRECT_URL.to_string()),
        ]
        .into_iter()
        .collect::<HashMap<&str, String>>(),

        AuthMode::Refresh(refresh) => [
            ("client_id", JIRA_APP_CLIENT_ID.to_string()),
            ("client_secret", JIRA_APP_CLIENT_SECRET.to_string()),
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh),
        ]
        .into_iter()
        .collect::<HashMap<&str, String>>(),
    };

    HTTP_CLIENT
        .post("https://auth.atlassian.com/oauth/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<AccessToken>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct User {
    account_id: String,
    nickname: String,
    email: String,
}

async fn get_authed_user(access_token: &str) -> Result<User, String> {
    HTTP_CLIENT
        .get("https://api.atlassian.com/me")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<User>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct RefreshState {
    refresh_state: String,
}

async fn refresh(req: Json<RefreshState>) -> impl IntoResponse {
    get_access_token(AuthMode::Refresh(decrypt(&req.refresh_state)))
        .await
        .map(|at| {
            (
                StatusCode::OK,
                Json(json!({
                    "access_state": encrypt(&at.access_token),
                    "refresh_state": req.refresh_state
                })),
            )
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct RouteItem {
    field: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ForwardRoute {
    site: Vec<RouteItem>,

    #[serde(default = "Vec::new")]
    project: Vec<RouteItem>,
}

#[derive(Deserialize, Serialize)]
struct HaikuReqBody {
    user: String,
    state: String,
    text: Option<String>,
    routes: Option<ForwardRoute>,
    forwards: Option<ForwardRoute>,
}

#[derive(Deserialize)]
struct Site {
    id: String,
    name: String,
    scopes: HashSet<String>,
}

async fn sites(req: Json<HaikuReqBody>) -> impl IntoResponse {
    HTTP_CLIENT
        .get("https://api.atlassian.com/oauth/token/accessible-resources")
        .bearer_auth(decrypt(&req.state))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .json::<Vec<Site>>()
        .await
        .map(|sites| {
            let list = sites
                .into_iter()
                .filter_map(|site| {
                    site.scopes
                        .contains("write:jira-work")
                        .then_some(RouteItem {
                            field: site.name,
                            value: site.id,
                        })
                })
                .collect::<Vec<_>>();

            Json(json!({ "list": list }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn projects(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let site = &req
        .routes
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing routes".to_string()))?
        .site
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing site item".to_string()))?
        .value;

    HTTP_CLIENT
        .get(format!(
            "https://api.atlassian.com/ex/jira/{site}/rest/api/latest/project"
        ))
        .bearer_auth(decrypt(&req.state))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .json::<Vec<Object>>()
        .await
        .map(|projects| {
            let list = projects
                .into_iter()
                .map(|project| RouteItem {
                    field: project.name,
                    value: project.id,
                })
                .collect::<Vec<_>>();

            Json(json!({ "list": list }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn actions() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "Create an issue",
                "value": "create_issue",
            }
        ]
    }))
}

async fn post_item(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let text = req
        .text
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?;

    let forwards = req
        .forwards
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing forwards".to_string()))?;

    let site = &forwards
        .site
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing site item".to_string()))?
        .value;

    let project = &forwards
        .project
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing project item".to_string()))?
        .value;

    let resp = HTTP_CLIENT
        .post(format!(
            "https://api.atlassian.com/ex/jira/{site}/rest/api/latest/issue"
        ))
        .bearer_auth(decrypt(&req.state))
        .json(&json!({
            "fields": {
                "project": {
                   "id": project
                },
                "summary": text,
                //"description": "",
                "issuetype": {
                   "id": "10001"
                }
            }
        }))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match resp.status().is_success() {
        true => Ok(StatusCode::OK),
        false => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.text().await.unwrap_or_default(),
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", get(auth))
        .route("/refresh", post(refresh))
        .route("/sites", post(sites))
        .route("/projects", post(projects))
        .route("/actions", post(actions))
        .route("/post", post(post_item));

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
