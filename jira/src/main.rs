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
use serde_json::{json, Value};
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct Object {
    id: String,
    name: String,
}

#[derive(Deserialize)]
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
                    "refresh_state": encrypt(&at.refresh_token)
                })),
            )
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Deserialize, Serialize, Default)]
struct RouteItem {
    field: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct Route {
    #[serde(default = "Vec::new")]
    site: Vec<RouteItem>,

    #[serde(default = "Vec::new")]
    project: Vec<RouteItem>,

    #[serde(default = "Vec::new")]
    action: Vec<RouteItem>,
}

#[derive(Deserialize)]
struct HaikuReqBody {
    // user: String,
    state: String,
    text: Option<String>,
    cursor: Option<String>,

    #[serde(default = "Route::default")]
    routes: Route,

    #[serde(default = "Route::default")]
    forwards: Route,
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

#[derive(Deserialize)]
struct Projects {
    #[serde(rename = "maxResults")]
    max_results: u32,
    #[serde(rename = "startAt")]
    start_at: u32,
    #[serde(rename = "isLast")]
    is_last: bool,
    values: Vec<Object>,
}

async fn projects(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let site = &req
        .routes
        .site
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing site item".to_string()))?
        .value;

    HTTP_CLIENT
        .get(format!(
            "https://api.atlassian.com/ex/jira/{site}/rest/api/3/project/search"
        ))
        .query(&[("startAt", req.cursor.as_ref().unwrap_or(&"0".to_string()))])
        .bearer_auth(decrypt(&req.state))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .json::<Projects>()
        .await
        .map(|projects| {
            let list = projects
                .values
                .into_iter()
                .map(|project| RouteItem {
                    field: project.name,
                    value: project.id,
                })
                .collect::<Vec<_>>();

            Json(json!({
                "list": list,
                "cursor": (!projects.is_last)
                    .then_some((projects.max_results + projects.start_at).to_string())
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn actions() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "Create an issue",
                "value": "create",
            },
            {
                "field": "Update an issue",
                "value": "update",
            }
        ]
    }))
}

async fn post_issue(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let text = req
        .text
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?;

    let site = &req
        .forwards
        .site
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing site item".to_string()))?
        .value;

    let project = &req
        .forwards
        .project
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing project item".to_string()))?
        .value;

    match req
        .forwards
        .action
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing action".to_string()))?
        .value
        .as_str()
    {
        "create" => create_issue(&decrypt(&req.state), site, project, text)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e)),
        "update" => update_issue(&decrypt(&req.state), site, text)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((StatusCode::BAD_REQUEST, "Invalid action".to_string())),
    }
}

#[derive(Deserialize)]
struct CreateOutbound {
    transition: Option<String>,

    #[serde(flatten)]
    fields: HashMap<String, Value>,
}

async fn create_issue(
    access_token: &String,
    site: &String,
    project: &String,
    text: &String,
) -> Result<(), String> {
    let mut data = serde_json::from_str::<CreateOutbound>(&text).map_err(|e| e.to_string())?;

    data.fields.extend(
        [
            ("project".to_string(), json!({ "id": project,})),
            ("issuetype".to_string(), json!({ "id": "10001" })),
        ]
        .into_iter(),
    );

    let resp = HTTP_CLIENT
        .post(format!(
            "https://api.atlassian.com/ex/jira/{site}/rest/api/latest/issue"
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "fields": data.fields,
            "transition": data.transition.map(|t| json!({ "id": t }))
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    match resp.status().is_success() {
        true => Ok(()),
        false => Err(resp.text().await.unwrap_or_default()),
    }
}

#[derive(Deserialize)]
struct Transitions {
    transitions: Vec<Object>,
}

async fn get_transitions(
    access_token: &String,
    site: &String,
    issue_key: &String,
) -> Result<Transitions, String> {
    HTTP_CLIENT
        .get(format!(
            "https://api.atlassian.com/ex/jira/{site}/rest/api/3/issue/{issue_key}/transitions",
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Transitions>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct UpdateOutbound {
    issue_key: String,
    transition: Option<String>,

    #[serde(flatten)]
    fields: HashMap<String, Value>,
}

async fn update_issue(
    access_token: &String, site: &String, text: &String
) -> Result<(), String> {
    let mut data = serde_json::from_str::<UpdateOutbound>(&text).map_err(|e| e.to_string())?;

    let issue_url = format!(
        "https://api.atlassian.com/ex/jira/{site}/rest/api/3/issue/{}",
        data.issue_key
    );

    // Transition issue
    if let Some(transition) = data.transition {
        let id = get_transitions(&access_token, site, &data.issue_key)
            .await?
            .transitions
            .into_iter()
            .find(|trans| trans.name == transition)
            .ok_or("Invaild transition".to_string())?
            .id;

        let resp = HTTP_CLIENT
            .post(format!("{issue_url}/transitions"))
            .bearer_auth(&access_token)
            .json(&json!({ "transition": { "id": id } }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(resp.text().await.unwrap_or_default());
        }
    }

    if let Some(description) = data.fields.get_mut("description") {
        let desc = description
            .as_str()
            .ok_or("Invalid description".to_string())?;

        *description = json!({
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "text": desc,
                            "type": "text"
                        }
                    ]
                }
            ]
        });
    }
    
    let resp = HTTP_CLIENT
        .put(issue_url)
        .bearer_auth(&access_token)
        .json(&json!({ "fields": data.fields }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    match resp.status().is_success() {
        true => Ok(()),
        false => Err(resp.text().await.unwrap_or_default()),
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
        .route("/post", post(post_issue));

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
