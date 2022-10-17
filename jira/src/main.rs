use axum::{
    extract::{Json, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use lazy_static::lazy_static;
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptTrait};
use reqwest::{Client, ClientBuilder, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, env};
use std::{collections::HashSet, net::SocketAddr};
use std::{fmt::Display, time::Duration};

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    static ref HAIKU_AUTH_TOKEN: String =
        env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
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
    static ref SCOPES: &'static str =
        "read:me read:jira-work write:jira-work manage:jira-webhook read:comment:jira read:issue-details:jira offline_access";
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

fn jira_api<A: Display, S: Display>(method: Method, site: S, api: A) -> RequestBuilder {
    HTTP_CLIENT.request(
        method,
        format!("https://api.atlassian.com/ex/jira/{site}/{api}"),
    )
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

#[derive(Deserialize, Serialize, Default, Debug)]
struct RouteItem {
    field: String,
    value: String,
}

#[derive(Deserialize, Default, Debug)]
struct Routes {
    #[serde(default = "Vec::new")]
    site: Vec<RouteItem>,

    #[serde(default = "Vec::new")]
    project: Vec<RouteItem>,

    #[serde(default = "Vec::new")]
    action: Vec<RouteItem>,
}

#[derive(Deserialize, Debug)]
struct HaikuReqBody {
    // user: String,
    state: String,
    text: Option<String>,
    cursor: Option<String>,

    #[serde(default = "Routes::default")]
    routes: Routes,

    #[serde(default = "Routes::default")]
    forwards: Routes,
}

#[derive(Deserialize)]
struct Site {
    id: String,
    url: String,
    name: String,
    scopes: HashSet<String>,
}

async fn get_sites<A: AsRef<str>>(access_token: A) -> Result<Vec<Site>, String> {
    HTTP_CLIENT
        .get("https://api.atlassian.com/oauth/token/accessible-resources")
        .bearer_auth(access_token.as_ref())
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Vec<Site>>()
        .await
        .map_err(|e| format!("get sites failed: {}", e.to_string()))
}

async fn sites(req: Json<HaikuReqBody>) -> impl IntoResponse {
    get_sites(decrypt(&req.state))
        .await
        .map(|sites| {
            let list = sites
                .into_iter()
                .filter_map(|site| {
                    (site.scopes.contains("write:jira-work")
                        && site.scopes.contains("read:jira-work"))
                    .then_some(RouteItem {
                        field: site.name,
                        value: site.id,
                    })
                })
                .collect::<Vec<_>>();

            Json(json!({ "list": list }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
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

    jira_api(Method::GET, site, "/rest/api/3/project/search")
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

async fn create_issue(
    access_token: &String,
    site: &String,
    project: &String,
    text: &String,
) -> Result<(), String> {
    let mut fields =
        serde_json::from_str::<HashMap<String, Value>>(&text).map_err(|e| e.to_string())?;

    fields.extend(
        [
            ("project".to_string(), json!({ "id": project,})),
            ("issuetype".to_string(), json!({ "id": "10001" })),
        ]
        .into_iter(),
    );

    let resp = jira_api(Method::POST, site, "/rest/api/latest/issue")
        .bearer_auth(&access_token)
        .json(&json!({ "fields": fields }))
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
    jira_api(
        Method::GET,
        site,
        format!("/rest/api/3/issue/{issue_key}/transitions"),
    )
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

async fn update_issue(access_token: &String, site: &String, text: &String) -> Result<(), String> {
    let mut data = serde_json::from_str::<UpdateOutbound>(&text).map_err(|e| e.to_string())?;

    // Transition issue
    if let Some(transition) = data.transition {
        let id = get_transitions(&access_token, site, &data.issue_key)
            .await?
            .transitions
            .into_iter()
            .find(|trans| trans.name == transition)
            .ok_or("Invaild transition".to_string())?
            .id;

        let resp = jira_api(
            Method::PUT,
            site,
            format!("/rest/api/3/issue/{}", data.issue_key),
        )
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

    let resp = jira_api(
        Method::GET,
        site,
        format!("/rest/api/3/issue/{}", data.issue_key),
    )
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

#[derive(Deserialize)]
struct WebhookResults {
    #[serde(rename = "webhookRegistrationResult")]
    webhooks: Vec<WebhookResult>,
}

#[derive(Deserialize)]
struct WebhookResult {
    #[serde(rename = "createdWebhookId")]
    id: u32,
}

async fn create_hook(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let site = &req
        .routes
        .site
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing site route".to_string()))?
        .value;

    let project = &req
        .routes
        .project
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing project route".to_string()))?
        .value;

    jira_api(Method::POST, site, "/rest/api/3/webhook")
        .bearer_auth(decrypt(&req.state))
        .json(&json!({
            "webhooks": [
                {
                    "jqlFilter": format!("project = {project}"),
                    "events": [
                        "jira:issue_created",
                        "jira:issue_updated",
                        "jira:issue_deleted",
                        "comment_created",
                        "comment_updated",
                        "comment_deleted"
                    ]
                }
            ],
            "url": format!("{}/webhook", &*SERVICE_API_PREFIX)
        }))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .json::<WebhookResults>()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .and_then(|hooks| {
            let id = hooks
                .webhooks
                .first()
                .ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Create webhook failed".to_string(),
                ))?
                .id;

            let revoke = format!("{}/revoke-hook?hook_id={}", &*SERVICE_API_PREFIX, id);

            Ok(Json(json!({ "revoke": revoke })))
        })
}

#[derive(Deserialize)]
struct RevokeHook {
    hook_id: u32,
}

async fn revoke_hook(req: Json<HaikuReqBody>, hook: Query<RevokeHook>) -> impl IntoResponse {
    let site = &req
        .routes
        .site
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing site route".to_string()))?
        .value;

    let resp = jira_api(Method::DELETE, site, "/rest/api/3/webhook")
        .bearer_auth(decrypt(&req.state))
        .json(&json!({ "webhookIds": [ hook.hook_id ] }))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match resp.status().is_success() {
        true => Ok(()),
        false => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.text().await.unwrap_or_default(),
        )),
    }
}

async fn events() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "Issue created",
                "value": "jira:issue_created",
            },
            {
                "field": "Issue updated",
                "value": "jira:issue_updated",
            },
            {
                "field": "Issue deleted",
                "value": "jira:issue_deleted",
            },
            {
                "field": "Comment created",
                "value": "comment_created",
            },
            {
                "field": "Comment updated",
                "value": "comment_updated",
            },
            {
                "field": "Comment deleted",
                "value": "comment_deleted",
            }
        ]
    }))
}

async fn get_access_token_from_haiku<A: AsRef<str>>(account_id: A) -> Result<String, String> {
    HTTP_CLIENT
        .post(format!("{}/api/_funcs/_author_state", &*HAIKU_API_PREFIX))
        .header(header::AUTHORIZATION, &*HAIKU_AUTH_TOKEN)
        .json(&json!({ "author": account_id.as_ref() }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map(|at| decrypt(at))
        .map_err(|e| format!("get access token from haiku failed: {}", e.to_string()))
}

async fn post_event_to_haiku<U: AsRef<str>, T: AsRef<str>>(
    user: U,
    text: T,
    triggers: HashMap<&str, &str>,
) -> Result<(), String> {
    HTTP_CLIENT
        .post(format!("{}/api/_funcs/_post", &*HAIKU_API_PREFIX))
        .header(header::AUTHORIZATION, &*HAIKU_AUTH_TOKEN)
        .json(&json!({
            "user": user.as_ref(),
            "text": text.as_ref(),
            "triggers": triggers,
        }))
        .send()
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| {
            r.status()
                .is_success()
                .then_some(())
                .ok_or(format!("Failed to post event to haiku: {:?}", r))
        })
}

async fn capture_event(req: Json<Value>) -> impl IntoResponse {
    if let Err(e) = capture_event_inner(&req).await {
        println!("capture event failed: {}", e);
    }

    StatusCode::OK
}

async fn capture_event_inner(payload: &Value) -> Result<(), String> {
    let event = payload["webhookEvent"]
        .as_str()
        .ok_or("Missing webhookEvent".to_string())?;

    let project = payload["issue"]["fields"]["project"]
        .as_object()
        .ok_or("Missing project".to_string())?;

    let project_id = project["id"]
        .as_str()
        .ok_or("Missing project:id".to_string())?;

    let project_url = project["self"]
        .as_str()
        .ok_or("Missing project:self".to_string())?;

    let account_id = payload["user"]["accountId"]
        .as_str()
        .or_else(|| payload["comment"]["author"]["accountId"].as_str())
        .ok_or("Missing accountId".to_string())?;

    let site_id = get_sites(get_access_token_from_haiku(account_id).await?)
        .await?
        .into_iter()
        .find(|site| project_url.contains(&site.url))
        .ok_or("Mismatch site".to_string())?
        .id;

    post_event_to_haiku(
        account_id,
        payload.to_string(),
        [
            ("site", site_id.as_str()),
            ("project", project_id),
            ("event", event),
        ]
        .into_iter()
        .collect(),
    )
    .await
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
        .route("/events", post(events))
        .route("/post", post(post_issue))
        .route("/create-hook", post(create_hook))
        .route("/revoke-hook", delete(revoke_hook))
        .route("/webhook", post(capture_event));

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
