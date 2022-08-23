#![recursion_limit = "256"]

use axum::{
    extract::{Form, Json, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Router, TypedHeader,
};
use headers::HeaderName;
use headers::{Header as IHeader, HeaderValue};
use itertools::iproduct;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use lazy_static::lazy_static;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

#[derive(Debug, Deserialize, Serialize)]
struct AuthBody {
    code: String,
    installation_id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct AccessTokenBody {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenBody {
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuthState {
    access_token: String,
    installation_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstRepo {
    node_id: String,
    name: String,
    full_name: String,
    html_url: String,
    hooks_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstalledRepos {
    total_count: u32,
    repositories: Vec<InstRepo>,
}

const RSA_BITS: usize = 2048;

const REPOS_PER_PAGE: u32 = 20;

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    static ref REACTOR_AUTH_TOKEN: String =
        env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
    static ref GITHUB_APP_INSTALL_LOCATION: String = env::var("GITHUB_APP_INSTALL_LOCATION")
        .expect("Env variable GITHUB_APP_INSTALL_LOCATION not set");
    static ref GITHUB_APP_ID: String =
        env::var("GITHUB_APP_ID").expect("Env variable GITHUB_APP_ID not set");
    static ref GITHUB_PRIVATE_KEY: String =
        env::var("GITHUB_APP_PRIVATE_KEY").expect("Env variable GITHUB_APP_PRIVATE_KEY not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    static ref GITHUB_CLIENT_ID: String =
        env::var("GITHUB_APP_CLIENT_ID").expect("Env variable GITHUB_APP_CLIENT_ID not set");
    static ref GITHUB_CLIENT_SECRET: String = env::var("GITHUB_APP_CLIENT_SECRET")
        .expect("Env variable GITHUB_APP_CLIENT_SECRET not set");
    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIV_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}

fn get_now() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    return since_the_epoch.as_secs();
}

fn encrypt(data: &str) -> String {
    hex::encode(
        PUB_KEY
            .encrypt(
                &mut CHACHA8RNG.clone(),
                PaddingScheme::new_pkcs1v15_encrypt(),
                data.as_bytes(),
            )
            .expect("failed to encrypt"),
    )
}

fn decrypt(data: &str) -> String {
    String::from_utf8(
        PRIV_KEY
            .decrypt(
                PaddingScheme::new_pkcs1v15_encrypt(),
                &hex::decode(data).unwrap(),
            )
            .expect("failed to decrypt"),
    )
    .unwrap()
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.eq("") {
        Err((StatusCode::BAD_REQUEST, "No code".to_string()))
    } else {
        match get_access_token(&auth_body.code).await {
            Ok(at) => match get_authed_user(&at.access_token).await {
                Ok(gu) => {
                    let location = format!(
                        "{}/api/connected?authorId={}&authorName={}&authorState={}",
                        REACTOR_API_PREFIX.as_str(),
                        gu.node_id,
                        gu.login,
                        encrypt(
                            &serde_json::to_string(&AuthState {
                                access_token: at.access_token,
                                installation_id: auth_body.installation_id,
                            })
                            .unwrap()
                        )
                    );
                    Ok((StatusCode::FOUND, [(header::LOCATION, location)]))
                }
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            },
            Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
        }
    }
}

async fn get_access_token(code: &str) -> Result<AccessTokenBody, String> {
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
                Ok(at) => return Ok(at),
                Err(_) => {
                    return Err("Failed to get access token".to_string());
                }
            }
        }
        Err(_) => {
            return Err("Failed to get access token".to_string());
        }
    }
}

async fn get_installation_token(installation_id: u64) -> Result<String, String> {
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
                Ok(at) => return Ok(at.token),
                Err(_) => {
                    return Err("Failed to get installation token".to_string());
                }
            }
        }
        Err(_) => {
            return Err("Failed to get installation token".to_string());
        }
    }
}

async fn get_installed_repositories(
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
            Ok(repos) => return Ok(repos),
            Err(_) => {
                return Err("Failed to get installed repositories".to_string());
            }
        },
        Err(_) => {
            return Err("Failed to get installed repositories".to_string());
        }
    }
}

#[derive(Debug, Deserialize)]
struct Event {
    connector: String,
    flow: String,
    payload: String,
}

struct GithubEvent(String);

// header name must be lowercase
static HN: HeaderName = HeaderName::from_static("x-github-event");

impl IHeader for GithubEvent {
    fn name() -> &'static HeaderName {
        &HN
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i headers::HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        Ok(Self(value.to_str().unwrap().to_owned()))
    }

    fn encode<E: Extend<headers::HeaderValue>>(&self, values: &mut E) {
        let value = HeaderValue::from_str(&self.0).unwrap();
        values.extend(std::iter::once(value));
    }
}

async fn capture_event(
    Form(event): Form<Event>,
    TypedHeader(ge): TypedHeader<GithubEvent>,
) -> impl IntoResponse {
    tokio::spawn(capture_event_inner(event, ge));
    (StatusCode::OK, String::new())
}

async fn capture_event_inner(event: Event, ge: GithubEvent) {
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

#[derive(Debug, Deserialize)]
struct GithubUser {
    login: String,
    node_id: String,
    email: Option<String>,
}

async fn get_authed_user(access_token: &str) -> Result<GithubUser, String> {
    let response = HTTP_CLIENT
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .send()
        .await;

    match response {
        Ok(res) => {
            let body = res.json::<GithubUser>().await;
            match body {
                Ok(gu) => {
                    return Ok(gu);
                }
                Err(_) => {
                    return Err("Failed to get user".to_string());
                }
            }
        }
        Err(_) => {
            return Err("Failed to get user".to_string());
        }
    }
}

async fn get_github_user(api_url: &str, access_token: &str) -> Result<GithubUser, ()> {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RouteObject {
    field: String,
    value: String,
}
#[derive(Debug, Deserialize)]
struct HookRoutes {
    event: Vec<RouteObject>,
    repo: Vec<RouteObject>,
}
#[derive(Debug, Deserialize)]
struct HookReq {
    user: String,
    state: String,
    flow: String,
    routes: HookRoutes,
}

async fn create_hook(Json(req): Json<HookReq>) -> impl IntoResponse {
    if req.routes.event.len() == 0 || req.routes.repo.len() != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            String::from("Bad routes, only one repo is allowed"),
        ));
    }
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

    match get_installation_token(auth_state.installation_id).await {
        Ok(install_token) => {
            match create_hook_inner(&req.user, &req.flow, &req.routes, &install_token).await {
                Ok(v) => Ok((StatusCode::CREATED, Json(v))),
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            }
        }
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

async fn create_hook_inner(
    connector: &str,
    flow_id: &str,
    routes: &HookRoutes,
    install_token: &str,
) -> Result<Value, String> {
    let events: Vec<String> = routes.event.iter().map(|e| e.value.clone()).collect();
    let param = json!({
        "name": "web",
        "active": true,
        "events": events,
        "config": {
            "url": format!("{}/event?connector={connector}&flow={flow_id}", SERVICE_API_PREFIX.as_str()),
            "content_type": "form",
        }
    });
    let response = HTTP_CLIENT
        .post(format!(
            "https://api.github.com/repos/{}/hooks",
            routes.repo[0].field
        ))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "Github Connector of Second State Reactor")
        .bearer_auth(install_token)
        .json(&param)
        .send()
        .await;
    if let Ok(r) = response {
        if r.status().is_success() {
            if let Ok(body) = r.bytes().await {
                let json_body: Value = serde_json::from_slice(&body).unwrap();
                let hook_id = json_body["id"].to_string();
                let result = serde_json::json!({
                    "revoke": format!("{}/revoke-hook?hook_id={hook_id}", SERVICE_API_PREFIX.as_str()),
                });
                return Ok(result);
            }
        } else {
            if let Ok(b) = r.text().await {
                println!("{}", b);
            }
        }
    }
    Err("Failed to create hook".to_string())
}

#[derive(Deserialize)]
struct RevokeQuery {
    hook_id: String,
}

async fn revoke_hook(
    Json(req): Json<HookReq>,
    Query(query): Query<RevokeQuery>,
) -> impl IntoResponse {
    if req.routes.event.len() == 0 || req.routes.repo.len() != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            String::from("Bad routes, only one repo is allowed"),
        ));
    }

    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

    match get_installation_token(auth_state.installation_id).await {
        Ok(install_token) => {
            match revoke_hook_inner(&req.routes, &query.hook_id, &install_token).await {
                Ok(()) => Ok(StatusCode::OK),
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            }
        }
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

async fn revoke_hook_inner(
    routes: &HookRoutes,
    hook_id: &str,
    install_token: &str,
) -> Result<(), String> {
    let response = HTTP_CLIENT
        .delete(format!(
            "https://api.github.com/repos/{}/hooks/{hook_id}",
            routes.repo[0].field
        ))
        .header(header::ACCEPT, "application/vnd.github.v3+json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .bearer_auth(install_token)
        .send()
        .await;
    if let Ok(_) = response {
        // the status can be 204 or 404
        // so no need to check r.status().is_success()
        // always return ok
        return Ok(());
    }
    Err("Failed to revoke hook".to_string())
}

#[derive(Debug, Deserialize)]
struct RouteReq {
    // user: String,
    state: String,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct _Event {
    #[serde(rename(deserialize = "GitHub Event"))]
    value: String,
    #[serde(rename(deserialize = "Event Title on WasmHaiku"))]
    field: String,
    #[serde(rename(deserialize = "Description"))]
    desc: String,
}

lazy_static! {
    static ref EVENTS: Vec<_Event> = {
        let content = include_bytes!("./events.csv");
        let mut rdr = csv::Reader::from_reader(content.as_slice());
        rdr.deserialize()
            .map(|r| {
                let event: _Event = r.unwrap();
                event
            })
            .collect()
    };
}

async fn hook_events() -> impl IntoResponse {
    Json(json!({
        "list": &*EVENTS
    }))
}

async fn repos(Json(body): Json<RouteReq>) -> impl IntoResponse {
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&body.state)).unwrap();
    match get_installation_token(auth_state.installation_id).await {
        Ok(install_token) => {
            let page = body.cursor.unwrap_or_else(|| "1".to_string());
            if let Ok(page) = page.parse::<u32>() {
                match get_installed_repositories(&install_token, page).await {
                    Ok(irs) => {
                        let rs: Vec<Value> = irs
                            .repositories
                            .iter()
                            .map(|ir| {
                                serde_json::json!({
                                    "field": ir.full_name,
                                    "value": ir.node_id
                                })
                            })
                            .collect();
                        let result = match irs.total_count > page * REPOS_PER_PAGE {
                            true => {
                                serde_json::json!({
                                    "next_cursor": page + 1,
                                    "list": rs
                                })
                            }
                            false => {
                                serde_json::json!({ "list": rs })
                            }
                        };
                        Ok(Json(result))
                    }
                    Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
                }
            } else {
                Err((StatusCode::BAD_REQUEST, "Invalid cursor".to_string()))
            }
        }
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

async fn actions() -> impl IntoResponse {
    let events = serde_json::json!({
        "list": [
            {
                "field": "Create Issue",
                "value": "create-issue",
            },
            {
                "field": "Create Issue/PR Comment",
                "value": "create-comment",
            },
            {
                "field": "Add labels to an Issue/PR",
                "value": "add-labels",
            },
            {
                "field": "Add assignees to an Issue/PR",
                "value": "add-assignees",
            },
        ],
    });
    Json(events)
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ForwardRoutes {
    action: Vec<RouteObject>,
    repo: Vec<RouteObject>,
}

#[derive(Deserialize, Serialize)]
struct PostBody {
    user: String,
    text: String,
    state: String,
    forwards: ForwardRoutes,
}

async fn post_msg(
    Json(msg_body): Json<PostBody>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    tokio::spawn(post_msg_inner(msg_body));
    Ok(StatusCode::OK)
}

async fn post_msg_inner(msg_body: PostBody) {
    let auth_state = serde_json::from_str::<AuthState>(&decrypt(&msg_body.state)).unwrap();
    let access_token = auth_state.access_token.to_owned();

    let fwds = msg_body.forwards;
    let msg_text = msg_body.text;

    for (repo, action) in iproduct!(fwds.repo, fwds.action) {
        post_action(&repo.value, &action.value, &access_token, &msg_text).await;
    }
}

async fn post_action(node_id: &str, action: &str, access_token: &str, msg_text: &str) {
    if let Ok(repo_name) = get_repo_namewithowner(node_id, access_token).await {
        let api_base = format!("https://api.github.com/repos/{}", repo_name);

        let rb = match action {
            "create-issue" => Some(
                HTTP_CLIENT
                    .post(format!("{api_base}/issues"))
                    .json(&serde_json::json!({ "title": msg_text })),
            ),
            // shared by issue & pr
            "create-comment" => {
                let msg: Value = serde_json::from_str(&msg_text).unwrap();
                let issue_number = msg["issue_number"].as_u64().unwrap();
                let body = msg["body"].as_str().unwrap();
                Some(
                    HTTP_CLIENT
                        .post(format!("{api_base}/issues/{}/comments", issue_number))
                        .json(&serde_json::json!({
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
                        .json(&serde_json::json!({
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
                        .json(&serde_json::json!({
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
        });

        if let Some(r) = rb {
            _ = r.send().await
        }
    }
}

async fn get_repo_namewithowner(node_id: &str, access_token: &str) -> Result<String, String> {
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

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/auth", get(auth))
        .route("/event", post(capture_event))
        .route("/create-hook", post(create_hook))
        .route("/revoke-hook", delete(revoke_hook))
        .route("/hook-events", post(hook_events))
        .route("/actions", post(actions))
        .route("/repos", post(repos))
        .route("/post", post(post_msg));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
