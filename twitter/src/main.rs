use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand::{distributions::Alphanumeric, Rng};
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const TIMEOUT: u64 = 120;

const RSA_BITS: usize = 2048;

const STATE_MAP_MAX: usize = 100;
const STATE_BLOCK_EXPIRE_SEC: u64 = 10 * 60;

lazy_static! {
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    static ref REACTOR_AUTH_TOKEN: String =
        env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
    static ref TWITTER_OAUTH_CLIENT_ID: String =
        env::var("TWITTER_OAUTH_CLIENT_ID").expect("Env variable TWITTER_OAUTH_CLIENT_ID not set");
    static ref TWITTER_OAUTH_CLIENT_SECRET: String = env::var("TWITTER_OAUTH_CLIENT_SECRET")
        .expect("Env variable TWITTER_OAUTH_CLIENT_SECRET not set");
    static ref TWITTER_OAUTH_REDIRECT_URL: String = env::var("TWITTER_OAUTH_REDIRECT_URL")
        .expect("Env variable TWITTER_OAUTH_REDIRECT_URL not set");
    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIVATE_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUBLIC_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIVATE_KEY);
    static ref STATE_MAP: Arc<Mutex<HashMap<String, StateBlock>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}

static CONNECT_HTML: &str = include_str!("./connect.html");

fn encrypt(data: &str) -> String {
    hex::encode(
        PUBLIC_KEY
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
        PRIVATE_KEY
            .decrypt(
                PaddingScheme::new_pkcs1v15_encrypt(),
                &hex::decode(data).unwrap(),
            )
            .expect("failed to decrypt"),
    )
    .unwrap()
}

struct StateBlock {
    time_instant: Instant,
    block_content: Option<String>,
}

fn clear_state_map(state_map: &mut HashMap<String, StateBlock>) {
    state_map.retain(|_, v| {
        let elapsed_time = v.time_instant.elapsed();
        elapsed_time.as_secs() < STATE_BLOCK_EXPIRE_SEC
    });
}

async fn connect() -> impl IntoResponse {
    match STATE_MAP.lock() {
        Ok(mut state_map) => {
            if state_map.len() > STATE_MAP_MAX {
                clear_state_map(&mut state_map);
            }
            let s: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();

            let html = CONNECT_HTML;
            // let html = std::fs::read("/home/darumadocker/github/second-state/reactor-connector-rs/twitter/src/connect.html").unwrap();
            // let html = String::from_utf8_lossy(&html);

            let html = html
                .replace("%STATE%", &s)
                .replace(
                    "%TWITTER_OAUTH_CLIENT_ID%",
                    TWITTER_OAUTH_CLIENT_ID.as_str(),
                )
                .replace(
                    "%TWITTER_OAUTH_REDIRECT_URL%",
                    TWITTER_OAUTH_REDIRECT_URL.as_str(),
                );

            state_map.insert(
                s,
                StateBlock {
                    time_instant: Instant::now(),
                    block_content: None,
                },
            );

            Ok((StatusCode::OK, [("Content-Type", "text/html")], html))
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected error".to_string(),
        )),
    }
}

#[derive(Deserialize)]
struct PollQuery {
    state: String,
}

async fn poll_block(Query(pq): Query<PollQuery>) -> impl IntoResponse {
    match STATE_MAP.lock() {
        Ok(state_map) => match state_map.get(&pq.state) {
            Some(block) => match &block.block_content {
                Some(location) => Ok((StatusCode::FOUND, Ok([("Location", location.clone())]))),
                None => Ok((StatusCode::OK, Err(()))),
            },
            None => Err((StatusCode::NOT_FOUND, "State not found")),
        },
        Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")),
    }
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
    code: Option<String>,
    state: String,
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    let code = auth_body.code;
    if code.is_none() {
        Err((StatusCode::BAD_REQUEST, "No code".to_string()))
    } else {
        match get_access_token(&code.unwrap()).await {
            Ok(at) => match get_authed_user(&at.access_token).await {
                Ok(person) => {
                    let location = format!(
                        "{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
                        REACTOR_API_PREFIX.as_str(),
                        person.id,
                        urlencoding::encode(&person.name),
                        encrypt(&at.access_token),
                        encrypt(&at.refresh_token)
                    );
                    match STATE_MAP.lock() {
                        Ok(mut state_map) => {
                            if let Some(block) = state_map.get_mut(&auth_body.state) {
                                block.block_content = Some(location);
                            }
                            Ok((
                                StatusCode::OK,
                                [("Content-Type", "text/html")],
                                "<script>window.close()</script>",
                            ))
                        }
                        Err(_) => Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Unexpected error".to_string(),
                        )),
                    }
                }
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            },
            Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TokenBody {
    access_token: String,
    refresh_token: String,
}

async fn get_access_token(code: &str) -> Result<TokenBody, String> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", TWITTER_OAUTH_REDIRECT_URL.as_str()),
        ("code_verifier", "challenge"),
    ];

    let response = HTTP_CLIENT
        .post("https://api.twitter.com/2/oauth2/token")
        .basic_auth(
            &*TWITTER_OAUTH_CLIENT_ID,
            Some(&*TWITTER_OAUTH_CLIENT_SECRET),
        )
        .form(&params)
        .send()
        .await;
    match response {
        Ok(r) => {
            let oauth_body = r.json::<TokenBody>().await;
            match oauth_body {
                Ok(at) => Ok(at),
                Err(_) => Err("Failed to get access token".to_string()),
            }
        }
        Err(_) => Err("Failed to get access token".to_string()),
    }
}

struct Person {
    id: String,
    name: String,
}

async fn get_authed_user(access_token: &str) -> Result<Person, String> {
    let response = HTTP_CLIENT
        .get("https://api.twitter.com/2/users/me")
        .bearer_auth(access_token)
        .send()
        .await;

    match response {
        Ok(res) => match res.text().await {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    let id = v["data"]["id"].as_str().unwrap().to_string();
                    let name = v["data"]["name"].as_str().unwrap().to_string();
                    Ok(Person { id, name })
                } else {
                    Err("Failed to get user's name".to_string())
                }
            }
            Err(_) => Err("Failed to get user's profile".to_string()),
        },
        Err(_) => Err("Failed to get user's profile".to_string()),
    }
}

async fn actions() -> impl IntoResponse {
    let events = serde_json::json!({
        "list": [
            {
                "field": "Create Tweet",
                "value": "create-tweet"
            }
        ]
    });
    Json(events)
}

#[derive(Debug, Deserialize, Serialize)]
struct ForwardRoute {
    route: String,
    value: String,
}

#[derive(Deserialize)]
struct PostBody {
    // user: String,
    text: String,
    state: String,
    forwards: Vec<ForwardRoute>,
}

async fn post_msg(Json(msg_body): Json<PostBody>) -> impl IntoResponse {
    let routes = msg_body
        .forwards
        .iter()
        .map(|route| (route.route.clone(), route.value.clone()))
        .collect::<HashMap<String, String>>();

    let action = if let Some(a) = routes.get("action") {
        a
    } else {
        return Err((StatusCode::BAD_REQUEST, "Missing action"));
    };

    match action.as_str() {
        "create-tweet" => {
            let resp = HTTP_CLIENT
                .post("https://api.twitter.com/2/tweets")
                .bearer_auth(decrypt(&msg_body.state))
                .json(&serde_json::json!({
                    "text": msg_body.text
                }))
                .send()
                .await;

            if resp.is_ok() {
                Ok((StatusCode::FOUND, "Ok"))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, "Create tweet failed"))
            }
        }
        _ => Err((StatusCode::BAD_REQUEST, "Unsupport action")),
    }
}

#[derive(Deserialize)]
struct RefreshState {
    refresh_state: String,
}

async fn refresh_token(Json(msg_body): Json<RefreshState>) -> impl IntoResponse {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", &decrypt(&msg_body.refresh_state)),
    ];

    let response = HTTP_CLIENT
        .post("https://api.twitter.com/2/oauth2/token")
        .basic_auth(
            &*TWITTER_OAUTH_CLIENT_ID,
            Some(&*TWITTER_OAUTH_CLIENT_SECRET),
        )
        .form(&params)
        .send()
        .await;

    if let Ok(r) = response {
        if let Ok(at) = r.json::<TokenBody>().await {
            let encrypted = serde_json::json!({
                "access_state": encrypt(&at.access_token),
                "refresh_state": encrypt(&at.refresh_token)
            });
            Ok((StatusCode::OK, serde_json::to_string(&encrypted).unwrap()))
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get access token".to_string(),
            ))
        }
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get access token".to_string(),
        ))
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/connect", get(connect))
        .route("/poll-block", get(poll_block))
        .route("/auth", get(auth))
        .route("/refresh", post(refresh_token))
        .route("/actions", post(actions))
        .route("/post", post(post_msg));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
