use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router, Server,
};
use lazy_static::lazy_static;
use serde::Deserialize;
use serde_json::json;
use std::{
    env,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use urlencoding::encode;

const RSA_BITS: usize = 2048;

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env variable SERVICE_API_PREFIX not set");
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    static ref REACTOR_AUTH_TOKEN: String =
        env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
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

fn _decrypt(data: &str) -> String {
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

async fn connect() -> impl IntoResponse {
    let location = format!(
        "{}/api/connected?authorId={}&authorName={}&authorState={}",
        REACTOR_API_PREFIX.as_str(),
        encode("normal_user"),
        encode("Normal User"),
        encrypt("")
    );
    (StatusCode::FOUND, [("Location", location)])
}

async fn schedules() -> impl IntoResponse {
    let schedules = json!({
        "list": [
            {
                "field": "Weather Report",
                "value": "weather_report",
                "desc": "This scheduler will return the weather info periodically",
                "frequently": false,
                "hook": format!("{}/hook", SERVICE_API_PREFIX.as_str())
            }
        ]
    });
    Json(schedules)
}

#[derive(Debug, Deserialize)]
struct Frequency {
    rate: String,
}

#[derive(Debug, Deserialize)]
struct Schedule {
    frequency: Frequency,
}

#[derive(Debug, Deserialize)]
struct Triggers {
    schedule: Vec<Schedule>,
}

#[derive(Debug, Deserialize)]
struct HookBody {
    timestamp: Option<String>,
    triggers: Triggers,
}

async fn hook(Json(hook_body): Json<HookBody>) -> impl IntoResponse {
    if hook_body.timestamp.is_some() {
        tokio::spawn(post_event_to_reactor(
            String::from("normal_user"),
            String::from("sunny"),
        ));
    }

    (
        StatusCode::OK,
        Json(
            json!({"timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().to_string()}),
        ),
    )
}

async fn post_event_to_reactor(user: String, text: String) {
    let request = json!({
        "user": user,
        "text": text,
        "triggers": {
            "schedule": "weather_report"
        }
    });

    let _ = HTTP_CLIENT
        .post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
        .header("Authorization", REACTOR_AUTH_TOKEN.as_str())
        .json(&request)
        .send()
        .await;
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/connect", get(connect))
        .route("/hook", post(hook))
        .route("/schedules", post(schedules));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
