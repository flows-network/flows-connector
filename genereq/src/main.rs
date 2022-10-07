use axum::{
    body::Bytes,
    extract::{Form, Json, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router, Server,
};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::{env, net::SocketAddr, time::Duration};

use reqwest::{header, Client, ClientBuilder};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env variable SERVICE_API_PREFIX not set");
    static ref PLATFORM_API_PREFIX: String =
        env::var("PLATFORM_API_PREFIX").expect("Env variable PLATFORM_API_PREFIX not set");
    static ref PLATFORM_AUTH_TOKEN: String =
        env::var("PLATFORM_AUTH_TOKEN").expect("Env variable PLATFORM_AUTH_TOKEN not set");
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}

static CONNECT_HTML: &str = include_str!("./connect.html");

async fn connect() -> impl IntoResponse {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    (
        StatusCode::OK,
        [("Content-Type", "text/html")],
        CONNECT_HTML
            .replace("{GENEREQ_SERVER_URL}", SERVICE_API_PREFIX.as_str())
            .replace("{GENEREQ_RID}", &rand_string),
    )
}

#[derive(Debug, Deserialize)]
struct AuthBody {
    codename: String,
    rid: String,
}

async fn auth(Form(auth_body): Form<AuthBody>) -> impl IntoResponse {
    let location = format!(
        "{}/api/connected?authorId={}&authorName={}&authorState={}",
        PLATFORM_API_PREFIX.as_str(),
        auth_body.rid,
        auth_body.codename,
        ""
    );

    return (StatusCode::FOUND, [("Location", location)]);
}

pub async fn capture_event(Path(rid): Path<String>, body: Bytes) -> impl IntoResponse {
    tokio::spawn(post_event_to_platform(rid, body));
    (StatusCode::OK, String::new())
}

async fn post_event_to_platform(user: String, text: Bytes) {
    let triggers = serde_json::json!({
        "event": "request",
    });

    let request = serde_json::json!({
        "user": user,
        "text": String::from_utf8_lossy(&text.to_vec()),
        "triggers": triggers,
    });

    let response = HTTP_CLIENT
        .post(format!("{}/api/_funcs/_post", PLATFORM_API_PREFIX.as_str()))
        .header(header::AUTHORIZATION, PLATFORM_AUTH_TOKEN.as_str())
        .json(&request)
        .send()
        .await;
    if let Err(e) = response {
        println!("{:?}", e);
    }
}

async fn events() -> impl IntoResponse {
    let events = serde_json::json!({
        "list": [
            {
                "field": "Request is received",
                "value": "request",
                "desc": "A request to the specified url is received by Genereq connector."
            }
        ]
    });
    Json(events)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", post(auth))
        .route("/s/:rid", post(capture_event))
        .route("/events", post(events));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
