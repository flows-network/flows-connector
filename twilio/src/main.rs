use axum::{
    extract::Form,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router, Server,
};
use lazy_static::lazy_static;
use regex::Regex;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};

use std::{collections::HashMap, env, net::SocketAddr, time::Duration};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

use urlencoding::encode;

const RSA_BITS: usize = 2048;

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
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

static CONNECT_HTML: &str = include_str!("./connect.html");

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

async fn connect() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/html")],
        CONNECT_HTML,
    )
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthBody {
    account_sid: String,
    auth_token: String,
    from_phone: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthState {
    account_sid: String,
    auth_token: String,
}

async fn auth(Form(auth_body): Form<AuthBody>) -> impl IntoResponse {
    let account_sid_regex = Regex::new(r#"^AC[a-zA-Z0-9]{32}$"#).unwrap();
    if !account_sid_regex.is_match(&auth_body.account_sid) {
        return Err((StatusCode::BAD_REQUEST, "Invalid SID"));
    }

    let auth_token_regex = Regex::new(r#"^.{32,}$"#).unwrap();
    if !auth_token_regex.is_match(&auth_body.auth_token) {
        return Err((StatusCode::BAD_REQUEST, "Invalid token"));
    }

    let location = format!(
        "{}/api/connected?authorId={}&authorName={}&authorState={}",
        REACTOR_API_PREFIX.as_str(),
        encode(&auth_body.from_phone),
        encode(&auth_body.from_phone),
        encrypt(
            &serde_json::to_string(&AuthState {
                account_sid: auth_body.account_sid,
                auth_token: auth_body.auth_token
            })
            .unwrap()
        ),
    );
    return Ok((StatusCode::FOUND, [("Location", location)]));
}

#[derive(Debug, Serialize, Deserialize)]
struct PostBody {
    user: String,
    text: String,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TwilioParams {
    body: String,
    to: String,
}

async fn post_msg(Json(pb): Json<PostBody>) -> impl IntoResponse {
    if let Ok(tp) = serde_json::from_str::<TwilioParams>(&pb.text) {
        let mut params = HashMap::with_capacity(3);

        params.insert("Body", tp.body);
        params.insert("To", tp.to);
        params.insert("From", pb.user);

        let state = serde_json::from_str::<AuthState>(&decrypt(&pb.state)).unwrap();

        let response = HTTP_CLIENT
            .post(format!(
                "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
                state.account_sid
            ))
            .form(&params)
            .basic_auth(state.account_sid, Some(state.auth_token))
            .send()
            .await;

        match response {
            Ok(_) => (StatusCode::OK, String::from("")),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)),
        }
    } else {
        (StatusCode::BAD_REQUEST, String::from(""))
    }
}

async fn actions() -> impl IntoResponse {
    let actions = serde_json::json!({
        "list": [
            {
                "field": "To send a SMS",
                "value": "send_sms",
                "desc": "This connector takes the return value of the flow function, sends it via the connected Twilio account. It corresponds to the `Send SMS` call in the Twilio API."
            }
        ]
    });
    Json(actions)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", post(auth))
        .route("/post", post(post_msg))
        .route("/actions", post(actions));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
