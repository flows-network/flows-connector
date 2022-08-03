use axum::{
    extract::{Form, Json},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router, Server,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, net::SocketAddr, time::Duration};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

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
    sender_email: String,
    api_key: String,
}

async fn auth(Form(auth_body): Form<AuthBody>) -> impl IntoResponse {
    let email_regex = Regex::new(r#"^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"#).unwrap();
    if !email_regex.is_match(&auth_body.sender_email.to_lowercase()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email"));
    }
    let api_key_regex = Regex::new(r"^.{50,}$").unwrap();
    if !api_key_regex.is_match(&auth_body.api_key) {
        return Err((StatusCode::BAD_REQUEST, "Invalid api key"));
    }
    let location = format!(
        "{}/api/connected?authorId={}&authorName={}&authorState={}",
        REACTOR_API_PREFIX.as_str(),
        auth_body.sender_email,
        auth_body.sender_email,
        encrypt(&auth_body.api_key)
    );
    return Ok((StatusCode::FOUND, [("Location", location)]));
}

#[derive(Debug, Serialize, Deserialize)]
struct MailBody {
    to_email: String,
    subject: String,
    content: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PostBody {
    user: String,
    text: String,
    state: String,
}

async fn post_msg(Json(pb): Json<PostBody>) -> impl IntoResponse {
    if let Ok(mbs) = serde_json::from_str::<Vec<MailBody>>(&pb.text) {
        if mbs.is_empty() {
            return (StatusCode::BAD_REQUEST, String::from(""));
        }

        let mut emails: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for mb in mbs {
            let subject = mb.subject;
            let to_email = mb.to_email;
            emails
                .entry(mb.content)
                .or_insert(vec![])
                .push((subject, to_email));
        }

        for (content, ens) in emails {
            let personalizations: Vec<_> = ens
                .into_iter()
                .map(|(subject, to_email)| {
                    serde_json::json!({
                        "to": [{"email": to_email}],
                        "subject": subject,
                    })
                })
                .collect();
            let request = serde_json::json!({
                "from": {
                    "email": pb.user,
                },
                "personalizations": personalizations,
                "content": [{
                    "type": "text/html",
                    "value": content,
                }]
            });

            let response = HTTP_CLIENT
                .post("https://api.sendgrid.com/v3/mail/send")
                .bearer_auth(decrypt(&pb.state))
                .json(&request)
                .send()
                .await;
            match response {
                Ok(_) => (),
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)),
            }
        }

        (StatusCode::OK, String::from(""))
    } else {
        (StatusCode::BAD_REQUEST, String::from(""))
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", post(auth))
        .route("/post", post(post_msg));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
