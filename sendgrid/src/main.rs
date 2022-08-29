use axum::{
    extract::{ContentLengthLimit, Form, Json, Multipart},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router, Server,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, net::SocketAddr, time::Duration};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder};
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
        encode(auth_body.sender_email.as_str()),
        encode(auth_body.sender_email.as_str()),
        encrypt(&auth_body.api_key)
    );
    return Ok((StatusCode::FOUND, [("Location", location)]));
}

#[derive(Debug, Deserialize, Serialize)]
struct PostBody {
    user: String,
    text: String,
    state: String,
}

async fn post_msg(Json(pb): Json<PostBody>) -> impl IntoResponse {
    if let Ok(mbs) = serde_json::from_str::<Vec<serde_json::Value>>(&pb.text) {
        if mbs.is_empty() {
            return (StatusCode::BAD_REQUEST, String::from(""));
        }
        for mut mb in mbs {
            mb.as_object_mut().and_then(|obj| {
                Some(obj.entry("from").or_insert(json!({
                    "email": pb.user,
                })))
            });

            let response = HTTP_CLIENT
                .post("https://api.sendgrid.com/v3/mail/send")
                .bearer_auth(decrypt(&pb.state))
                .json(&mb)
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

async fn upload_msg(
    ContentLengthLimit(mut multipart): ContentLengthLimit<
        Multipart,
        {
            10 * 1024 * 1024 // 250mb
        },
    >,
) -> impl IntoResponse {
    tokio::spawn(async move {
        let mut user = String::new();
        let mut text = String::new();
        let mut state = String::new();
        // let mut forwards = String::new();

        let mut data = Vec::new();

        while let Some(field) = multipart.next_field().await.unwrap() {
            let name = field.name().unwrap().to_owned();

            match name.as_str() {
                "file" => {
                    let file_name = field.file_name().unwrap().to_string();
                    let content_type = field.content_type().unwrap().to_string();
                    if let Ok(datum) = field.bytes().await {
                        data.push((file_name, content_type, datum));
                    }
                }
                "user" => {
                    if let Ok(u) = field.text().await {
                        user = u;
                    }
                }
                "state" => {
                    if let Ok(s) = field.text().await {
                        state = s;
                    }
                }
                "text" => {
                    if let Ok(t) = field.text().await {
                        text = t;
                    }
                }
                "forwards" => {
                    // if let Ok(f) = field.text().await {
                    //     if let Ok(fws) = serde_json::from_str(&f) {
                    //         forwards = fws;
                    //     }
                    // }
                }
                _ => {}
            };
        }

        if user.len() == 0 || state.len() == 0 {
            return;
        }

        if data.len() > 0 {
            let text_: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&text);
            if let Ok(mut t) = text_ {
                let mut atchsmts = vec![];
                for (file_name, content_type, datum) in data.into_iter() {
                    let name: String = file_name.chars().take_while(|&c| c != '.').collect();

                    let content = base64::encode(datum);

                    atchsmts.push(serde_json::json!({
                        "content": content,
                        "content_id": content[..10],
                        "disposition": "inline",
                        "filename": file_name,
                        "name": name,
                        "type": content_type,
                    }));
                }

                // NOTE every email were injected the same attachments
                for o in t.as_array_mut().unwrap() {
                    o.as_object_mut().and_then(|obj| {
                        Some(
                            obj.entry("attachments")
                                .or_insert(serde_json::json!(atchsmts)),
                        )
                    });
                }

                text = t.to_string();
            } else {
                return;
            }
        }

        if text.len() > 0 {
            tokio::spawn(post_msg(Json::from(PostBody { user, text, state })));
        }
    });

    StatusCode::OK
}

async fn actions() -> impl IntoResponse {
    let actions = serde_json::json!({
        "list": [
            {
                "field": "To send an email",
                "value": "send_email",
                "desc": "This connector takes the return value of the flow function, creates an email message, and sends it via the connected Sendgrid account. It corresponds to the `Send Email` call in the SendGrid API."
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
        .route("/post", post(post_msg).put(upload_msg))
        .route("/actions", post(actions));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
