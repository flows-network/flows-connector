use axum::{
    extract::{ContentLengthLimit, Json, Multipart, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Router,
};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use regex::Regex;
use reqwest::{
    header,
    multipart::{Form, Part},
    Client,
};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, net::SocketAddr};

const RSA_BITS: usize = 2048;

static CONNECT_HTML: &str = include_str!("./connect.html");

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    static ref HAIKU_AUTH_TOKEN: String =
        env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIVATE_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUBLIC_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIVATE_KEY);
    static ref HTTP_CLIENT: Client = Client::new();
}

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

fn decrypt<T: AsRef<[u8]>>(data: T) -> String {
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

async fn connect() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        CONNECT_HTML,
    )
}

#[derive(Serialize, Deserialize)]
struct ApiEnv {
    cloud_name: String,
    api_key: String,
    api_secret: String,
}

async fn auth(req: Query<ApiEnv>) -> impl IntoResponse {
    HTTP_CLIENT
        .get(format!(
            "https://api.cloudinary.com/v1_1/{}/ping",
            req.cloud_name
        ))
        .basic_auth(&req.api_key, Some(&req.api_secret))
        .send()
        .await
        .map(|r| {
            if !r.status().is_success() {
                return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string());
            }

            let location = format!(
                "{}/api/connected?authorId={}&authorName={}&authorState={}",
                *HAIKU_API_PREFIX,
                req.cloud_name,
                req.cloud_name,
                encrypt(&serde_json::to_string(&*req).unwrap())
            );

            (StatusCode::OK, location)
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn upload(
    ContentLengthLimit(mut multipart): ContentLengthLimit<Multipart, { 250 * 1024 * 1024 }>,
) -> impl IntoResponse {
    let mut api_env = None;
    let mut file = Vec::new();
    let mut file_type = None;
    let mut file_name = None;

    while let Some(field) = multipart.next_field().await.unwrap_or_else(|_| None) {
        match field.name().unwrap_or_default() {
            "file" => {
                let t = field
                    .content_type()
                    .ok_or((StatusCode::BAD_REQUEST, "Missing content type".to_string()))?;

                let t = t.split_once("/").map_or_else(|| t, |t| t.0);

                file_type = match t {
                    "image" | "video" | "raw" => Some(t.to_string()),
                    _ => return Err((StatusCode::BAD_REQUEST, "Invalid content type".to_string())),
                };

                file_name = field.file_name().map(|n| n.to_string());

                file.append(
                    &mut field
                        .bytes()
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                        .into(),
                );
            }
            "state" => {
                let bytes = decrypt(
                    field
                        .bytes()
                        .await
                        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
                );

                api_env = Some(
                    serde_json::from_str::<ApiEnv>(&bytes)
                        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
                );
            }
            _ => {}
        }
    }

    if file.len() == 0 {
        return Err((StatusCode::BAD_REQUEST, "Invalid file".to_string()));
    }

    upload_file_to_cloudinary(
        file,
        file_name.ok_or((StatusCode::BAD_REQUEST, "Missing file name".to_string()))?,
        file_type.ok_or((StatusCode::BAD_REQUEST, "Missing content type".to_string()))?,
        api_env.ok_or((StatusCode::BAD_REQUEST, "Missing API env".to_string()))?,
    )
    .await
    .map(|_| (StatusCode::OK, "OK".to_string()))
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn upload_file_to_cloudinary(
    file: Vec<u8>,
    file_path: String,
    file_type: String,
    api_env: ApiEnv,
) -> Result<(), String> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let hook = format!("{}/webhook", *SERVICE_API_PREFIX);
    let file_name = file_path
        .split_once(".")
        .map_or_else(|| file_path.clone(), |f| f.0.to_string());

    let signature = sha256::digest(format!(
        "notification_url={}&public_id={}&timestamp={}{}",
        hook, file_name, timestamp, api_env.api_secret
    ));

    let form = Form::new()
        .part("file", Part::bytes(file).file_name(file_path))
        .text("api_key", api_env.api_key)
        .text("notification_url", hook)
        .text("public_id", file_name)
        .text("timestamp", timestamp)
        .text("signature", signature);

    HTTP_CLIENT
        .post(format!(
            "https://api.cloudinary.com/v1_1/{}/{}/upload",
            api_env.cloud_name, file_type
        ))
        .multipart(form)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct Notification {
    notification_type: String,
    secure_url: Option<String>,
    error: Option<ErrorMessage>,
}

#[derive(Deserialize)]
struct ErrorMessage {
    message: String,
}

async fn capture_event(Json(req): Json<Notification>) -> impl IntoResponse {
    if let Err(e) = capture_event_inner(req).await {
        println!("capture_event error: {}", e);
    };

    StatusCode::OK
}

async fn capture_event_inner(req: Notification) -> Result<(), String> {
    match req.notification_type.as_str() {
        "upload" => {
            let secure_url = req.secure_url.ok_or("Missing secure url".to_string())?;

            let reg = Regex::new("res.cloudinary.com/([\\w-]+)/").unwrap();
            let cloud_name = reg
                .captures(&secure_url)
                .ok_or("Invaild secure url".to_string())?
                .get(1)
                .ok_or("Invaild secure url".to_string())?
                .as_str();

            let body = json!({
                "user": cloud_name,
                "text": secure_url,
                "triggers": {
                    "event": "file_uploaded"
                }
            });

            let response = HTTP_CLIENT
                .post(format!("{}/api/_funcs/_post", *HAIKU_API_PREFIX))
                .header(header::AUTHORIZATION, &*HAIKU_AUTH_TOKEN)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?;

            match response.status().is_success() {
                true => Ok(()),
                false => Err(format!("Post event failed: {:?}", response.bytes().await)),
            }
        }
        "error" => Err(req
            .error
            .ok_or("Missing error message".to_string())?
            .message),
        _ => Ok(()),
    }
}

async fn events() -> impl IntoResponse {
    let events = serde_json::json!({
        "list": [
            {
                "field": "File Uploaded",
                "value": "file_uploaded"
            }
        ]
    });
    Json(events)
}

async fn actions() -> impl IntoResponse {
    let actions = serde_json::json!({
        "list": [
            {
                "field": "Upload File",
                "value": "upload_file"
            }
        ]
    });
    Json(actions)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", get(auth))
        .route("/post", put(upload))
        .route("/webhook", post(capture_event))
        .route("/events", post(events))
        .route("/actions", post(actions));

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
