use axum::{
    extract::{Json, Query, ContentLengthLimit, Multipart},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Router,
};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{header, Client};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use serde_json::json;
use std::{net::SocketAddr, env};

const RSA_BITS: usize = 2048;

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    // static ref HAIKU_AUTH_TOKEN: String =
    //     env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    static ref DROPBOX_APP_CLIENT_ID: String =
        env::var("DROPBOX_APP_CLIENT_ID").expect("Env variable DROPBOX_APP_CLIENT_ID not set");
    static ref DROPBOX_APP_CLIENT_SECRET: String = env::var("DROPBOX_APP_CLIENT_SECRET")
        .expect("Env variable DROPBOX_APP_CLIENT_SECRET not set");
    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    
    static ref REDIRECT_URL: String = format!("{}/auth", &*SERVICE_API_PREFIX);
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
    (StatusCode::FOUND, [(header::LOCATION, format!(
            "https://www.dropbox.com/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&token_access_type=offline",
            &*DROPBOX_APP_CLIENT_ID,
            urlencoding::encode(&*REDIRECT_URL)
        )
    )])
}

#[derive(Deserialize)]
struct AuthBody {
    code: String,
}

#[derive(Deserialize, Clone)]
struct AccessToken {
    access_token: String,
    refresh_token: String,
    account_id: Option<String>,
    // team_id: String,
}

enum AuthMode {
    Authorization(String),
    Refresh(String),
}

async fn get_access_token(mode: AuthMode) -> Result<AccessToken, String> {
    let params = match mode {
        AuthMode::Authorization(code) => {
            [
                ("code", code),
                ("grant_type", "authorization_code".to_string()),
                ("redirect_uri", REDIRECT_URL.to_string()),
            ]
        },
        AuthMode::Refresh(refresh_token) => {
            [
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token".to_string()),
                ("redirect_uri", REDIRECT_URL.to_string()),
            ]
        },
    };

    HTTP_CLIENT
        .post("https://api.dropbox.com/oauth2/token")
        .basic_auth(&*DROPBOX_APP_CLIENT_ID, Some(&*DROPBOX_APP_CLIENT_SECRET))
        .form(&params)
        .send()
        .await
        .map_err(|e| e.to_string())?

        .json::<AccessToken>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct Name {
    display_name: String,
}

#[derive(Deserialize)]
struct Account {
    email: String,
    name: Name
}

async fn get_account(at: &AccessToken) -> Result<Account, String> {
    HTTP_CLIENT
        .post("https://api.dropboxapi.com/2/users/get_current_account")
        .bearer_auth(at.access_token.clone())
        .send()
        .await
        .map_err(|e| e.to_string())?

        .json::<Account>()
        .await
        .map_err(|e| e.to_string())
}

async fn auth(req: Query<AuthBody>) -> impl IntoResponse {
    let at = match get_access_token(AuthMode::Authorization(req.code.clone())).await{
        Ok(at) => at,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, e))
    };

    let id = at.account_id
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing refresh_token".to_string()))?;

    let account = get_account(&at).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR,
            format!("get_account failed: {}", e)))?;

    Ok((StatusCode::FOUND, [(header::LOCATION, format!(
        "{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
        &*HAIKU_API_PREFIX,
        id,
        format!("{} ({})", account.name.display_name, account.email),
        encrypt(&at.access_token),
        encrypt(&at.refresh_token)
    ))]))
}

#[derive(Deserialize)]
struct RefreshBody {
    refresh_state: String
}

async fn refresh(req: Json<RefreshBody>) -> impl IntoResponse {
    get_access_token(AuthMode::Refresh(decrypt(&req.refresh_state))).await
        .map(|at| (StatusCode::OK, encrypt(&at.access_token)))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn upload(
    ContentLengthLimit(mut multipart): ContentLengthLimit<Multipart, { 150 * 1024 * 1024 }>,
) -> impl IntoResponse {
    let mut access_token = None; 
    let mut file = Vec::new();
    let mut file_name = None;

    while let Some(field) = multipart.next_field().await.unwrap_or_else(|_| None) {
        match field.name().unwrap_or_default() {
            "file" => {
                file.append(
                    &mut field
                        .bytes()
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                        .into(),
                );
            },
            "text" => {
                file_name = Some(String::from_utf8(field
                    .bytes()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
                    .to_vec())
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?);
            }
            "state" => {
                access_token = Some(decrypt(
                    field
                        .bytes()
                        .await
                        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
                ));
            }
            _ => {},
        }
    }

    if file.len() == 0 {
        return Err((StatusCode::BAD_REQUEST, "Invalid file".to_string()));
    }

    upload_file_to_dropbox(
        file,
        file_name.ok_or((StatusCode::BAD_REQUEST, "Missing file name".to_string()))?,
        access_token.ok_or((StatusCode::BAD_REQUEST, "Missing access_token".to_string()))?,
    )
    .await
    .map(|_| StatusCode::OK)
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn upload_file_to_dropbox(
    file: Vec<u8>,
    file_name: String,
    access_token: String,
) -> Result<(), String> {
    let response = HTTP_CLIENT
        .post("https://content.dropboxapi.com/2/files/upload")
        .bearer_auth(access_token)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("Dropbox-API-Arg",
            json!({
                "autorename": true,
                "path": file_name,
            }).to_string())
        .body(file)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    match response.status().is_success() {
        true => Ok(()),
        false => Err(format!("Upload failed: {:?}", response.bytes().await.unwrap_or_default())),
    }
}

#[derive(Deserialize)]
struct ChallengeBody {
    challenge: String,
}

async fn webhook_challenge(req: Query<ChallengeBody>) -> impl IntoResponse {
    (
        [
            ("Content-Type", "text/plain"),
            ("X-Content-Type-Options", "nosniff"),
        ],
        req.challenge.clone()
    )
}

#[derive(Deserialize)]
struct Accounts {
    accounts: Vec<String>,
}

#[derive(Deserialize)]
struct Notification {
    list_folder: Accounts
}

async fn capture_event(Json(req): Json<Notification>) -> impl IntoResponse {
    let accounts = req.list_folder.accounts
        .into_iter()
        .map(|a| a.split_once(":").unwrap_or_default().1.to_string())
        .collect();

    capture_event_inner(accounts).await
        .unwrap_or_else(|e| println!("capture_event error: {}", e));

    StatusCode::OK
}

async fn capture_event_inner(_accounts: Vec<String>) -> Result<(), String> {
    todo!();
}

async fn actions() -> impl IntoResponse {
    let actions = serde_json::json!({
        "list": [
            {
                "field": "To upload a file",
                "value": "upload_file",
                "desc": "This connector takes the return value of the flow function, and uploads it to the connected Dropbox API. It corresponds to the upload event in Dropbox API."
            }
        ]
    });
    Json(actions)
}

async fn events() -> impl IntoResponse {
    let events = serde_json::json!({
        "list": [
            {
                "field": "Received a file",
                "value": "file_uploaded",
                "desc": "This connector is triggered when a new file is uploaded to the connected Dropbox. It corresponds to the upload event in Dropbox API."
            }
        ]
    });
    Json(events)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", get(auth))
        .route("/refresh", post(refresh))
        .route("/post", put(upload))
        .route("/actions", post(actions))
        .route("/events", post(events))
        .route("/webhook", get(webhook_challenge).post(capture_event));

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
