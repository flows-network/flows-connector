use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router, Server,
};
use lazy_static::lazy_static;
use openssl::rsa::{Padding, Rsa};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, time::Duration};
use urlencoding::encode;

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    static ref GOOGLE_APP_REDIRECT_URL: String =
        env::var("GOOGLE_APP_REDIRECT_URL").expect("Env variable GOOGLE_APP_REDIRECT_URL not set");
    static ref GOOGLE_APP_CLIENT_ID: String =
        env::var("GOOGLE_APP_CLIENT_ID").expect("Env variable GOOGLE_APP_CLIENT_ID not set");
    static ref GOOGLE_APP_CLIENT_SECRET: String = env::var("GOOGLE_APP_CLIENT_SECRET")
        .expect("Env variable GOOGLE_APP_CLIENT_SECRET not set");
    static ref PASSPHRASE: String =
        env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
    static ref PUBLIC_KEY_PEM: String =
        env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
    static ref PRIVATE_KEY_PEM: String =
        env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}
#[derive(Deserialize, Serialize)]
struct AuthBody {
    code: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AccessTokenBody {
    access_token: String,
    refresh_token: Option<String>,
    id_token: String,
}

#[derive(Debug, Deserialize)]
struct GoogleEmail {
    email: String,
}

fn encrypt(data: String) -> String {
    let rsa = Rsa::public_key_from_pem(PUBLIC_KEY_PEM.as_bytes()).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1)
        .unwrap();
    hex::encode(buf)
}

fn decrypt(hex: String) -> String {
    let rsa =
        Rsa::private_key_from_pem_passphrase(PRIVATE_KEY_PEM.as_bytes(), PASSPHRASE.as_bytes())
            .unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    let l = rsa
        .private_decrypt(&hex::decode(hex).unwrap(), &mut buf, Padding::PKCS1)
        .unwrap();
    String::from_utf8(buf[..l].to_vec()).unwrap()
}

async fn auth<'a>(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.eq("") {
        Err((StatusCode::BAD_REQUEST, String::from("No code")))
    } else {
        match get_access_token(&auth_body.code).await {
            Ok(at) => {
                let google_email = get_google_email(&at.id_token).await;
                match google_email {
                    Ok(ge) => {
                        let location = format!(
                            "{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
                            REACTOR_API_PREFIX.as_str(),
                            encode(&ge.email),
                            encode(&ge.email),
                            encrypt(at.access_token),
                            encrypt(at.refresh_token.unwrap_or_default()),
                        );
                        Ok((StatusCode::FOUND, [("Location", location)]))
                    }
                    Err(failed_resp) => Err((StatusCode::INTERNAL_SERVER_ERROR, failed_resp)),
                }
            }
            Err(failed_resp) => Err((StatusCode::INTERNAL_SERVER_ERROR, failed_resp)),
        }
    }
}

async fn get_google_email(id_token: &str) -> Result<GoogleEmail, String> {
    let response = HTTP_CLIENT
        .get(format!(
            "https://oauth2.googleapis.com/tokeninfo?id_token={}",
            id_token
        ))
        .header("User-Agent", "Github Connector of Second State Reactor")
        .send()
        .await;

    match response {
        Ok(res) => {
            let body = res.json::<GoogleEmail>().await;
            match body {
                Ok(ge) => Ok(ge),
                Err(e) => Err(e.to_string()),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

async fn get_access_token(code: &str) -> Result<AccessTokenBody, String> {
    let params = [
        ("client_id", GOOGLE_APP_CLIENT_ID.as_str()),
        ("client_secret", GOOGLE_APP_CLIENT_SECRET.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", GOOGLE_APP_REDIRECT_URL.as_str()),
        ("code", &code),
    ];

    let response = HTTP_CLIENT
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await;
    match response {
        Ok(r) => {
            let token_body = r.json::<AccessTokenBody>().await;
            match token_body {
                Ok(at) => return Ok(at),
                Err(e) => {
                    return Err(e.to_string());
                }
            }
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }
}

#[derive(Deserialize, Serialize)]
struct PostBody {
    user: String,
    text: String,
    state: String,
}

async fn post_msg(Json(mb): Json<PostBody>) -> impl IntoResponse {
    let request = serde_json::json!({
        "raw": base64::encode(mb.text)
    });

    let response = HTTP_CLIENT
        .post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
        .bearer_auth(decrypt(mb.state))
        .json(&request)
        .send()
        .await;
    match response {
        Ok(_) => (StatusCode::OK, String::from("")),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct RefreshState {
    refresh_state: String,
}

async fn refresh_token(Json(rs): Json<RefreshState>) -> impl IntoResponse {
    let params = [
        ("client_id", (*GOOGLE_APP_CLIENT_ID).as_str()),
        ("client_secret", (*GOOGLE_APP_CLIENT_SECRET).as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", &decrypt(rs.refresh_state)),
    ];

    let response = HTTP_CLIENT
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await;
    match response {
        Ok(r) => {
            let token_body = r.json::<AccessTokenBody>().await;
            match token_body {
                Ok(at) => (StatusCode::OK, encrypt(at.access_token)),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/auth", get(auth))
        .route("/post", post(post_msg))
        .route("/refresh", post(refresh_token));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
