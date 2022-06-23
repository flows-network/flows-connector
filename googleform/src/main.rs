use axum::{extract::Query, http::header, response::IntoResponse, routing::get, Router};
use lazy_static::lazy_static;
use openssl::rsa::{Padding, Rsa};
use reqwest::{Client, ClientBuilder, Proxy, StatusCode};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, time::Duration};

lazy_static! {
    static ref PUBLIC_KEY_PEM: String =
        env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
    code: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct GithubUser {
    id: Option<String>,
    email: Option<String>,
    verified_email: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
    locale: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OAuthAccessBody {
    expires_in: Option<u32>,
    access_token: Option<String>,
    token_type: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}

fn encrypt(data: String) -> String {
    let rsa = Rsa::public_key_from_pem(PUBLIC_KEY_PEM.as_bytes()).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1)
        .unwrap();
    hex::encode(buf)
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.eq("") {
        Err((StatusCode::BAD_REQUEST, "No code".to_string()))
    } else {
        match get_access_token(&auth_body.code).await {
            Ok(at) => match get_authed_user(&at.access_token.clone().unwrap()).await {
                Ok(gu) => {
                    let location = format!(
                        "{}/api/connected?authorId={}&authorName={}&authorState={}",
                        REACTOR_API_PREFIX.as_str(),
                        gu.id.unwrap(),
                        gu.name.unwrap(),
                        encrypt(at.access_token.unwrap())
                    );
                    Ok((StatusCode::FOUND, [("Location", location)]))
                }
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            },
            Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
        }
    }
}

const TIMEOUT: u64 = 120;

fn new_http_client() -> Client {
    let cb = ClientBuilder::new().timeout(Duration::from_secs(TIMEOUT));
    cb.build().unwrap()
}

async fn get_access_token(code: &str) -> Result<OAuthAccessBody, String> {
    let form_client_id = env::var("FORM_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
    let form_client_secret = env::var("FORM_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");
    let redirect_uri = env::var("FORM_APP_DIRECT_URI").expect("Env variable FORM_APP_DIRECT_URI not set");
    let params = [
        (
            "client_id",
            form_client_id.as_str()
        ),
        ("client_secret", form_client_secret.as_str()),
        ("code", &code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri.as_str()),
    ];

    let response = new_http_client()
        .post("https://accounts.google.com/o/oauth2/token")
        .form(&params)
        .send()
        .await;
    match response {
        Ok(r) => {
            let oauth_body = r.json::<OAuthAccessBody>().await;
            match oauth_body {
                Ok(at) => Ok(at),
                Err(_) => Err("Failed to get access token".to_string()),
            }
        }
        Err(a) => {
            println!("{:?}", a);
            Err("Failed to get access token".to_string())
        }
    }
}

async fn get_authed_user(access_token: &str) -> Result<GithubUser, String> {
    let Bearer = format!("Bearer {}", access_token);
    let response = new_http_client()
        .get("https://www.googleapis.com/oauth2/v1/userinfo")
        .header("Authorization", Bearer)
        .send()
        .await;
    println!("{:?}", response);
    match response {
        Ok(res) => match res.json::<GithubUser>().await {
            Ok(body) => Ok(body),
            Err(_) => Err("Failed to get user's profile".to_string()),
        },
        Err(a) => {
            println!("{:?}", a);
            Err("Failed to get user's profile".to_string())
        }
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/auth", get(auth));
    let port = env::var("PORT").unwrap_or_else(|_| "8091".to_string());
    let port: u16 = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
