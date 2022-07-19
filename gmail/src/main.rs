use actix_web::{web, App, HttpResponse, HttpServer, ResponseError};
use lazy_static::lazy_static;
use openssl::rsa::{Padding, Rsa};
use serde::{Deserialize, Serialize};
use std::env;
use urlencoding::encode;

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
}

const TIMEOUT: u64 = 120;

fn new_http_client() -> awc::Client {
    let connector = awc::Connector::new()
        .timeout(std::time::Duration::from_secs(TIMEOUT))
        .finish();
    return awc::ClientBuilder::default()
        .timeout(std::time::Duration::from_secs(TIMEOUT))
        .connector(connector)
        .finish();
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

async fn auth<'a>(auth_body: web::Query<AuthBody>) -> HttpResponse {
    if auth_body.code.eq("") {
        HttpResponse::BadRequest().body("No code")
    } else {
        match get_access_token(&auth_body.code).await {
            Ok(at) => {
                let google_email = get_google_email(&at.id_token).await;
                match google_email {
                    Ok(ge) => {
                        let location = format!(
                            "{}/api/connected?authorId={}&authorState={}&refreshState={}",
                            REACTOR_API_PREFIX.as_str(),
                            encode(&ge.email),
                            encrypt(at.access_token),
                            encrypt(at.refresh_token.unwrap_or_default()),
                        );
                        HttpResponse::Found().header("Location", location).finish()
                    }
                    Err(failed_resp) => failed_resp,
                }
            }
            Err(failed_resp) => failed_resp,
        }
    }
}

async fn get_google_email(id_token: &str) -> Result<GoogleEmail, HttpResponse> {
    let response = new_http_client()
        .get(format!(
            "https://oauth2.googleapis.com/tokeninfo?id_token={}",
            id_token
        ))
        .set_header("User-Agent", "Github Connector of Second State Reactor")
        .send()
        .await;

    match response {
        Ok(mut res) => {
            let body = res.json::<GoogleEmail>().await;
            match body {
                Ok(ge) => {
                    return Ok(ge);
                }
                Err(e) => {
                    return Err(e.error_response());
                }
            }
        }
        Err(e) => {
            return Err(e.error_response());
        }
    }
}

async fn get_access_token(code: &str) -> Result<AccessTokenBody, HttpResponse> {
    let params = [
        ("client_id", GOOGLE_APP_CLIENT_ID.as_str()),
        ("client_secret", GOOGLE_APP_CLIENT_SECRET.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", GOOGLE_APP_REDIRECT_URL.as_str()),
        ("code", &code),
    ];

    let response = new_http_client()
        .post("https://oauth2.googleapis.com/token")
        .send_form(&params)
        .await;
    match response {
        Ok(mut r) => {
            let token_body = r.json::<AccessTokenBody>().await;
            match token_body {
                Ok(at) => return Ok(at),
                Err(e) => {
                    return Err(e.error_response());
                }
            }
        }
        Err(e) => {
            return Err(e.error_response());
        }
    }
}

#[derive(Deserialize, Serialize)]
struct PostBody {
    user: String,
    text: String,
    state: String,
}

async fn post_msg(msg_body: web::Json<PostBody>) -> HttpResponse {
    let mb = msg_body.into_inner();

    let request = serde_json::json!({
        "raw": base64::encode(mb.text)
    });

    let response = new_http_client()
        .post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
        .header("Authorization", format!("Bearer {}", decrypt(mb.state)))
        .send_json(&request)
        .await;
    match response {
        Ok(_) => return HttpResponse::Ok().finish(),
        Err(e) => e.error_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RefreshState {
    refresh_state: String,
}

async fn refresh_token(msg_body: web::Json<RefreshState>) -> HttpResponse {
    let rs = msg_body.into_inner();
    let params = [
        ("client_id", (*GOOGLE_APP_CLIENT_ID).as_str()),
        ("client_secret", (*GOOGLE_APP_CLIENT_SECRET).as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", &decrypt(rs.refresh_state)),
    ];

    let response = new_http_client()
        .post("https://oauth2.googleapis.com/token")
        .send_form(&params)
        .await;
    match response {
        Ok(mut r) => {
            let token_body = r.json::<AccessTokenBody>().await;
            match token_body {
                Ok(at) => {
                    return HttpResponse::Ok().body(encrypt(at.access_token));
                }
                Err(e) => {
                    return e.error_response();
                }
            }
        }
        Err(e) => {
            return e.error_response();
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    HttpServer::new(|| {
        App::new()
            .route("/auth", web::get().to(auth))
            .route("/post", web::post().to(post_msg))
            .route("/refresh", web::post().to(refresh_token))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
