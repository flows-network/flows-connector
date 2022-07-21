use axum::{extract::Query, http::StatusCode, response::IntoResponse, routing::{get, post, delete}, Router, Json};
use lazy_static::lazy_static;
use openssl::rsa::{Padding, Rsa};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, net::SocketAddr};
use urlencoding::encode;
use reqwest::{Client, header};

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

    static ref HTTP_CLIENT: Client = Client::new();
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

async fn auth(auth_body: Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.eq("") {
        return Err((StatusCode::BAD_REQUEST, "No code".to_string()));
    }

    match get_access_token(&auth_body.code).await {
        Ok(at) => {
            match get_google_email(&at.id_token).await {
                Ok(ge) => {
                    let location = format!(
                        "{}/api/connected?authorId={}&authorState={}&refreshState={}",
                        REACTOR_API_PREFIX.as_str(),
                        encode(&ge.email),
                        encrypt(at.access_token),
                        encrypt(at.refresh_token.unwrap_or_default()),
                    );
                    Ok((StatusCode::FOUND, [("Location", location)]))
                }
                Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
            }
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

async fn get_google_email(id_token: &str) -> Result<GoogleEmail, String> {
    let response = HTTP_CLIENT
        .get(format!("https://oauth2.googleapis.com/tokeninfo?id_token={}", id_token))
        .header("User-Agent", "Github Connector of Second State Reactor")
        .send()
        .await;

    if let Ok(resp) = response {
        if let Ok(gmail) = resp.json::<GoogleEmail>().await {
            return Ok(gmail);
        }
    }

    Err("Get google email failed".to_string())
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

    if let Ok(r) = response {
        if let Ok(token_body) = r.json::<AccessTokenBody>().await {
            return Ok(token_body);
        }
    }

    Err("Failed to get access token".to_string())
}

#[derive(Debug, Deserialize)]
struct RefreshState {
    refresh_state: String,
}

async fn refresh_token(msg_body: Query<RefreshState>) -> impl IntoResponse {
    let params = [
        ("client_id", (*GOOGLE_APP_CLIENT_ID).as_str()),
        ("client_secret", (*GOOGLE_APP_CLIENT_SECRET).as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", &decrypt(msg_body.refresh_state.clone())),
    ];

    let response = HTTP_CLIENT
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await;

    if let Ok(resp) = response {
        if let Ok(at) = resp.json::<AccessTokenBody>().await {
            return Ok((StatusCode::FOUND, encrypt(at.access_token)));
        }
    }

    Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to refresh token".to_string()))
}

#[derive(Deserialize)]
struct PostBody {
    user: String,       // Gmail
    text: String,       // Form ID
    state: String,      // AccessToken
}

#[derive(Deserialize)]
struct TopicName {
    topicName: String,
}

#[derive(Deserialize)]
struct Topic {
    topic: TopicName,
}

#[derive(Deserialize)]
struct Watch {
    id: String,
    target: Topic,
    // eventType: String,
    // createTime: String,
    // expireTime: String,
    errorType: String,
    state: String,
}

// ref https://developers.google.cn/forms/api/reference/rest/v1beta/forms.watches/create
async fn create_watches(req: Json<PostBody>) -> impl IntoResponse {
    let create_body = json!({
        "watch": {
            "target": {
                "topic": {
                    "topicName": "google-form"      // TODO: Google PubSub topic name
                }
            },
            "eventType": "RESPONSES",   // A watch with this event type will be notified when form responses are submitted.
        },
    });

    let response = HTTP_CLIENT
        .post(format!("https://forms.googleapis.com/v1beta/forms/{}/watches", req.text))
        .header(header::USER_AGENT, "Github Connector of Second State Reactor")
        .header("Authorization", format!("Bearer {}", &decrypt(req.state.clone())))
        .json(&create_body)
        .send()
        .await;

    let watch = match response {
        Ok(resp) => {
            match resp.json::<Watch>().await {
                Ok(body) => body,
                Err(e) => { return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())); },
            }
        },
        Err(e) => { return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())); },
    };

    if watch.state != "ACTIVE" {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, 
            format!("Failed to create watch: Watch not actived: {}", watch.errorType)));
    }

    Ok((StatusCode::CREATED, Json(json!({
        "revoke": format!("{}/revoke-hook?hook_id={}", REACTOR_API_PREFIX.as_str(), watch.id),
    }))))
}

#[derive(Deserialize)]
struct RevokeQuery {
    hook_id: String,
}

// ref https://developers.google.cn/forms/api/reference/rest/v1beta/forms.watches/delete
async fn revoke_watches(
    query: Query<RevokeQuery>,
    body: Json<PostBody>,
) -> impl IntoResponse {
    let response = HTTP_CLIENT
        .delete(format!("https://forms.googleapis.com/v1beta/forms/{}/watches/{}",
            body.text, query.hook_id))
        .header(header::USER_AGENT, "Github Connector of Second State Reactor")
        .header("Authorization", format!("Bearer {}", &decrypt(body.state.clone())))
        .send()
        .await;

    match response {
        Ok(resp) if resp.status() == StatusCode::FOUND => Ok(StatusCode::FOUND),
        Ok(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// ref https://developers.google.cn/forms/api/reference/rest/v1beta/forms.watches/renew
async fn renew_watches(
    query: Query<RevokeQuery>,
    body: Json<PostBody>
) -> impl IntoResponse {
    let response = HTTP_CLIENT
        .post(format!(
            "https://forms.googleapis.com/v1beta/forms/{}/watches/{}:renew",
            body.text, query.hook_id))
        .header(header::USER_AGENT, "Github Connector of Second State Reactor")
        .header("Authorization", format!("Bearer {}", &decrypt(body.state.clone())))
        .send()
        .await;

    let watch = match response {
        Ok(resp) => {
            match resp.json::<Watch>().await {
                Ok(body) => body,
                Err(e) => { return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())); },
            }
        },
        Err(e) => { return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())); },
    };

    if watch.state != "ACTIVE" {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, 
            format!("Failed to renew watch: Watch not actived: {}", watch.errorType)));
    }

    Ok((StatusCode::CREATED, Json(json!({
        "revoke": format!("{}/revoke-hook?hook_id={}", REACTOR_API_PREFIX.as_str(), watch.id),
    }))))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    let app = Router::new()
        .route("/auth", get(auth))
        .route("/refresh", get(refresh_token))
        .route("/create-watches", post(create_watches))
        .route("/revoke-watches", delete(revoke_watches))

        // The watches should be renew every 7 days
        .route("/renew-watches", post(renew_watches));

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
