use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router
};
use oauth1::Token;
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder, header};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::Mutex,
    time::Duration, borrow::Cow,
};

const TIMEOUT: u64 = 120;

const RSA_BITS: usize = 2048;

lazy_static! {
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    // static ref REACTOR_AUTH_TOKEN: String =
    //     env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
    static ref CONNECTOR_DOMAIN: String = env::var("CONNECTOR_DOMAIN")
        .expect("Env variable CONNECTOR_DOMAIN not set");       // eg. https://twitter.reactor.io or https://localhost:8090
        
    static ref TWITTER_APP_ID: String = env::var("TWITTER_APP_ID")
        .expect("Env variable TWITTER_APP_ID not set");
    static ref TWITTER_CONSUMER: Token<'static> = Token::new(
        env::var("TWITTER_CONSUMER_KEY").expect("Env variable TWITTER_CONSUMER_KEY not set"),
        env::var("TWITTER_CONSUMER_SECRET").expect("Env variable TWITTER_CONSUMER_SECRET not set"));
    static ref TWITTER_BEARER_TOKEN: String = env::var("TWITTER_BEADER_TOKEN")
        .expect("Env variable TWITTER_BEADER_TOKEN not set");

    static ref DEV_ACCESS_TOKEN: Token<'static> = Token::new(
        env::var("ACCESS_TOKEN").expect("Env variable ACCESS_TOKEN not set"),
        env::var("ACCESS_TOKEN_SECRET").expect("Env variable ACCESS_TOKEN_SECRET not set"));

    static ref ACCESS_TOKEN: String = env::var("ACCESS_TOKEN")
        .expect("Env variable ACCESS_TOKEN not set");           // Dev access token
    static ref ACCESS_TOKEN_SECRET: String = env::var("ACCESS_TOKEN_SECRET")
        .expect("Env variable ACCESS_TOKEN_SECRET not set");    // Dev access token secret

    static ref TWITTER_WEBHOOK_ID: Mutex<String> = Mutex::new(String::new());

    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIVATE_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUBLIC_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIVATE_KEY);
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
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

fn decrypt(data: &str) -> String {
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

#[derive(Serialize, Deserialize)]
struct AuthBody {
    oauth_token: String,
    oauth_token_secret: Option<String>,
    oauth_verifier: Option<String>,
}

async fn auth(req: Query<AuthBody>) -> impl IntoResponse {
    if req.oauth_token.is_empty() || req.oauth_verifier.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Missing oauth_token or oauth_verifier".to_string()));
    }

    let at = get_access_token(&req).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let person = get_authed_user(&at).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let location = format!(
        "{}/api/connected?authorId={}&authorName={}&authorState={}",
        REACTOR_API_PREFIX.as_str(),
        person.id,
        urlencoding::encode(&person.name),
        encrypt(&serde_json::to_string(&at).unwrap()),
    );

    Ok((StatusCode::OK, [("Location", location)]))
}

async fn get_access_token(auth: &AuthBody) -> Result<AuthBody, String> {
    let params = [
        ("oauth_token", auth.oauth_token.clone()),
        ("oauth_verifier", auth.oauth_verifier.clone().unwrap()),
    ];

    let body = HTTP_CLIENT
        .post("https://api.twitter.com/oauth/access_token")
        .query(&params)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;

    let auth = serde_urlencoded::from_bytes::<AuthBody>(&body)
        .map_err(|e| e.to_string())?;

    if auth.oauth_token.is_empty() || auth.oauth_token_secret.is_none() {
        return Err("Failed to get access token".to_string());
    }

    Ok(auth)
}

#[derive(Deserialize)]
struct User {
    data: UserData
}

#[derive(Deserialize)]
struct UserData {
    id: String,
    name: String,
}

async fn get_authed_user(access_token: &AuthBody) -> Result<UserData, String> {
    HTTP_CLIENT
        .get("https://api.twitter.com/2/users/me")
        .header(header::AUTHORIZATION,
            oauth1::authorize("GET", "https://api.twitter.com/2/users/me",
            &*TWITTER_CONSUMER,
            Some(&Token::new(access_token.oauth_token.clone(), 
                access_token.oauth_token_secret.clone().unwrap())),
            None))
        .send()
        .await
        .map_err(|_| "Failed to get user's profile".to_string())?

        .json::<User>()
        .await
        .map(|u| u.data)
        .map_err(|e| e.to_string())
}

async fn actions() -> impl IntoResponse {
    let events = serde_json::json!({
        "list": [
            {
                "field": "Create Tweet",
                "value": "create-tweet"
            }
        ]
    });
    Json(events)
}

#[derive(Debug, Deserialize, Serialize)]
struct ForwardRoute {
    route: String,
    value: String,
}

#[derive(Deserialize)]
struct PostBody {
    // user: String,
    text: String,
    state: String,
    forwards: Vec<ForwardRoute>,
}

async fn post_msg(msg_body: Json<PostBody>) -> impl IntoResponse {
    let routes = msg_body
        .forwards
        .iter()
        .map(|route| (route.route.clone(), route.value.clone()))
        .collect::<HashMap<String, String>>();

    let action = routes.get("action")
        .ok_or((StatusCode::BAD_REQUEST, "Missing action".to_string()))?;

    let auth = serde_json::from_str::<AuthBody>(&decrypt(&msg_body.state))
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    if auth.oauth_token.is_empty() || auth.oauth_token_secret.is_none() {
        return Err((StatusCode::BAD_REQUEST,
            "Missing oauth_token or oauth_token_secret".to_string()));
    }

    match action.as_str() {
        "create-tweet" => {
            HTTP_CLIENT
                .post("https://api.twitter.com/2/tweets")
                .header(header::AUTHORIZATION,
                    oauth1::authorize("GET",
                    "https://api.twitter.com/2/tweets",
                    &*TWITTER_CONSUMER,
                    Some(&Token::new(auth.oauth_token, auth.oauth_token_secret.unwrap())),
                    None))
                .json(&serde_json::json!({
                    "text": msg_body.text
                }))
                .send()
                .await

                .map(|_| (StatusCode::OK, "OK".to_string()))
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Create tweet failed".to_string()))
        }
        _ => Err((StatusCode::BAD_REQUEST, "Unsupport action".to_string())),
    }
}

#[derive(Deserialize)]
struct CrcRequest {
    crc_token: String,
}

async fn webhook_challenge(req: Query<CrcRequest>) -> impl IntoResponse {
    let sha256_hash = hmac_sha256::HMAC::mac(
        TWITTER_CONSUMER.secret.as_bytes(), req.crc_token.as_bytes());

    (StatusCode::OK, Json(json!({
         "response_token": format!("{}", base64::encode(&sha256_hash)),
    })))
}

async fn login() -> impl IntoResponse {
    let params = [("oauth_callback", format!("{}/auth", *CONNECTOR_DOMAIN))];

    let body = HTTP_CLIENT
        .post("https://api.twitter.com/oauth/request_token")
        .query(&params)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION,
            oauth1::authorize("POST", 
            "https://api.twitter.com/oauth/request_token",
            &*TWITTER_CONSUMER, None, Some(
                params
                .into_iter()
                .map(|item| (item.0, Cow::from(item.1))).collect())))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?

        .bytes()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tokens = serde_urlencoded::from_bytes::<AuthBody>(&body)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if tokens.oauth_token.is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Parse OAuth body failed".to_string()));
    }

    let location = format!(
        "https://api.twitter.com/oauth/authorize?oauth_token={}",
        tokens.oauth_token);

    Ok((StatusCode::FOUND, [("Location", location)]))
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Webhook {
    id: String,
    url: String,
    valid: bool,
    created_at: String,
}

#[derive(Deserialize)]
struct Environment {
    webhooks: Vec<Webhook>,
}

#[derive(Deserialize)]
struct Webhooks {
    environments: Vec<Environment>,
}

async fn fetch_webhooks() -> Result<Vec<Webhook>, Box<dyn std::error::Error>> {
    let json = HTTP_CLIENT
        .get("https://api.twitter.com/1.1/account_activity/all/webhooks.json")
        .bearer_auth(&*TWITTER_BEARER_TOKEN)
        .send()
        .await?
        .json::<Webhooks>()
        .await?;

    let mut ret = Vec::new();

    for env in json.environments {
        for hook in env.webhooks {
            ret.push(hook);
        }
    }

    Ok(ret)
}

async fn register_webhook() -> Result<Webhook, Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.twitter.com/1.1/account_activity/all/{}/webhooks.json",
        *TWITTER_APP_ID);

    let params = [("url", format!("{}/crc", &*CONNECTOR_DOMAIN))];

    let response = HTTP_CLIENT
        .post(url.clone())
        .query(&params)
        .header(header::AUTHORIZATION,
            oauth1::authorize("POST",
                &url,
                &*TWITTER_CONSUMER,
                Some(&*DEV_ACCESS_TOKEN),
                Some(
                    params
                    .into_iter()
                    .map(|item| (item.0, Cow::from(item.1))).collect())))
        .send()
        .await?;

    Ok(response.json::<Webhook>().await?)
}

async fn reenable_webhook(hook: &Webhook) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.twitter.com/1.1/account_activity/all/{}/webhooks/{}.json",
        *TWITTER_APP_ID, hook.id);

    HTTP_CLIENT
        .put(url.clone())
        .header(header::AUTHORIZATION,
            oauth1::authorize("PUT",
                &url,
                &*TWITTER_CONSUMER,
                Some(&*DEV_ACCESS_TOKEN),
                None))
        .send()
        .await?;

    Ok(())
}

async fn init_webhook() -> Result<(), Box<dyn std::error::Error>> {
    let hooks = fetch_webhooks().await?;

    let hook = if hooks.is_empty() {
        register_webhook().await?
    } else {
        let hook = hooks.first().unwrap();
        if !hook.valid {
            reenable_webhook(hook).await?;
        }
        hooks.into_iter().next().unwrap()
    };

    println!("{:#?}", hook);
    *TWITTER_WEBHOOK_ID.lock()? = hook.id;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/auth", get(auth))
        .route("/actions", post(actions))
        .route("/post", post(post_msg))
        .route("/login", get(login))

        .route("/crc", get(webhook_challenge));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    init_webhook().await?;

    Ok(())
}
