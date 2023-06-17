use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use oauth1::Token;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{header, Client, ClientBuilder};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{borrow::Cow, collections::HashMap, env, net::SocketAddr, time::Duration};

const TIMEOUT: u64 = 120;

const RSA_BITS: usize = 2048;

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    static ref HAIKU_AUTH_TOKEN: String =
        env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env variable SERVICE_API_PREFIX not set");
    static ref TWITTER_CONSUMER: Token<'static> = Token::new(
        env::var("TWITTER_CONSUMER_KEY").expect("Env variable TWITTER_CONSUMER_KEY not set"),
        env::var("TWITTER_CONSUMER_SECRET").expect("Env variable TWITTER_CONSUMER_SECRET not set")
    );
    static ref TWITTER_BEARER_TOKEN: String =
        env::var("TWITTER_BEARER_TOKEN").expect("Env variable TWITTER_BEARER_TOKEN not set");
    static ref ACCESS_TOKEN: String =
        env::var("ACCESS_TOKEN").expect("Env variable ACCESS_TOKEN not set");
    static ref ACCESS_TOKEN_SECRET: String =
        env::var("ACCESS_TOKEN_SECRET").expect("Env variable ACCESS_TOKEN_SECRET not set");
    static ref ENV_NAME: String = env::var("ENV_NAME").expect("Env variable ENV_NAME not set");
    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref DEV_ACCESS_TOKEN: Token<'static> = Token::new(&*ACCESS_TOKEN, &*ACCESS_TOKEN_SECRET);
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

#[derive(Deserialize)]
struct Session {
    flows_auth_session: String,
}

async fn connect(query: Query<Session>) -> impl IntoResponse {
    let params = [(
        "oauth_callback",
        format!(
            "{}/auth?session_id={}",
            *SERVICE_API_PREFIX, query.flows_auth_session
        ),
    )];

    let tokens = HTTP_CLIENT
        .post("https://api.twitter.com/oauth/request_token")
        .query(&params)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            oauth1::authorize(
                "POST",
                "https://api.twitter.com/oauth/request_token",
                &*TWITTER_CONSUMER,
                None,
                Some(
                    params
                        .into_iter()
                        .map(|item| (item.0, Cow::from(item.1)))
                        .collect(),
                ),
            ),
        )
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .bytes()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .and_then(|b| {
            serde_urlencoded::from_bytes::<AuthBody>(&b)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        })?;

    if tokens.oauth_token.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Parse OAuth body failed".to_string(),
        ));
    }

    let location = format!(
        "https://api.twitter.com/oauth/authorize?oauth_token={}",
        tokens.oauth_token
    );

    Ok((StatusCode::FOUND, [("Location", location)]))
}

#[derive(Serialize, Deserialize)]
struct AuthBody {
    oauth_token: String,
    oauth_token_secret: Option<String>,
    oauth_verifier: Option<String>,
    session_id: Option<String>,
}

async fn auth(req: Query<AuthBody>) -> impl IntoResponse {
    if req.oauth_token.is_empty() || req.oauth_verifier.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing oauth_token or oauth_verifier".to_string(),
        ));
    }

    let at = get_access_token(&req)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    let person = get_authed_user(&at)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    post_authorized_state(
        req.session_id
            .as_ref()
            .ok_or((StatusCode::BAD_REQUEST, "Missing session_id".to_string()))?,
        &person.id,
        &person.name,
        encrypt(&serde_json::to_string(&at).unwrap()),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html")],
        "<body><script>
            window.close();
        </script></body>",
    ))
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

    let auth = serde_urlencoded::from_bytes::<AuthBody>(&body).map_err(|e| e.to_string())?;

    if auth.oauth_token.is_empty() || auth.oauth_token_secret.is_none() {
        return Err("Failed to get access token".to_string());
    }

    Ok(auth)
}

#[derive(Deserialize)]
struct User {
    data: UserData,
}

#[derive(Deserialize)]
struct UserData {
    id: String,
    name: String,
}

async fn get_authed_user(access_token: &AuthBody) -> Result<UserData, String> {
    HTTP_CLIENT
        .get("https://api.twitter.com/2/users/me")
        .header(
            header::AUTHORIZATION,
            oauth1::authorize(
                "GET",
                "https://api.twitter.com/2/users/me",
                &*TWITTER_CONSUMER,
                Some(&Token::new(
                    access_token.oauth_token.clone(),
                    access_token.oauth_token_secret.clone().unwrap(),
                )),
                None,
            ),
        )
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

#[derive(Default, Deserialize)]
struct RouteItem {
    // field: String,
    value: String,
}

#[derive(Default, Deserialize)]
struct Routes {
    #[serde(default)]
    action: Vec<RouteItem>,
}

#[derive(Deserialize)]
struct HaikuReqBody {
    user: String,
    state: String,
    text: Option<String>,
    #[serde(default)]
    forwards: Routes,
}

async fn post_msg(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let action = &req
        .forwards
        .action
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing action item".to_string()))?
        .value;

    let text = req
        .text
        .clone()
        .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?;

    let auth = serde_json::from_str::<AuthBody>(&decrypt(&req.state))
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    if auth.oauth_token.is_empty() || auth.oauth_token_secret.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing oauth_token or oauth_token_secret".to_string(),
        ));
    }

    match action.as_str() {
        "create-tweet" => HTTP_CLIENT
            .post("https://api.twitter.com/2/tweets")
            .header(
                header::AUTHORIZATION,
                oauth1::authorize(
                    "POST",
                    "https://api.twitter.com/2/tweets",
                    &*TWITTER_CONSUMER,
                    Some(&Token::new(
                        auth.oauth_token,
                        auth.oauth_token_secret.unwrap(),
                    )),
                    None,
                ),
            )
            .json(&json!({ "text": text }))
            .send()
            .await
            .map(|_| ())
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Create tweet failed".to_string(),
                )
            }),
        _ => Err((StatusCode::BAD_REQUEST, "Unsupport action".to_string())),
    }
}

#[derive(Deserialize)]
struct CrcRequest {
    crc_token: String,
}

async fn webhook_challenge(req: Query<CrcRequest>) -> impl IntoResponse {
    let sha256_hash =
        hmac_sha256::HMAC::mac(TWITTER_CONSUMER.secret.as_bytes(), req.crc_token.as_bytes());

    (
        StatusCode::OK,
        Json(json!({
             "response_token": format!("{}", base64::encode(&sha256_hash)),
        })),
    )
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
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
    let hooks = HTTP_CLIENT
        .get("https://api.twitter.com/1.1/account_activity/all/webhooks.json")
        .header(
            header::AUTHORIZATION,
            oauth1::authorize(
                "GET",
                "https://api.twitter.com/1.1/account_activity/all/webhooks.json",
                &*TWITTER_CONSUMER,
                Some(&*DEV_ACCESS_TOKEN),
                None,
            ),
        )
        .send()
        .await?
        .json::<Webhooks>()
        .await?;

    Ok(hooks
        .environments
        .iter()
        .map(|e| e.webhooks.clone())
        .flatten()
        .collect::<Vec<Webhook>>())
}

async fn register_webhook() -> Result<Webhook, Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.twitter.com/1.1/account_activity/all/{}/webhooks.json",
        *ENV_NAME
    );

    let params = [("url", format!("{}/webhook", &*SERVICE_API_PREFIX))];

    HTTP_CLIENT
        .post(url.clone())
        .query(&params)
        .header(
            header::AUTHORIZATION,
            oauth1::authorize(
                "POST",
                &url,
                &*TWITTER_CONSUMER,
                Some(&*DEV_ACCESS_TOKEN),
                Some(
                    params
                        .into_iter()
                        .map(|item| (item.0, Cow::from(item.1)))
                        .collect(),
                ),
            ),
        )
        .send()
        .await?
        .json::<Webhook>()
        .await
        .map_err(Into::into)
}

async fn reenable_webhook(hook: &Webhook) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.twitter.com/1.1/account_activity/all/{}/webhooks/{}.json",
        *ENV_NAME, hook.id
    );

    HTTP_CLIENT
        .put(url.clone())
        .header(
            header::AUTHORIZATION,
            oauth1::authorize(
                "PUT",
                &url,
                &*TWITTER_CONSUMER,
                Some(&*DEV_ACCESS_TOKEN),
                None,
            ),
        )
        .send()
        .await?;

    Ok(())
}

async fn init_webhook() -> Result<(), String> {
    let hooks = fetch_webhooks()
        .await
        .map_err(|e| format!("fetch_webhooks failed: {}", e.to_string()))?;

    let hook = if let Some(hook) = hooks.first() {
        if !hook.valid {
            reenable_webhook(hook)
                .await
                .map_err(|e| format!("reenable_webhook failed: {}", e.to_string()))?;
        }
        hooks.into_iter().next().unwrap()
    } else {
        register_webhook()
            .await
            .map_err(|e| format!("register_webhook failed: {}", e.to_string()))?
    };

    println!("init_webhook success:\n{:#?}", hook);

    Ok(())
}

async fn events() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "Favorite",
                "value": "favorite_events"
            },
            {
                "field": "Follow",
                "value": "follow_events"
            },
            {
                "field": "Unfollow",
                "value": "unfollow_events"
            },
            {
                "field": "Block",
                "value": "block_events"
            },
            {
                "field": "Unblock",
                "value": "unblock_events"
            },
            {
                "field": "Mute",
                "value": "mute_events"
            },
            {
                "field": "Unmute",
                "value": "unmute_events"
            },
            {
                "field": "Direct message",
                "value": "direct_message_events"
            },
            {
                "field": "Tweet delete",
                "value": "tweet_delete_events"
            },
        ]
    }))
}

async fn subscribe(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let url = format!(
        "https://api.twitter.com/1.1/account_activity/all/{}/subscriptions.json",
        *ENV_NAME
    );

    let auth = serde_json::from_str::<AuthBody>(&req.state)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    HTTP_CLIENT
        .post(url.clone())
        .header(
            header::AUTHORIZATION,
            oauth1::authorize(
                "POST",
                &url,
                &*TWITTER_CONSUMER,
                Some(&Token::new(
                    auth.oauth_token,
                    auth.oauth_token_secret.unwrap(),
                )),
                None,
            ),
        )
        .send()
        .await
        .map(|_| {
            Json(json!({
                "revoke": format!("{}/unsubscribe?user_id={}", *SERVICE_API_PREFIX, req.user),
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[derive(Deserialize)]
struct UnsubscribeReq {
    user_id: String,
}

async fn unsubscribe(req: Json<UnsubscribeReq>) -> impl IntoResponse {
    let url = format!(
        "https://api.twitter.com/1.1/account_activity/all/{}/subscriptions/{}.json",
        *ENV_NAME, req.user_id
    );

    HTTP_CLIENT
        .delete(url.clone())
        .header(
            header::AUTHORIZATION,
            oauth1::authorize(
                "DELETE",
                &url,
                &*TWITTER_CONSUMER,
                Some(&*DEV_ACCESS_TOKEN),
                None,
            ),
        )
        .send()
        .await
        .map(|_| (StatusCode::OK, "OK".to_string()))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Payload {
    for_user_id: String,
    user_has_blocked: Option<bool>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

async fn capture_event(req: Json<Payload>) -> impl IntoResponse {
    tokio::spawn(async move {
        if let Err(e) = capture_event_inner(&req).await {
            println!("{}", e.to_string());
        }
    });

    StatusCode::OK
}

async fn capture_event_inner(payload: &Payload) -> Result<(), String> {
    let event = payload
        .extra
        .iter()
        .find(|(name, _)| name.as_str().ne("users"))
        .ok_or("Invalid event".to_string())?
        .0;

    post_event_to_haiku(
        &payload.for_user_id,
        event,
        serde_json::to_string(&payload.extra).unwrap(),
    )
    .await
}

async fn post_authorized_state<SE, I, N, ST>(
    session_id: SE,
    id: I,
    name: N,
    state: ST,
) -> Result<(), String>
where
    SE: Into<String>,
    I: Into<String>,
    N: Into<String>,
    ST: Into<String>,
{
    let response = HTTP_CLIENT
        .post(format!(
            "{}/api/_connectings/_authorized",
            &*HAIKU_API_PREFIX
        ))
        .header(header::AUTHORIZATION, &*HAIKU_AUTH_TOKEN)
        .json(&json!({
            "sessionId": session_id.into(),
            "authorId": id.into(),
            "authorName": name.into(),
            "authorState": state.into(),
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    match response.status().is_success() {
        true => Ok(()),
        false => Err(response.text().await.unwrap_or_default()),
    }
}

async fn post_event_to_haiku<I: Into<String>, E: Into<String>, B: Into<String>>(
    id: I,
    event_type: E,
    event_body: B,
) -> Result<(), String> {
    let body = json!({
        "user": id.into(),
        "text": event_body.into(),
        "triggers": {
            "event": event_type.into(),
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
        false => Err(response.text().await.unwrap_or_default()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/auth", get(auth))
        .route("/actions", post(actions))
        .route("/post", post(post_msg))
        .route("/connect", get(connect))
        .route("/webhook", get(webhook_challenge).post(capture_event))
        .route("/events", post(events))
        .route("/subscribe", get(subscribe))
        .route("/unsubscribe", get(unsubscribe));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    if let Err(e) = init_webhook().await {
        eprintln!("init_webhook failed: {}", e);
    }

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
