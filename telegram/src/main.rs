use axum::{
    extract::{Json, Query},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use reqwest::{Client, ClientBuilder, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use std::{collections::HashMap, env};
use std::{fmt::Display, net::SocketAddr};

const TIMEOUT: u64 = 120;

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    static ref HAIKU_AUTH_TOKEN: String =
        env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
    static ref TELEGRAM_BOT_TOKEN: String =
        env::var("TELEGRAM_BOT_TOKEN").expect("Env var TELEGRAM_BOT_TOKEN not set");
    static ref TELEGRAM_BOT_NAME: String =
        env::var("TELEGRAM_BOT_NAME").expect("Env var TELEGRAM_BOT_NAME not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref CONNECT_HTML: String =
        include_str!("./connect.html").replace("{TELEGRAM_BOT_NAME}", &*TELEGRAM_BOT_NAME);
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
    id: String,
    name: String,
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    let location = format!(
        "{}/api/connected?authorId={}&authorName={}&authorState=none",
        HAIKU_API_PREFIX.as_str(),
        auth_body.id,
        auth_body.name
    );

    (StatusCode::FOUND, [("Location", location)])
}

fn bot_api<U: AsRef<str>>(method: Method, uri: U) -> RequestBuilder {
    HTTP_CLIENT.request(
        method,
        format!(
            "https://api.telegram.org/bot{}{}",
            &*TELEGRAM_BOT_TOKEN,
            uri.as_ref()
        ),
    )
}

#[derive(Deserialize)]
struct RouteItem {
    // field: String,
    value: String,
}

#[derive(Deserialize)]
struct Route {
    action: Vec<RouteItem>,
}

#[derive(Deserialize)]
struct HaikuReqBody {
    // user: String,
    text: String,
    forwards: Route,
}

async fn post_msg(req: Json<HaikuReqBody>) -> Result<(), (StatusCode, String)> {
    let action = &req
        .forwards
        .action
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing action item".to_string()))?
        .value;

    let response = match action.as_str() {
        "send" => bot_api(Method::POST, "/sendMessage"),
        "edit" => bot_api(Method::POST, "/editMessageText"),
        "ban" => bot_api(Method::POST, "/banChatMember"),
        _ => return Err((StatusCode::BAD_REQUEST, "Unsupported action".to_string())),
    }
    .header(header::CONTENT_TYPE, "application/json")
    .body(req.text.to_owned())
    .send()
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match response.status().is_success() {
        true => Ok(()),
        false => Err((response.status(), response.text().await.unwrap_or_default())),
    }
}

async fn connect() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/html; charset=utf-8")],
        CONNECT_HTML.as_str(),
    )
}

#[derive(Deserialize)]
struct ApiResult<R> {
    // ok: bool,
    #[serde(bound(deserialize = "R: Deserialize<'de>"))]
    result: R,
}

#[derive(Deserialize)]
struct Member {
    user: User,
    status: String,
}

#[derive(Deserialize)]
struct User {
    id: i64,
}

async fn get_chat_owner<C: Display>(chat_id: C) -> Result<User, String> {
    bot_api(
        Method::GET,
        format!("/getChatAdministrators?chat_id={chat_id}"),
    )
    .send()
    .await
    .map_err(|e| e.to_string())?
    .json::<ApiResult<Vec<Member>>>()
    .await
    .map_err(|e| e.to_string())?
    .result
    .into_iter()
    .find(|member| member.status.eq("creator"))
    .ok_or("Can not find owner".to_string())
    .map(|member| member.user)
}

#[derive(Deserialize)]
struct WebhookPayload {
    #[serde(rename = "update_id")]
    _update_id: i64,
    #[serde(flatten)]
    event: HashMap<String, Value>,
}

async fn capture_event(
    payload: Json<WebhookPayload>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    headers
        .get("X-Telegram-Bot-Api-Secret-Token")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .eq(&*TELEGRAM_BOT_NAME)
        .then_some(())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if let Err(e) = capture_event_inner(
        payload
            .event
            .to_owned()
            .into_iter()
            .next()
            .ok_or(StatusCode::BAD_REQUEST)?,
    )
    .await
    {
        println!("capture event error: {}", e);
    }

    Ok(StatusCode::OK)
}

#[derive(Deserialize, Debug)]
struct Chat {
    id: i64,
    r#type: String,
}

#[derive(Deserialize, Debug)]
struct SupportedEvent {
    chat: Chat,
}

async fn capture_event_inner(event: (String, Value)) -> Result<(), String> {
    let chat = match serde_json::from_value::<SupportedEvent>(event.1.clone()) {
        Ok(c) => c.chat,
        Err(_) => return Ok(()),
    };

    let user = match chat.r#type.as_str() {
        "private" => chat.id,
        _ => {
            get_chat_owner(chat.id)
                .await
                .map_err(|e| format!("get_chat_owner failed: {}", e.to_string()))?
                .id
        }
    }
    .to_string();

    post_event_to_haiku(
        user,
        json!({ event.0.clone(): event.1 }).to_string(),
        [("event", event.0)],
    )
    .await
}

async fn post_event_to_haiku<
    U: Into<String>,
    T: Into<String>,
    TK: Into<String>,
    TV: Into<String>,
    TRI: IntoIterator<Item = (TK, TV)>,
>(
    user: U,
    text: T,
    triggers: TRI,
) -> Result<(), String> {
    let response = HTTP_CLIENT
        .post(format!("{}/api/_funcs/_post", HAIKU_API_PREFIX.as_str()))
        .header(header::AUTHORIZATION, HAIKU_AUTH_TOKEN.as_str())
        .json(&json!({
            "user": user.into(),
            "text": text.into(),
            "triggers": triggers
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect::<HashMap<_, _>>()
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to post event to haiku: {}", e.to_string()))?;

    match response.status().is_success() {
        true => Ok(()),
        false => Err(format!(
            "Failed to post event to haiku: {}",
            response.text().await.unwrap_or_default()
        )),
    }
}

async fn actions() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "Send a text message",
                "value": "send"
            },
            {
                "field": "Edit a text message",
                "value": "edit"
            },
            {
                "field": "Ban a user in a chat",
                "value": "ban"
            }
        ]
    }))
}

async fn events() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "New incoming message",
                "value": "message",
                "desc": "New incoming message of any kind - text, photo, sticker, etc."
            },
            {
                "field": "New version of a edited message",
                "value": "edited_message",
                "desc": "New version of a message that is known to the bot and was edited."
            },
            {
                "field": "New incoming channel post",
                "value": "channel_post",
                "desc": "New incoming channel post of any kind - text, photo, sticker, etc."
            },
            {
                "field": "New version of a edited channel post",
                "value": "edited_channel_post",
                "desc": "New version of a channel post that is known to the bot and was edited"
            },
            {
                "field": "Bot's chat member status was updated in a chat",
                "value": "my_chat_member",
                "desc": "The bot's chat member status was updated in a chat. For private chats, this update is received only when the bot is blocked or unblocked by the user."
            },
            {
                "field": "A chat member's status was updated in a chat",
                "value": "chat_member",
                "desc": "A chat member's status was updated in a chat. The bot must be an administrator in the chat."
            },
            {
                "field": "A request to join the chat has been sent",
                "value": "chat_join_request",
                "desc": "A request to join the chat has been sent."
            },
        ]
    }))
}

async fn init_webhook() -> Result<(), String> {
    let response = bot_api(
        Method::POST,
        format!(
            "/setWebhook?url={}/webhook&secret_token={}&drop_pending_updates=true",
            &*SERVICE_API_PREFIX, &*TELEGRAM_BOT_NAME
        ),
    )
    .send()
    .await
    .map_err(|e| format!("setWebhook failed: {}", e.to_string()))?;

    match response.status().is_success() {
        true => Ok(()),
        false => Err(format!(
            "setWebhook failed: {}",
            response.text().await.unwrap_or_default()
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/auth", get(auth))
        .route("/connect", get(connect))
        .route("/post", post(post_msg))
        .route("/actions", post(actions))
        .route("/events", post(events))
        .route("/webhook", post(capture_event));

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    init_webhook().await?;

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
