use std::{collections::HashMap, env, net::SocketAddr, time::Duration};

use axum::{
    async_trait,
    extract::{Json, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serenity::{
    http::Http as ApiClient,
    model::prelude::{ChannelId, ChannelType, GuildId, Message, MessageType, Ready},
    prelude::{Client as GatewayClient, Context, EventHandler, GatewayIntents},
};

const TIMEOUT: u64 = 120;

const RSA_BITS: usize = 2048;

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    static ref HAIKU_AUTH_TOKEN: String =
        env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
    static ref DISCORD_APP_CLIENT_ID: String =
        env::var("DISCORD_APP_CLIENT_ID").expect("Env variable DISCORD_APP_CLIENT_ID not set");
    static ref DISCORD_APP_APPLICATION_ID: u64 = DISCORD_APP_CLIENT_ID
        .parse()
        .expect("Invalid DISCORD_APP_CLIENT_ID");
    static ref DISCORD_APP_CLIENT_SECRET: String = env::var("DISCORD_APP_CLIENT_SECRET")
        .expect("Env variable DISCORD_APP_CLIENT_SECRET not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref BOT_TOKEN: String = env::var("BOT_TOKEN").expect("Env variable BOT_TOKEN not set");
    static ref SCOPES: String = urlencoding::encode("identify guilds bot").to_string();
    static ref REDIRECT_URL: String = format!("{}/auth", &*SERVICE_API_PREFIX);
    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIV_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
    static ref API_CLIENT: ApiClient = ApiClient::new(&*BOT_TOKEN);
}

fn encrypt(data: &str) -> String {
    hex::encode(
        PUB_KEY
            .encrypt(
                &mut CHACHA8RNG.clone(),
                PaddingScheme::new_pkcs1v15_encrypt(),
                data.as_bytes(),
            )
            .map_err(|e| println!("Failed to encrypt: {}", e.to_string()))
            .unwrap_or_default(),
    )
}

fn decrypt(data: &str) -> String {
    String::from_utf8(
        PRIV_KEY
            .decrypt(
                PaddingScheme::new_pkcs1v15_encrypt(),
                &hex::decode(data).unwrap(),
            )
            .map_err(|e| println!("Failed to decrypt: {}", e.to_string()))
            .unwrap_or_default(),
    )
    .unwrap_or_default()
}

async fn connect() -> impl IntoResponse {
    let location = format!(
        "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&scope={}&response_type=code&permissions=8",
        &*DISCORD_APP_CLIENT_ID,
        &*REDIRECT_URL,
        &*SCOPES
    );

    (StatusCode::FOUND, [(header::LOCATION, location)])
}

#[derive(Deserialize)]
struct AuthBody {
    code: String,
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    let at = get_access_token(
        [
            ("grant_type", "authorization_code"),
            ("code", &auth_body.code),
            ("redirect_uri", REDIRECT_URL.as_str()),
        ]
        .into_iter(),
    )
    .await
    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    get_authed_user(&at.access_token)
        .await
        .map(|user| {
            let location = format!(
                "{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
                HAIKU_API_PREFIX.as_str(),
                user.id,
                user.username,
                encrypt(&at.access_token),
                encrypt(&at.refresh_token)
            );

            (StatusCode::FOUND, [("Location", location)])
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Serialize, Deserialize)]
struct AccessToken {
    access_token: String,
    refresh_token: String,
}

async fn get_access_token<'a, T: IntoIterator<Item = (&'a str, &'a str)>>(
    p: T,
) -> Result<AccessToken, String> {
    let mut params = [
        ("client_id", DISCORD_APP_CLIENT_ID.as_str()),
        ("client_secret", DISCORD_APP_CLIENT_SECRET.as_str()),
    ]
    .into_iter()
    .collect::<HashMap<&str, &str>>();

    params.extend(p);

    HTTP_CLIENT
        .post("https://discord.com/api/oauth2/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<AccessToken>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct User {
    id: String,
    username: String,
}

#[derive(Deserialize)]
struct Account {
    user: User,
}

async fn get_authed_user<A: AsRef<str>>(access_token: A) -> Result<User, String> {
    HTTP_CLIENT
        .get("https://discord.com/api/oauth2/@me")
        .bearer_auth(access_token.as_ref())
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Account>()
        .await
        .map(|account| account.user)
        .map_err(|e| e.to_string())
}

#[derive(Deserialize, Default)]
struct RouteItem {
    // field: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct Routes {
    #[serde(default = "Vec::new")]
    guild: Vec<RouteItem>,
    #[serde(default = "Vec::new")]
    channel: Vec<RouteItem>,
}

#[derive(Deserialize)]
struct HaikuReqBody {
    // user: String,
    state: String,
    text: Option<String>,
    #[serde(default = "Routes::default")]
    routes: Routes,
    #[serde(default = "Routes::default")]
    forwards: Routes,
}

#[derive(Deserialize)]
struct OutboundData {
    content: String,
    reply_to: Option<Message>,
}

async fn post_msg(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let channel_id = req
        .forwards
        .channel
        .first()
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Invalid JSON data: Missing database".to_string(),
        ))?
        .value
        .parse::<u64>()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid channel id: {}", e.to_string()),
            )
        })?;

    let data = serde_json::from_str::<OutboundData>(
        &req.text
            .as_ref()
            .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?,
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid outbound data: {}", e.to_string()),
        )
    })?;

    match data.reply_to {
        Some(r) => r.reply(&*API_CLIENT, data.content).await,
        None => ChannelId(channel_id).say(&*API_CLIENT, data.content).await,
    }
    .map(|_| StatusCode::OK)
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[derive(Deserialize)]
struct RefreshState {
    refresh_state: String,
}

async fn refresh_token(Json(msg_body): Json<RefreshState>) -> impl IntoResponse {
    get_access_token(
        [
            ("grant_type", "refresh_token"),
            ("refresh_token", &decrypt(&msg_body.refresh_state)),
        ]
        .into_iter(),
    )
    .await
    .map(|at| {
        Json(json!({
            "access_state": encrypt(&at.access_token),
            "refresh_state": encrypt(&at.refresh_token)
        }))
    })
    .map_err(|e| (StatusCode::UNAUTHORIZED, e))
}

#[derive(Deserialize)]
struct Guild {
    id: String,
    name: String,
    owner: bool,
}

async fn guilds(req: Json<HaikuReqBody>) -> Result<Json<Value>, (StatusCode, String)> {
    let list = HTTP_CLIENT
        .get("https://discord.com/api/users/@me/guilds")
        .bearer_auth(decrypt(&req.state))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .json::<Vec<Guild>>()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .filter_map(|guild| {
            guild.owner.then_some(json!({
                "field": guild.name,
                "value": guild.id
            }))
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({ "list": list })))
}

async fn channels(req: Json<HaikuReqBody>) -> Result<Json<Value>, (StatusCode, String)> {
    let guild_id = req
        .routes
        .guild
        .first()
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Missing guild route item".to_string(),
        ))?
        .value
        .parse::<u64>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid guild id".to_string()))?;

    let list = GuildId(guild_id)
        .channels(&*API_CLIENT)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .filter_map(|(id, ch)| {
            (ch.kind == ChannelType::Text).then_some(json!({
                "field": format!("# {}", ch.name),
                "value": id.to_string()
            }))
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({ "list": list })))
}

async fn events() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "A message is send to a channel",
                "value": (MessageType::Regular as u8).to_string(),
            },
            {
                "field": "A message reply",
                "value": (MessageType::InlineReply as u8).to_string(),
            },
            {
                "field": "A member is joined a channel",
                "value": (MessageType::MemberJoin as u8).to_string(),
            },
            {
                "field": "The group name was modified by the author",
                "value": (MessageType::GroupNameUpdate as u8).to_string(),
            },
            {
                "field": "The group icon was modified by the author",
                "value": (MessageType::GroupIconUpdate as u8).to_string(),
            }
        ]
    }))
}

async fn actions() -> impl IntoResponse {
    Json(json!({
        "list": [
            {
                "field": "To send or reply to a message",
                "value": "say"
            }
        ]
    }))
}

struct DiscordEventHandler;

#[async_trait]
impl EventHandler for DiscordEventHandler {
    async fn message(&self, context: Context, msg: Message) {
        // Ignore self-generated events
        if msg.author.id == *DISCORD_APP_APPLICATION_ID {
            return;
        }

        let guild_id = match msg.guild_id {
            Some(id) => id,
            None => return,
        };

        let user = match guild_id.to_partial_guild(&context).await {
            Ok(guild) => guild.owner_id,
            Err(e) => {
                println!("to_partial_guild failed: {}", e.to_string());
                return;
            }
        }
        .to_string();

        post_event_to_haiku(
            user,
            serde_json::to_string(&msg).unwrap_or_default(),
            [
                ("guild", guild_id.to_string()),
                ("channel", msg.channel_id.to_string()),
                ("event", (msg.kind as u8).to_string()),
            ]
            .into_iter(),
        )
        .await
        .unwrap_or_else(|e| println!("{}", e));
    }

    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
    }
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", get(auth))
        .route("/refresh", post(refresh_token))
        .route("/guilds", post(guilds))
        .route("/channels", post(channels))
        .route("/events", post(events))
        .route("/actions", post(actions))
        .route("/post", post(post_msg));

    tokio::spawn(async move {
        let intents = GatewayIntents::GUILD_MEMBERS
            | GatewayIntents::GUILD_MESSAGES
            | GatewayIntents::DIRECT_MESSAGES
            | GatewayIntents::MESSAGE_CONTENT;

        GatewayClient::builder(&*BOT_TOKEN, intents)
            .event_handler(DiscordEventHandler {})
            .await
            .expect("Err creating client")
            .start()
            .await
            .unwrap_or_else(|e| println!("Failed to start GatewayClient: {}", e.to_string()));
    });

    let port = env::var("PORT")
        .unwrap_or("8090".to_string())
        .parse::<u16>()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
