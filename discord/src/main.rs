use axum::{
    extract::{Json, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::channel::MessageType;
use serenity::model::gateway::Ready;
use serenity::prelude::*;
use serenity::utils::MessageBuilder;


const TIMEOUT: u64 = 120;

const RSA_BITS: usize = 2048;

lazy_static! {
    static ref WASMHAIKU_API_PREFIX: String =
        env::var("WASMHAIKU_API_PREFIX").expect("Env variable WASMHAIKU_API_PREFIX not set");
    static ref WASMHAIKU_AUTH_TOKEN: String =
        env::var("WASMHAIKU_AUTH_TOKEN").expect("Env variable WASMHAIKU_AUTH_TOKEN not set");
    static ref DISCORD_APP_CLIENT_ID: String =
        env::var("DISCORD_APP_CLIENT_ID").expect("Env variable DISCORD_APP_CLIENT_ID not set");
    static ref DISCORD_APP_CLIENT_SECRET: String = env::var("DISCORD_APP_CLIENT_SECRET")
        .expect("Env variable DISCORD_APP_CLIENT_SECRET not set");
    static ref DISCORD_REDIRECT_URL: String =
        env::var("DISCORD_REDIRECT_URL").expect("Env variable DISCORD_REDIRECT_URL not set");
    static ref SERVICE_API_PREFIX: String = env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");

    static ref PASSPHRASE: String =
        env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
    static ref PUBLIC_KEY_PEM: String =
        env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
    static ref PRIVATE_KEY_PEM: String =
        env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");
    static ref BOT_TOKEN: String = env::var("BOT_TOKEN").expect("Env variable BOT_TOKEN not set");
    // static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
    //     .expect("Env variable RSA_RAND_SEED not set")
    //     .as_bytes()
    //     .try_into()
    //     .unwrap();
    static ref RSA_RAND_SEED: [u8; 32] = [8;32];

    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIV_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
    static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}

fn encrypt(data: &str) -> String {
    hex::encode(
        PUB_KEY
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
        PRIV_KEY
            .decrypt(
                PaddingScheme::new_pkcs1v15_encrypt(),
                &hex::decode(data).unwrap(),
            )
            .expect("failed to decrypt"),
    )
    .unwrap()
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
    code: Option<String>,
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
    let code = auth_body.code;
    if code.is_none() {
        Err((StatusCode::BAD_REQUEST, "No code".to_string()))
    } else {
        match get_access_token(&code.unwrap()).await {
            Ok(at) => match get_authed_user(&at.access_token).await {
                Ok(gu) => {
                    let encrypted = serde_json::json!({
                        "access_token":&at.access_token,
                        "id": &at.guild.id
                    });
                    let location = format!(
                        "{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
                        WASMHAIKU_API_PREFIX.as_str(),
                        gu.0,
                        gu.1,
                        encrypt(&serde_json::to_string(&encrypted).unwrap()),
                        encrypt(&at.refresh_token)
                    );
                    Ok((StatusCode::FOUND, [("Location", location)]))
                }
                Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
            },
            Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChannelInner {
    id: String,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct OAuthBody {
    access_token: String,
    refresh_token: String,
    guild: ChannelInner,
}

async fn get_access_token(code: &str) -> Result<OAuthBody, String> {
    let params = [
        ("client_id", DISCORD_APP_CLIENT_ID.as_str()),
        ("client_secret", DISCORD_APP_CLIENT_SECRET.as_str()),
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", DISCORD_REDIRECT_URL.as_str()),
    ];

    let response = HTTP_CLIENT
        .post("https://discord.com/api/oauth2/token")
        .form(&params)
        .send()
        .await;

    match response {
        Ok(r) => {
            let oauth_body = r.json::<OAuthBody>().await;
            match oauth_body {
                Ok(at) => Ok(at),
                Err(_) => Err("Failed to get access token".to_string()),
            }
        }
        Err(_) => Err("Failed to get access token".to_string()),
    }
}

async fn get_authed_user(access_token: &str) -> Result<(String, String), String> {
    let response = HTTP_CLIENT
        .get("https://discord.com/api/oauth2/@me")
        .bearer_auth(access_token)
        .send()
        .await;

    match response {
        Ok(res) => match res.text().await {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    let user_id = v["user"]["id"].as_str().unwrap().to_string();
                    let user_name = v["user"]["username"].as_str().unwrap().to_string();
                    Ok((user_id, user_name))
                } else {
                    Err("Failed to get user's name".to_string())
                }
            }
            Err(_) => Err("Failed to get user's profile".to_string()),
        },
        Err(_) => Err("Failed to get user's profile".to_string()),
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ForwardRoute {
    route: String,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct RouteItem {
    field: String,
    value: String,
}

#[derive(Deserialize)]
struct DatabaseRoute {
    channels: Vec<RouteItem>,
    // properties: Option<Vec<RouteItem>>,
}

#[derive(Deserialize)]
struct ReactorReqBody {
    user: String,                   // Workspace ID
    state: String,
    text: Option<String>,
    // cursor: Option<String>,
    // routes: Option<Value>,
    forwards: Option<DatabaseRoute>,
}

async fn post_msg(req: Json<ReactorReqBody>) -> impl IntoResponse {
    let forwards = req.forwards.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "Invalid JSON data: Missing forwards".to_string(),
    ))?;

    let channel_id = &forwards
        .channels
        .first()
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Invalid JSON data: Missing database".to_string(),
        ))?
        .value;

    let text = req
        .text
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?;

    // println!("{},{}",channel_id,text);

    let request = serde_json::json!({"content": text});

    let response = HTTP_CLIENT
        .post(format!("https://discord.com/api/channels/{}/messages",channel_id))
        .header("Authorization", format!("Bot {}", BOT_TOKEN.as_str()))
        .json(&request)
        .send()
        .await;

    match response {
        Ok(r) => Ok((StatusCode::OK, r.bytes().await.unwrap_or_default().to_vec())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Post channel item failed: {}.", e.to_string()),
        )),
    }
}

// async fn post_msg(
//     Json(req): Json<ReactorReqBody>,
// ) -> impl IntoResponse {

//     tokio::spawn(async move {
//         for pb in msg_body.forwards.iter() {
//             if pb.route.eq("channels") {
//                 let request = serde_json::json!({
//                     "content": msg_body.text
//                   }
//                 );

//                 tokio::spawn(
//                     HTTP_CLIENT
//                         .post(format!(
//                             "https://discord.com/api/channels/{}/messages",
//                             pb.value
//                         ))
//                         .header("Authorization", format!("Bot {}", BOT_TOKEN.as_str()))
//                         .json(&request)
//                         .send(),
//                 );
//             }
//         }
//     });

//     Ok(StatusCode::OK)
// }

#[derive(Deserialize)]
struct RefreshState {
    refresh_state: String,
}

async fn refresh_token(Json(msg_body): Json<RefreshState>) -> impl IntoResponse {
    let params = [
        ("client_id", DISCORD_APP_CLIENT_ID.as_str()),
        ("client_secret", DISCORD_APP_CLIENT_SECRET.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", &decrypt(&msg_body.refresh_state)),
    ];

    let response = HTTP_CLIENT
        .post("https://discord.com/api/oauth2/token")
        .form(&params)
        .send()
        .await;

    match response {
        Ok(r) => {
            let oauth_body = r.json::<OAuthBody>().await;
            match oauth_body {
                Ok(at) => {
                    let encrypted = serde_json::json!({
                        "access_state": encrypt(&at.access_token),
                        "refresh_state": encrypt(&at.refresh_token)
                    });
                    Ok((StatusCode::OK, serde_json::to_string(&encrypted).unwrap()))
                }
                Err(_) => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get access token".to_string(),
                )),
            }
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get access token".to_string(),
        )),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChannelName {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct RouteReq {
    state: String,
}

async fn get_channels(id: &str) -> Result<Vec<ChannelName>, String> {
    let response = HTTP_CLIENT
        .get(format!("https://discord.com/api/guilds/{}/channels", id))
        .header("Authorization", format!("Bot {}", BOT_TOKEN.as_str()))
        .send()
        .await;
    if let Ok(r) = response {
        let data = r.text().await.unwrap();
        let channels: Vec<ChannelName> = serde_json::from_str(&data).unwrap();
        return Ok(channels);
    }
    Err("Failed to get channels".to_string())
}

async fn route_channels(Json(body): Json<RouteReq>) -> impl IntoResponse {
    let authstate = decrypt(&body.state);
    let mut id = body.state;
    if let Ok(v) = serde_json::from_str::<Value>(&authstate) {
        id = v["id"].as_str().unwrap().to_string();
    }

    match get_channels(&id).await {
        Ok(mut chs) => {
            let rs: Vec<Value> = chs
                .iter_mut()
                .filter_map(|ch| {
                    if true {
                        return Some(serde_json::json!({
                            "field": format!("# {}", ch.name),
                            "value": ch.id
                        }));
                    }
                    return None;
                })
                .collect();

            let result = serde_json::json!({ "list": rs });
            Ok(Json(result))
        }
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

struct Handler{
    data: String,
}

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, context: Context, msg: Message) {
        // println!("{:?}",msg);

        let words: Vec<&str> = self.data
        .as_str()
        .split(",")
        .collect(); 

        let connector = words[0];
        let flow = words[1];

        // println!("{},{}",connector,flow);

        let triggers = serde_json::json!({
            "channels": msg.channel_id.to_string(),
        });

        let mut request = serde_json::json!({
            "user": connector,
            "flow": flow,
            "text": msg.content.to_string(),
            "triggers": triggers,
        });

        if msg.kind == MessageType::MemberJoin{
            request = serde_json::json!({
                "user": connector,
                "flow": flow,
                "text": "MemberJoin ".to_owned() + &msg.content,
                "triggers": triggers,
            });
        }

        // println!("{:?}",request);
    
        let response = HTTP_CLIENT
            .post(format!("{}/api/_funcs/_post", WASMHAIKU_API_PREFIX.as_str()))
            .header(header::AUTHORIZATION, WASMHAIKU_AUTH_TOKEN.as_str())
            .json(&request)
            .send()
            .await;
    
        if let Err(e) = response {
            println!("{:?}", e);
        }

        if msg.content == "!ping" {
            let channel = match msg.channel_id.to_channel(&context).await {
                Ok(channel) => channel,
                Err(why) => {
                    println!("Error getting channel: {:?}", why);

                    return;
                },
            }; 

            // The message builder allows for creating a message by
            // mentioning users dynamically, pushing "safe" versions of
            // content (such as bolding normalized content), displaying
            // emojis, and more.
            let response = MessageBuilder::new()
                .push("User ")
                .push_bold_safe(&msg.author.name)
                .push(" used the 'ping' command in the ")
                .mention(&channel)
                .push(" channel")
                .build();

            if let Err(why) = msg.channel_id.say(&context.http, &response).await {
                println!("Error sending message: {:?}", why);
            }
     
        }
    }

    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
    }
}

async fn capture_event_inner(event: Message, connector: String, flow: String) {

    let triggers = serde_json::json!({
        "channels": event.channel_id.to_string(),
    });

    post_event_to_reactor(&connector, &flow, &event.content.to_string(), triggers).await;
}

async fn post_event_to_reactor(user: &str, flow: &str, text: &str, triggers: Value) {
    let request = serde_json::json!({
        "user": user,
        "flow": flow,
        "text": text,
        "triggers": triggers,
    });

    let response = HTTP_CLIENT
        .post(format!("{}/api/_funcs/_post", WASMHAIKU_API_PREFIX.as_str()))
        .header(header::AUTHORIZATION, WASMHAIKU_AUTH_TOKEN.as_str())
        .json(&request)
        .send()
        .await;

    if let Err(e) = response {
        println!("{:?}", e);
    }
}

async fn create_client(Json(req): Json<Value>){
    let text = format!("{},{}",req["connector"].as_str().unwrap(),req["flow_id"].as_str().unwrap());
    let token = BOT_TOKEN.as_str();
    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::DIRECT_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT;
    let mut client =
        serenity::prelude::Client::builder(&token, intents)
        .event_handler(Handler{data:text.to_string()})
        .await
        .expect("Err creating client");

    let result = serde_json::json!({
            "revoke": format!("{}/revoke-hook", SERVICE_API_PREFIX.as_str()),
        });

    if let Err(why) = client.start().await {
        println!("Client error: {:?}", why);
    }

}

#[derive(Debug, Deserialize)]
struct HookReq {
    user: String,
    // state: String,
    // field: String,
    // value: String,
    flow: Option<String>,
}

async fn create_hook(Json(req): Json<HookReq>) -> impl IntoResponse {
    // println!("{:?}",req);
    match create_hook_inner(&req.user, &req.flow.unwrap()).await {
        Ok(v) => Ok((StatusCode::CREATED, Json(v))),
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

async fn create_hook_inner(
    connector: &str,
    flow_id: &str
) -> Result<Value, String> {
    let request = serde_json::json!({
        "connector": connector,
        "flow_id": flow_id
    });

    tokio::spawn(
        HTTP_CLIENT
            .post(format!(
                "{}/create-client",
                SERVICE_API_PREFIX.as_str(),
            ))
            .json(&request)
            .send(),
    );

    let result = serde_json::json!({
        "revoke": format!("{}/revoke-hook", SERVICE_API_PREFIX.as_str()),
    });

    return Ok(result);
}

async fn revoke_hook() -> impl IntoResponse {
    match revoke_hook_inner().await {
        Ok(()) => Ok(StatusCode::OK),
        Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
    }
}

async fn revoke_hook_inner() -> Result<(), String> {
    // let response = HTTP_CLIENT
    //     .post(format!(
    //         "https://api.telegram.org/bot{}/deleteWebhook?drop_pending_updates=True",
    //         TELEGRAM_BOT_TOKEN.as_str()
    //     ))
    //     .send()
    //     .await;

    return Ok(());
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/auth", get(auth))
        .route("/refresh", post(refresh_token))
        .route("/channels", post(route_channels))
        .route("/post", post(post_msg))
        .route("/revoke-hook", delete(revoke_hook))
        .route("/create-hook", post(create_hook))
        .route("/create-client", post(create_client));

    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
    let port = port.parse::<u16>().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
