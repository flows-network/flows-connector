use std::env;
use std::time::{Duration};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use lazy_static::lazy_static;
use reqwest::{Client, ClientBuilder};
use axum::{
	Router,
	routing::{get, post, delete},
	extract::{Query, Json},
	response::{IntoResponse},
	http::{StatusCode,header,HeaderMap},
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

const TIMEOUT: u64 = 120;

const RSA_BITS: usize = 2048;

lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");

	static ref TELEGRAM_BOT_TOKEN: String = env::var("TELEGRAM_BOT_TOKEN").expect("Env var TELEGRAM_BOT_TOKEN not set");
	static ref TELEGRAM_BOT_NAME: String = env::var("TELEGRAM_BOT_NAME").expect("Env var TELEGRAM_BOT_NAME not set");

	static ref SERVICE_API_PREFIX: String = env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
	
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
	id: String,
	name: String
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
	let id = auth_body.id;
	let name = auth_body.name;
	if id == "" {
		Err((StatusCode::BAD_REQUEST, "No id or name".to_string()))
	} else {
		let location = format!(
			"{}/api/connected?authorId={}&authorName={}&authorState={}",
			REACTOR_API_PREFIX.as_str(),
			id,
			name,
			encrypt(&id)
		);
		Ok((StatusCode::FOUND, [("Location", location)]))
	}
}

#[derive(Debug, Serialize, Deserialize)]
struct ProjectName {
	id: String,
	name: String,
}


async fn chat(Json(body): Json<Value>) -> impl IntoResponse {

	println!("{:?}",body);

	let events = serde_json::json!({
		"list": [
			{
				"field": TELEGRAM_BOT_NAME.as_str(),
				"value": TELEGRAM_BOT_NAME.as_str()
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

#[derive(Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
	forwards: Vec<ForwardRoute>,
}

async fn post_msg(Json(msg_body): Json<PostBody>) -> Result<StatusCode, (StatusCode, &'static str)> {
	println!("{}",msg_body.text);

	let words: Vec<&str> = msg_body.text.split(" ").collect();

	if words[0]=="ban"{
		let words: Vec<&str> = msg_body.text.split(" ").collect();
		let text = format!("ban user: {} \n from group: {}",words[4],words[3]);

		tokio::spawn(HTTP_CLIENT
			.post(format!("https://api.telegram.org/bot{}/banChatMember?chat_id={}&user_id={}",TELEGRAM_BOT_TOKEN.as_str(),words[1],words[2]))
			.send());
		
		tokio::spawn(HTTP_CLIENT
			.post(format!("https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}",TELEGRAM_BOT_TOKEN.as_str(),msg_body.user.as_str(),text))
			.send());
	}
	else
	{
		tokio::spawn(HTTP_CLIENT
			.post(format!("https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}",TELEGRAM_BOT_TOKEN.as_str(),msg_body.user.as_str(),msg_body.text))
			.send());
	}

	Ok(StatusCode::OK)
}

static CONNECT_HTML: &str = include_str!("./connect.html");

async fn connect() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/html; charset=utf-8")],
        CONNECT_HTML,
    )
}

#[derive(Debug, Deserialize)]
struct HookReq {
	user: String,
    state: String,
	field: String,
	value: String,
	flow: Option<String>,
}

async fn create_hook(Json(req): Json<HookReq>) -> impl IntoResponse {

	match create_hook_inner(&req.user, &req.flow.unwrap(), &req.field, &req.value).await {
		Ok(v) => {
			Ok((StatusCode::CREATED, Json(v)))
		}
		Err(err_msg) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn create_hook_inner(connector: &str, flow_id: &str, repo_full_name: &str, id: &str) -> Result<Value, String> {

	tokio::spawn(HTTP_CLIENT
		.post(format!("https://api.telegram.org/bot{}/setWebhook?url={}/newmessage&secret_token={}",TELEGRAM_BOT_TOKEN.as_str(),SERVICE_API_PREFIX.as_str(),format!("{}_{}",connector,flow_id)))
		.send());
	
	let result = serde_json::json!({
			"revoke": format!("{}/revoke-hook", SERVICE_API_PREFIX.as_str()),
		});
	
	return Ok(result);
}

async fn revoke_hook() -> impl IntoResponse {

	match revoke_hook_inner().await {
		Ok(()) => {
			Ok(StatusCode::OK)
		}
		Err(err_msg) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn revoke_hook_inner() -> Result<(), String> {
	let response = HTTP_CLIENT
		.post(format!("https://api.telegram.org/bot{}/deleteWebhook?drop_pending_updates=True",TELEGRAM_BOT_TOKEN.as_str()))
		.send()
		.await;
	
	return Ok(());
}

async fn newmessage(Json(msg_body): Json<Value>,headers: HeaderMap) -> Result<StatusCode, (StatusCode, &'static str)> {
	println!("{:?}",msg_body);
	println!("{:?}",headers["x-telegram-bot-api-secret-token"]);

	let words: Vec<&str> = headers["x-telegram-bot-api-secret-token"].to_str().unwrap().split("_").collect();

	let connector = words[0];
	let flow = words[1];

	tokio::spawn(capture_event_inner(msg_body,connector.to_string(),flow.to_string()));

	Ok(StatusCode::OK)
}

async fn capture_event_inner(event: Value, connector: String, flow: String) {

	let mut project: Value = serde_json::from_str(&event["message"].to_string()).unwrap();

	let triggers = serde_json::json!({
		"chat": TELEGRAM_BOT_NAME.as_str(),
	});

	post_event_to_reactor(&connector, &flow, &event.to_string(),triggers).await;

}

async fn post_event_to_reactor(user: &str, flow: &str, text: &str, triggers: Value) {
	let request = serde_json::json!({
		"user": user,
		"flow": flow,
		"text": text,
		"triggers": triggers,
	});

	let response = HTTP_CLIENT
		.post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
		.header(header::AUTHORIZATION, REACTOR_AUTH_TOKEN.as_str())
		.json(&request)
		.send()
		.await;

	if let Err(e) = response {
		println!("{:?}", e);
	}
}

async fn hook_events() -> impl IntoResponse {
	let events = serde_json::json!({
		"list": [
			{
				"field": "message",
				"value": "message"
			}
		]
	});
	Json(events)
}

async fn delete_member() -> impl IntoResponse {

	let result = serde_json::json!({
		"state": "OK",
		"member": "jack"
	});

	Json(result)
}

#[tokio::main]
async fn main() {
	let app = Router::new()
		.route("/auth", get(auth))
		.route("/connect",get(connect))
		.route("/chat", post(chat))
		.route("/post", post(post_msg))
		.route("/revoke-hook", delete(revoke_hook))
		.route("/create-hook", post(create_hook))
		.route("/hook-events", post(hook_events))
		.route("/deletemember",post(delete_member))
		.route("/newmessage",post(newmessage));

	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));

	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}