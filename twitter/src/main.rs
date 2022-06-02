use std::env;
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};
use reqwest::{Client, ClientBuilder};
use rand::{distributions::Alphanumeric, Rng};
use axum::{
	Router,
	routing::{get, post},
	extract::{Query, Json},
	response::{IntoResponse},
	http::{StatusCode},
};

lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");

	static ref TWITTER_OAUTH_CLIENT_ID: String = env::var("TWITTER_OAUTH_CLIENT_ID").expect("Env variable TWITTER_OAUTH_CLIENT_ID not set");
	static ref TWITTER_OAUTH_CLIENT_SECRET: String = env::var("TWITTER_OAUTH_CLIENT_SECRET").expect("Env variable TWITTER_OAUTH_CLIENT_SECRET not set");
	static ref TWITTER_OAUTH_REDIRECT_URL: String = env::var("TWITTER_OAUTH_REDIRECT_URL").expect("Env variable TWITTER_OAUTH_REDIRECT_URL not set");

	static ref PASSPHRASE: String = env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref PRIVATE_KEY_PEM: String = env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");

	static ref STATE_MAP: Arc<Mutex<HashMap<String, StateBlock>>> = Arc::new(Mutex::new(HashMap::new()));
}

static CONNECT_HTML: &str = include_str!("./connect.html");

const TIMEOUT: u64 = 120;

const STATE_MAP_MAX: usize = 100;
const STATE_BLOCK_EXPIRE_SEC: u64 = 10 * 60;

fn new_http_client() -> Client {
	let cb = ClientBuilder::new().timeout(Duration::from_secs(TIMEOUT));
	return cb.build().unwrap();
}

fn encrypt(data: &str) -> String {
	let rsa = Rsa::public_key_from_pem(PUBLIC_KEY_PEM.as_bytes()).unwrap();
	let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
	rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
	hex::encode(buf)
}

fn decrypt(hex: &str) -> String {
	let rsa = Rsa::private_key_from_pem_passphrase(PRIVATE_KEY_PEM.as_bytes(), PASSPHRASE.as_bytes()).unwrap();
	let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
	let l = rsa.private_decrypt(&hex::decode(hex).unwrap(), &mut buf, Padding::PKCS1).unwrap();
	String::from_utf8(buf[..l].to_vec()).unwrap()
}

struct StateBlock {
	time_instant: Instant,
	block_content: Option<String>,
}

fn clear_state_map(state_map: &mut HashMap<String, StateBlock>) {
	state_map.retain(|_, v| {
		let elapsed_time = v.time_instant.elapsed();
		elapsed_time.as_secs() < STATE_BLOCK_EXPIRE_SEC
	});
}

async fn connect() -> impl IntoResponse {
	match STATE_MAP.lock() {
		Ok(mut state_map) => {
			if state_map.len() > STATE_MAP_MAX {
				clear_state_map(&mut state_map);
			}
			let s: String = rand::thread_rng()
				.sample_iter(&Alphanumeric)
				.take(10)
				.map(char::from)
				.collect();
			
			let html = CONNECT_HTML;
			// let html = std::fs::read("/home/darumadocker/github/second-state/reactor-connector-rs/twitter/src/connect.html").unwrap();
			// let html = String::from_utf8_lossy(&html);

			let html = html
				.replace("%STATE%", &s)
				.replace("%TWITTER_OAUTH_CLIENT_ID%", TWITTER_OAUTH_CLIENT_ID.as_str())
				.replace("%TWITTER_OAUTH_REDIRECT_URL%", TWITTER_OAUTH_REDIRECT_URL.as_str());

			state_map.insert(s, StateBlock { time_instant: Instant::now(), block_content: None });

			Ok((StatusCode::OK, [("Content-Type", "text/html")], html))
		}
		Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error".to_string()))
	}
}

#[derive(Deserialize)]
struct PollQuery {
	state: String,
}

async fn poll_block(Query(pq): Query<PollQuery>) -> impl IntoResponse {
	match STATE_MAP.lock() {
		Ok(state_map) => {
			match state_map.get(&pq.state) {
				Some(block) => {
					match &block.block_content {
						Some(location) => Ok((StatusCode::FOUND, Ok([("Location", location.clone())]))),
						None => Ok((StatusCode::OK, Err(())))
					}
				}
				None => Err((StatusCode::NOT_FOUND, "State not found"))
			}
		}
		Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"))
	}
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
	code: Option<String>,
	state: String,
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
	let code = auth_body.code;
	if code.is_none() {
		Err((StatusCode::BAD_REQUEST, "No code".to_string()))
	} else {
		match get_access_token(&code.unwrap()).await {
			Ok(at) => {
				match get_authed_user(&at.access_token).await {
					Ok(gu) => {
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
							REACTOR_API_PREFIX.as_str(),
							gu.0,
							gu.1,
							encrypt(&at.access_token),
							encrypt(&at.refresh_token)
						);
						match STATE_MAP.lock() {
							Ok(mut state_map) => {
								if let Some(block) = state_map.get_mut(&auth_body.state) {
									block.block_content = Some(location);
								}
								Ok((StatusCode::OK, [("Content-Type", "text/html")], "<script>window.close()</script>"))
							}
							Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error".to_string()))
						}
					}
					Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
				}
			},
			Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

#[derive(Serialize, Deserialize)]
struct OAuthBody {
	access_token: String,
	refresh_token: String,
}

async fn get_access_token(code: &str) -> Result<OAuthBody, String> {
	let params = [
		("grant_type", "authorization_code"),
		("code", &code),
		("redirect_uri", TWITTER_OAUTH_REDIRECT_URL.as_str()),
		("code_verifier", "challenge")
	];

	let basic_auth = base64::encode(format!("{}:{}",
		TWITTER_OAUTH_CLIENT_ID.as_str(),
		TWITTER_OAUTH_CLIENT_SECRET.as_str()));
	
	let response = new_http_client().post("https://api.twitter.com/2/oauth2/token")
		.header("Authorization", format!("Basic {}", basic_auth))
		.form(&params)
		.send()
		.await;
	match response {
		Ok(r) => {
			let oauth_body = r.json::<OAuthBody>().await;
			match oauth_body {
				Ok(at) => {
					Ok(at)
				}
				Err(_) => {
					Err("Failed to get access token".to_string())
				}
			}
		},
		Err(_) => {
			Err("Failed to get access token".to_string())
		}
	}
}

async fn get_authed_user(access_token: &str) -> Result<(String, String), String> {
	let response = new_http_client().get("https://api.twitter.com/2/users/me")
		.bearer_auth(access_token)
		.send()
		.await;

	match response {
		Ok(res) => {
			match res.text().await {
				Ok(body) => {
					if let Ok(v) = serde_json::from_str::<Value>(&body) {
						let user_id = v["data"]["id"].as_str().unwrap().to_string();
						let user_name = v["data"]["name"].as_str().unwrap().to_string();
						Ok((user_id, user_name))
					} else {
						Err("Failed to get user's name".to_string())
					}
				}
				Err(_) => {
					Err("Failed to get user's profile".to_string())
				}
			}
		}
		Err(_) => {
			Err("Failed to get user's profile".to_string())
		}
	}
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

#[derive(Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
	forwards: Vec<ForwardRoute>,
}

async fn post_msg(Json(msg_body): Json<PostBody>) -> Result<StatusCode, (StatusCode, &'static str)> {
	tokio::spawn(async move {
		let route = msg_body.forwards.into_iter().fold(None, |mut accum, f| {
			if accum.is_none() && f.route.eq("action") {
				accum = Some(f.value);
			}
			accum
		});

		if route.is_some() {
			match route.unwrap().as_str() {
				"create-tweet" => {
					_ = new_http_client().post("https://api.twitter.com/2/tweets")
						.bearer_auth(decrypt(&msg_body.state))
						.json(&serde_json::json!({
							"text": msg_body.text
						}))
						.send().await;
				}
				_ => ()
			}
		}
	});

	Ok(StatusCode::OK)
}

#[tokio::main]
async fn main() {
	let app = Router::new()
		.route("/connect", get(connect))
		.route("/poll-block", get(poll_block))
		.route("/auth", get(auth))
		.route("/actions", post(actions))
		.route("/post", post(post_msg));

	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));

	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}