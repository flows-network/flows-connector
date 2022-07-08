use std::env;
use std::time::{Duration};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};
use reqwest::{Client, ClientBuilder};
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

	static ref DISCORD_APP_CLIENT_ID: String = env::var("DISCORD_APP_CLIENT_ID").expect("Env variable DISCORD_APP_CLIENT_ID not set");
	static ref DISCORD_APP_CLIENT_SECRET: String = env::var("DISCORD_APP_CLIENT_SECRET").expect("Env variable DISCORD_APP_CLIENT_SECRET not set");
	static ref DISCORD_REDIRECT_URL: String = env::var("DISCORD_REDIRECT_URL").expect("Env variable DISCORD_REDIRECT_URL not set");

	static ref PASSPHRASE: String = env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref PRIVATE_KEY_PEM: String = env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");

	static ref BOT_TOKEN: String = env::var("BOT_TOKEN").expect("Env variable BOT_TOKEN not set");

}

const TIMEOUT: u64 = 120;


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
			Ok(at) => {
				match get_authed_user(&at.access_token).await {
					Ok(gu) => {
						let encrypted = serde_json::json!({
							"access_token":&at.access_token,
							"id": &at.guild.id
						});
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
							REACTOR_API_PREFIX.as_str(),
							gu.0,
							gu.1,
							encrypt(&serde_json::to_string(&encrypted).unwrap()),
							encrypt(&at.refresh_token)
						);
						Ok((StatusCode::FOUND, [("Location", location)]))
					}
					Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
				}
			},
			Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
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

	let response = new_http_client().post("https://discord.com/api/oauth2/token")
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
	let response = new_http_client().get("https://discord.com/api/oauth2/@me")
		.bearer_auth(access_token)
		.send()
		.await;

	match response {
		Ok(res) => {
			match res.text().await {
				Ok(body) => {
					if let Ok(v) = serde_json::from_str::<Value>(&body) {
						let user_id = v["user"]["id"].as_str().unwrap().to_string();
						let user_name = v["user"]["username"].as_str().unwrap().to_string();
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
		for pb in msg_body.forwards.iter() {
			if pb.route.eq("channels") {
				let request = serde_json::json!({
					"content": "issue",
					"tts": false,
					"embeds": [{
					  "title": "message issue",
					  "description": msg_body.text
					}]
				  }
				);
	
				tokio::spawn(new_http_client().post(format!("https://discord.com/api/channels/{}/messages",pb.value))
					.header("Authorization",BOT_TOKEN.as_str())
					.json(&request)
					.send());
			}
		}
	});

	Ok(StatusCode::OK)
}

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

	let response = new_http_client().post("https://discord.com/api/oauth2/token")
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
				Err(_) => {
					Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to get access token".to_string()))
				}
			}
		},
		Err(_) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to get access token".to_string()))
		}
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
	let response = new_http_client()
		.get(format!("https://discord.com/api/guilds/{}/channels",id))
		.header("Authorization",BOT_TOKEN.as_str())
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
			let rs: Vec<Value> = chs.iter_mut().filter_map(|ch| {
				if true {
					return Some(serde_json::json!({
						"field": format!("# {}", ch.name),
						"value": ch.id
					}));
				} 
				return None;
			})
			.collect();

			let result = serde_json::json!({
				"list": rs
			});
			Ok(Json(result))
		}
		Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
	}
}

#[tokio::main]
async fn main() {
	let app = Router::new()
		.route("/auth", get(auth))
		.route("/refresh", post(refresh_token))
		.route("/channels", post(route_channels))
		.route("/post", post(post_msg));

	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));

	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}