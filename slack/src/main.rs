use std::env;
use std::time::Duration;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};
use reqwest::{Client, ClientBuilder, multipart};
use axum::{
	Router,
	routing::{get, post},
	extract::{Query, Json},
	response::{IntoResponse},
	http::{StatusCode},
	extract::{ContentLengthLimit, Multipart},
};

lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");

	static ref PASSPHRASE: String = env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref PRIVATE_KEY_PEM: String = env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");
}

const TIMEOUT: u64 = 120;

fn new_http_client() -> Client {
	let cb = ClientBuilder::new().timeout(Duration::from_secs(TIMEOUT));
	return cb.build().unwrap();
}

fn encrypt(data: String) -> String {
	let rsa = Rsa::public_key_from_pem(PUBLIC_KEY_PEM.as_bytes()).unwrap();
	let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
	rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
	hex::encode(buf)
}

fn decrypt(hex: String) -> String {
	let rsa = Rsa::private_key_from_pem_passphrase(PRIVATE_KEY_PEM.as_bytes(), PASSPHRASE.as_bytes()).unwrap();
	let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
	let l = rsa.private_decrypt(&hex::decode(hex).unwrap(), &mut buf, Padding::PKCS1).unwrap();
	String::from_utf8(buf[..l].to_vec()).unwrap()
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
	code: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuthedUser {
	id: String,
	access_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct OAuthAccessBody {
	ok: bool,
	authed_user: Option<AuthedUser>,
	access_token: Option<String>,
	error: Option<String>,
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
	if auth_body.code.eq("") {
		Err((StatusCode::BAD_REQUEST, "No code".to_string()))
	} else {
		match get_access_token(&auth_body.code).await {
			Ok(at) => {
				if at.ok {
					let authed_user = at.authed_user.unwrap();
					match get_authed_user(&authed_user.access_token).await {
						Ok(gu) => {
							let location = format!(
								"{}/api/connected?authorId={}&authorName={}&authorState={}",
								REACTOR_API_PREFIX.as_str(),
								authed_user.id,
								gu,
								encrypt(at.access_token.unwrap())
							);
							Ok((StatusCode::FOUND, [("Location", location)]))
						}
						Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
					}
				} else {
					Err((StatusCode::BAD_REQUEST, "Invalid code".to_string()))
				}
			},
			Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn get_access_token(code: &str) -> Result<OAuthAccessBody, String> {
	let slack_client_id = env::var("SLACK_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
	let slack_client_secret = env::var("SLACK_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");

	let params = [
		("client_id", slack_client_id.as_str()),
		("client_secret", slack_client_secret.as_str()),
		("code", &code)
	];

	let response = new_http_client().post("https://slack.com/api/oauth.v2.access")
		.form(&params)
		.send()
		.await;
	match response {
		Ok(r) => {
			let oauth_body = r.json::<OAuthAccessBody>().await;
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

async fn get_authed_user(access_token: &str) -> Result<String, String> {
	let response = new_http_client().get("https://slack.com/api/users.profile.get")
		.bearer_auth(access_token)
		.send()
		.await;

	match response {
		Ok(res) => {
			match res.text().await {
				Ok(body) => {
					if let Ok(v) = serde_json::from_str::<Value>(&body) {
						Ok(v["profile"]["real_name"].as_str().unwrap().to_string())
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

#[derive(Deserialize)]
struct EventBody {
	challenge: Option<String>,
	event: Option<Event>,
}

#[derive(Deserialize)]
struct Event {
	bot_id: Option<String>,
	channel: Option<String>,
	// channel_type: Option<String>,
	user: Option<String>,
	text: Option<String>,
	files: Option<Vec<File>>,
}

#[derive(Debug, Deserialize)]
struct File {
	name: String,
	mimetype: String,
	url_private: String,
}

async fn _capture_event_body(b: axum::body::Bytes) -> impl IntoResponse {
	let s = String::from_utf8_lossy(&b.to_vec()).into_owned();
	let v: Value= serde_json::from_str(&s).unwrap();
	println!("{}", serde_json::to_string_pretty(&v).unwrap());
	(StatusCode::OK, String::new())
}

async fn capture_event(Json(evt_body): Json<EventBody>) -> impl IntoResponse {
	if let Some(challenge) = evt_body.challenge {
		return (StatusCode::OK, challenge);
	}

	if let Some(evt) = evt_body.event {
		// Only handle message which is sent by user
		if evt.bot_id.is_none() {
			let user = evt.user.unwrap_or_else(|| String::from(""));
			let text = evt.text.unwrap_or_else(|| String::from(""));
			let files = evt.files.unwrap_or_else(|| Vec::new());
			let channel = evt.channel.unwrap_or_default();
			tokio::spawn(post_event_to_reactor(user, text, files, channel));
		}
	}

	(StatusCode::OK, String::new())
}

async fn post_event_to_reactor(user: String, text: String, files: Vec<File>, channel: String) {

	if files.len() == 0 {
		let request = serde_json::json!({
			"user": user,
			"text": text,
			"triggers": {
				"channels": channel
			}
		});

		_ = new_http_client().post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
			.header("Authorization", REACTOR_AUTH_TOKEN.as_str())
			.json(&request)
			.send()
			.await;
	} else {
		if let Ok(access_token) = get_author_token_from_reactor(&user).await {
			let mut request = multipart::Form::new()
				.text("user", user)
				.text("text", text)
				.text("triggers", format!(r#"{{"channels": "{}"}}"#, channel));

			for f in files.into_iter() {
				if let Ok(b) = get_file(&access_token, &f.url_private).await {
					if let Ok(part) = multipart::Part::bytes(b)
						.file_name(f.name)
						.mime_str(&f.mimetype) {
						request = request.part("file", part);
					}
				}
			}

			_ = new_http_client().post(format!("{}/api/_funcs/_upload", REACTOR_API_PREFIX.as_str()))
				.header("Authorization", REACTOR_AUTH_TOKEN.as_str())
				.multipart(request)
				.send()
				.await;
		}
	}
}

async fn get_author_token_from_reactor(user: &str) -> Result<String, ()> {
	let request = serde_json::json!({
		"author": user
	});

	let response = new_http_client().post(format!("{}/api/_funcs/_author_state", REACTOR_API_PREFIX.as_str()))
		.header("Authorization", REACTOR_AUTH_TOKEN.as_str())
		.json(&request)
		.send()
		.await;

	if let Ok(res) = response {
		if res.status().is_success() {
			if let Ok(body) = res.text().await {
				return Ok(decrypt(body));
			}
		}
	}
	Err(())
}

async fn get_file(access_token: &str, url_private: &str) -> Result<Vec<u8>, ()> {
	let response = new_http_client().get(url_private)
		.bearer_auth(access_token)
		.send()
		.await;
	
	if let Ok(res) = response {
		if res.status().is_success() {
			if let Ok(body) = res.bytes().await {
				return Ok(body.to_vec());
			}
		}
	}

	Err(())
}

#[derive(Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
}

async fn post_msg(Json(msg_body): Json<PostBody>) -> Result<StatusCode, (StatusCode, &'static str)> {
	let request = serde_json::json!({
		"channel": msg_body.user,
		"text": msg_body.text,
	});

	let response = new_http_client().post("https://slack.com/api/chat.postMessage")
		.bearer_auth(decrypt(msg_body.state))
		.json(&request)
		.send()
		.await;
	match response {
		Ok(_) => Ok(StatusCode::OK),
		Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to post message to slack"))
	}
}

async fn upload_file_to_slack(form: multipart::Form, access_token: String) {
	let response = new_http_client().post("https://slack.com/api/files.upload")
		.bearer_auth(decrypt(access_token))
		.multipart(form)
		.send()
		.await;
	if let Ok(res) = response {
		if res.status().is_success() {
			// println!("{:?}", res.text().await);
		}
	}
}


async fn upload_msg(ContentLengthLimit(mut multipart): ContentLengthLimit<Multipart, {10 * 1024 * 1024 /* 250mb */},>) -> impl IntoResponse {
	let mut user = String::new();
	let mut text = String::new();
	let mut state = String::new();

	let mut parts = Vec::new();
	while let Some(field) = multipart.next_field().await.unwrap() {
		let name = field.name().unwrap().to_string();
		match name.as_str() {
			"file" => {
				let file_name = field.file_name().unwrap().to_string();
				let content_type = field.content_type().unwrap().to_string();
				let data = field.bytes().await.unwrap();
				if let Ok(part) = multipart::Part::bytes(data.to_vec())
					.file_name(file_name)
					.mime_str(&content_type) {
					parts.push(part);
				}
			}
			"user" => {
				if let Ok(u) = field.text().await {
					user = u;
				}
			}
			"state" => {
				if let Ok(s) = field.text().await {
					state = s;
				}
			}
			"text" => {
				if let Ok(t) = field.text().await {
					text = t;
				}
			}
			_ => {}
		}
	}

	if user.len() == 0 || state.len() == 0 {
		return Err((StatusCode::BAD_REQUEST, ""));
	}

	if parts.len() > 0 {
		for part in parts.into_iter() {
			let mut form = multipart::Form::new()
				.text("channels", user.clone());
			form = form.part("file", part);
			upload_file_to_slack(form, state.clone()).await;
		}
	}

	if text.len() > 0 {
		return post_msg(Json::from(PostBody {
			user: user,
			state: state,
			text: text,
		})).await;
	} else {
		return Ok(StatusCode::OK);
	}
}

const CHANNELS_PER_PAGE: u32 = 20;
#[derive(Debug, Serialize, Deserialize)]
struct Channel {
	id: String,
	name: Option<String>,
	is_channel: Option<bool>,
	is_im: Option<bool>,
	user: Option<String>,
}

#[derive(Deserialize)]
struct ChannelInfo {
	ok: bool,
	channel: Option<Channel>,
}

#[derive(Deserialize)]
struct RespMeta {
	next_cursor: String,
}

#[derive(Deserialize)]
struct Channels {
	ok: bool,
	channels: Vec<Channel>,
	response_metadata: RespMeta
}
#[derive(Deserialize)]
struct RouteReq {
	user: String,
	state: String,
	cursor: Option<String>,
}

async fn get_channels(access_token: &str, cursor: String) -> Result<Channels, String> {
	let response = new_http_client()
		.get(format!("https://slack.com/api/conversations.list?limit={}&cursor={}&types=public_channel,im", CHANNELS_PER_PAGE, cursor))
		.bearer_auth(access_token)
		.send()
		.await;
	if let Ok(r) = response {
		if let Ok(channels) = r.json::<Channels>().await {
			if channels.ok {
				return Ok(channels);
			}
		}
	}
	Err("Failed to get installed repositories".to_string())
}

async fn view_channel(access_token: &str, channel: &str) -> Option<Channel> {
	let response = new_http_client()
		.get(format!("https://slack.com/api/conversations.info?channel={}", channel))
		.bearer_auth(access_token)
		.send()
		.await;
	if let Ok(r) = response {
		if let Ok(ci) = r.json::<ChannelInfo>().await {
			if ci.ok {
				return ci.channel;
			}
		}
	}
	None
}

async fn route_channels(Json(body): Json<RouteReq>) -> impl IntoResponse {
	let access_token = decrypt(body.state);
	let cursor = body.cursor.unwrap_or_default();
	match get_channels(&access_token, cursor).await {
		Ok(mut chs) => {
			let rs: Vec<Value> = chs.channels.iter_mut().filter_map(|ch| {
				if ch.is_channel.is_some() && ch.is_channel.unwrap() {
					return Some(serde_json::json!({
						"field": ch.name,
						"value": ch.id
					}));
				} else if ch.is_im.is_some() && ch.is_im.unwrap() {
					if ch.user.is_some() && ch.user.take().unwrap().eq(&body.user) {
						return Some(serde_json::json!({
							"field": "Reactor App",
							"value": ch.id
						}));
					}
				}
				return None;
			})
			.collect();
			let result = match chs.response_metadata.next_cursor.as_str() {
				"" => {
					serde_json::json!({
						"list": rs
					})
				}
				s => {
					serde_json::json!({
						"next_cursor": s,
						"list": rs
					})
				}
			};
			Ok(Json(result))
		}
		Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
	}
}

#[derive(Debug, Deserialize)]
struct JoinChannelReq {
	// user: String,
    state: String,
	// field: String,
	value: String,
}

async fn join_channel(Json(req): Json<JoinChannelReq>) -> impl IntoResponse {
	let access_token = decrypt(req.state);

	match view_channel(&access_token, &req.value).await {
		Some(ch) => {
			if ch.is_channel.is_some() && ch.is_channel.unwrap() {
				match join_channel_inner(&req.value, &access_token).await {
					Ok(v) => {
						return Ok((StatusCode::CREATED, Json(v)));
					}
					Err(err_msg) => {
						return Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg));
					}
				}
			} else {
				return Ok((StatusCode::OK, Json(())));
			}
		}
		None => {
			return Err((StatusCode::BAD_REQUEST, "Channel not found".to_string()));
		}
	}
}

async fn join_channel_inner(channel: &str, access_token: &str) -> Result<(), String> {
	let param = serde_json::json!({
		"channel": channel
	});
	let response = new_http_client().post(format!("https://slack.com/api/conversations.join"))
		.bearer_auth(access_token)
		.json(&param)
		.send()
		.await;
	if let Ok(r) = response {
		if r.status().is_success() {
			if let Ok(body) = r.bytes().await {
				let json_body: Value = serde_json::from_slice(&body).unwrap();
				if let Some(ok) = json_body["ok"].as_bool() {
					if ok {
						return Ok(());
					}
				}
				
			}
		}
	}
	Err("Failed to create hook".to_string())
}

#[tokio::main]
async fn main() {
	let app = Router::new()
		.route("/auth", get(auth))
		.route("/event", post(capture_event))
		.route("/post", post(post_msg).put(upload_msg))
		.route("/channels", post(route_channels))
		.route("/join-channel", post(join_channel));

	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));

	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}