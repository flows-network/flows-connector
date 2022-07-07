use axum::{
	extract::{ContentLengthLimit, Multipart},
	extract::{Json, Query},
	http::StatusCode,
	response::IntoResponse,
	routing::{get, post},
	Router,
};
use lazy_static::lazy_static;
use reqwest::{multipart, Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

static RSA_BITS: usize = 2048;

lazy_static! {
	static ref REACTOR_API_PREFIX: String =
		env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String =
		env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
	static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
		.expect("Env variable RSA_RAND_SEED not set")
		.as_bytes()
		.try_into()
		.unwrap();
	static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
	static ref PRIV_KEY: RsaPrivateKey =
		RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
	static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
}

const TIMEOUT: u64 = 120;

fn new_http_client() -> Client {
	let cb = ClientBuilder::new().timeout(Duration::from_secs(TIMEOUT));
	return cb.build().unwrap();
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
								encrypt(at.access_token.unwrap().as_str())
							);
							Ok((StatusCode::FOUND, [("Location", location)]))
						}
						Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
					}
				} else {
					Err((StatusCode::BAD_REQUEST, "Invalid code".to_string()))
				}
			}
			Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
		}
	}
}

async fn get_access_token(code: &str) -> Result<OAuthAccessBody, String> {
	let slack_client_id =
		env::var("SLACK_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
	let slack_client_secret =
		env::var("SLACK_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");

	let params = [
		("client_id", slack_client_id.as_str()),
		("client_secret", slack_client_secret.as_str()),
		("code", &code),
	];

	let response = new_http_client()
		.post("https://slack.com/api/oauth.v2.access")
		.form(&params)
		.send()
		.await;
	match response {
		Ok(r) => {
			let oauth_body = r.json::<OAuthAccessBody>().await;
			match oauth_body {
				Ok(at) => Ok(at),
				Err(_) => Err("Failed to get access token".to_string()),
			}
		}
		Err(_) => Err("Failed to get access token".to_string()),
	}
}

async fn get_authed_user(access_token: &str) -> Result<String, String> {
	let response = new_http_client()
		.get("https://slack.com/api/users.profile.get")
		.bearer_auth(access_token)
		.send()
		.await;

	match response {
		Ok(res) => match res.text().await {
			Ok(body) => {
				if let Ok(v) = serde_json::from_str::<Value>(&body) {
					Ok(v["profile"]["real_name"].as_str().unwrap().to_string())
				} else {
					Err("Failed to get user's name".to_string())
				}
			}
			Err(_) => Err("Failed to get user's profile".to_string()),
		},
		Err(_) => Err("Failed to get user's profile".to_string()),
	}
}

#[derive(Debug, Deserialize)]
struct EventBody {
	challenge: Option<String>,
	event: Option<Event>,
}

#[derive(Debug, Deserialize)]
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
	let v: Value = serde_json::from_str(&s).unwrap();
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

		let _ = new_http_client()
			.post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
			.header("Authorization", REACTOR_AUTH_TOKEN.as_str())
			.json(&request)
			.send()
			.await;
	} else if let Ok(access_token) = get_author_token_from_reactor(&user).await {
		let mut request = multipart::Form::new()
			.text("user", user)
			.text("text", text)
			.text("triggers", format!(r#"{{"channels": "{}"}}"#, channel));

		for f in files.into_iter() {
			if let Ok(b) = get_file(&access_token, &f.url_private).await {
				if let Ok(part) = multipart::Part::bytes(b)
					.file_name(f.name)
					.mime_str(&f.mimetype)
				{
					request = request.part("file", part);
				}
			}
		}

		let _ = new_http_client()
			.post(format!(
				"{}/api/_funcs/_upload",
				REACTOR_API_PREFIX.as_str()
			))
			.header("Authorization", REACTOR_AUTH_TOKEN.as_str())
			.multipart(request)
			.send()
			.await;
	}
}

async fn get_author_token_from_reactor(user: &str) -> Result<String, ()> {
	let request = serde_json::json!({ "author": user });

	let response = new_http_client()
		.post(format!(
			"{}/api/_funcs/_author_state",
			REACTOR_API_PREFIX.as_str()
		))
		.header("Authorization", REACTOR_AUTH_TOKEN.as_str())
		.json(&request)
		.send()
		.await;

	if let Ok(res) = response {
		if res.status().is_success() {
			if let Ok(body) = res.text().await {
				return Ok(decrypt(body.as_str()));
			}
		}
	}
	Err(())
}

async fn get_file(access_token: &str, url_private: &str) -> Result<Vec<u8>, ()> {
	let response = new_http_client()
		.get(url_private)
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

async fn post_msg(
	Json(msg_body): Json<PostBody>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
	tokio::spawn(async move {
		for pb in msg_body.forwards.iter() {
			if pb.route.eq("channels") {
				let request = serde_json::json!({
					"channel": pb.value,
					"text": msg_body.text,
				});

				tokio::spawn(
					new_http_client()
						.post("https://slack.com/api/chat.postMessage")
						.bearer_auth(decrypt(msg_body.state.as_str()))
						.json(&request)
						.send(),
				);
			}
		}
	});

	Ok(StatusCode::OK)
}

async fn upload_file_to_slack(form: multipart::Form, access_token: String) {
	let response = new_http_client()
		.post("https://slack.com/api/files.upload")
		.bearer_auth(decrypt(access_token.as_str()))
		.multipart(form)
		.send()
		.await;
	if let Ok(res) = response {
		if res.status().is_success() {
			// println!("{:?}", res.text().await);
		}
	}
}

async fn upload_msg(
	ContentLengthLimit(mut multipart): ContentLengthLimit<
		Multipart,
		{
			10 * 1024 * 1024 /* 250mb */
		},
	>,
) -> impl IntoResponse {
	tokio::spawn(async move {
		let mut user = String::new();
		let mut text = String::new();
		let mut state = String::new();
		let mut forwards = Vec::new();

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
						.mime_str(&content_type)
					{
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
				"forwards" => {
					if let Ok(f) = field.text().await {
						if let Ok(fws) = serde_json::from_str::<Vec<ForwardRoute>>(&f) {
							forwards = fws;
						}
					}
				}
				_ => {}
			}
		}

		if user.len() == 0 || state.len() == 0 {
			return;
		}

		if parts.len() > 0 {
			for part in parts.into_iter() {
				let mut form = multipart::Form::new().text("channels", user.clone());
				form = form.part("file", part);
				upload_file_to_slack(form, state.clone()).await;
			}
		}

		if text.len() > 0 {
			tokio::spawn(post_msg(Json::from(PostBody {
				user,
				state,
				text,
				forwards,
			})));
		}
	});

	StatusCode::OK
}

const CHANNELS_PER_PAGE: u32 = 20;
#[derive(Debug, Serialize, Deserialize)]
struct Channel {
	id: String,
	name: Option<String>,
	is_channel: Option<bool>,
	is_im: Option<bool>,
	is_member: Option<bool>,
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
	response_metadata: RespMeta,
}
#[derive(Deserialize)]
struct RouteReq {
	user: String,
	state: String,
	cursor: Option<String>,
}

async fn get_channels(access_token: &str, cursor: String) -> Result<Channels, String> {
	let response = new_http_client()
		.get(format!("https://slack.com/api/conversations.list?limit={}&cursor={}&types=public_channel,private_channel,im", CHANNELS_PER_PAGE, cursor))
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
		.get(format!(
			"https://slack.com/api/conversations.info?channel={}",
			channel
		))
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
	let access_token = decrypt(body.state.as_str());
	let cursor = body.cursor.unwrap_or_default();
	match get_channels(&access_token, cursor).await {
		Ok(mut chs) => {
			let rs: Vec<Value> = chs
				.channels
				.iter_mut()
				.filter_map(|ch| {
					if ch.is_channel.is_some() && ch.is_channel.unwrap() {
						return Some(serde_json::json!({
							"field": format!("# {}", ch.name.take().unwrap_or_else(|| "no name".to_string())),
							"value": ch.id
						}));
					} else if ch.is_im.is_some()
						&& ch.is_im.unwrap() && ch.user.is_some()
						&& ch.user.take().unwrap().eq(&body.user)
					{
						return Some(serde_json::json!({
							"field": "Direct Message with App",
							"value": ch.id
						}));
					}
					None
				})
				.collect();
			let result = match chs.response_metadata.next_cursor.as_str() {
				"" => {
					serde_json::json!({ "list": rs })
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
		Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
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
	let access_token = decrypt(req.state.as_str());

	return match view_channel(&access_token, &req.value).await {
		Some(ch) => {
			if ch.is_channel.is_some()
				&& ch.is_channel.unwrap()
				&& (ch.is_member.is_some() && !ch.is_member.unwrap())
			{
				match join_channel_inner(&req.value, &access_token).await {
					Ok(v) => Ok((StatusCode::CREATED, Json(v))),
					Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg)),
				}
			} else {
				Ok((StatusCode::OK, Json(())))
			}
		}
		None => Err((StatusCode::BAD_REQUEST, "Channel not found".to_string())),
	};
}

async fn join_channel_inner(channel: &str, access_token: &str) -> Result<(), String> {
	let param = serde_json::json!({ "channel": channel });
	let response = new_http_client()
		.post(format!("https://slack.com/api/conversations.join"))
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
