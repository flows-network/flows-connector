#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;
use wasmhaiku_host::{async_request, request, RequestMethod};

use std::{collections::HashMap, env};

use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde_json::Value;

static RSA_BITS: usize = 2048;

lazy_static! {
	// static ref HAIKU_API_PREFIX: String = env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
	// static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED").expect("Env variable RSA_RAND_SEED not set").as_bytes().try_into().unwrap();
	// static ref HAIKU_AUTH_TOKEN: String = env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
	// static ref SLACK_APP_CLIENT_ID: String = env::var("SLACK_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
	// static ref SLACK_APP_CLIENT_SECRET: String = env::var("SLACK_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");

	static ref HAIKU_API_PREFIX: String = String::from("http://127.0.0.1:3000");
	static ref RSA_RAND_SEED: [u8; 32] = "wWuE6hfm7mMCjq$2eefEv2Y@2aeLYNUn".as_bytes().try_into().unwrap();
	static ref HAIKU_AUTH_TOKEN: String = String::from("2b72aea305fd3ac2dd1f903fb1dbdf050c113aca");
	static ref SLACK_APP_CLIENT_ID: String = String::from("3029929096563.3015312061287");
	static ref SLACK_APP_CLIENT_SECRET: String = String::from("b441d2041ab46bd0664b5f7a45eaeebd");

	static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
	static ref PRIV_KEY: RsaPrivateKey = RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
	static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
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

#[wasmedge_bindgen]
pub fn init() {
	/// Init PRIV_KEY for its slow generation time
	encrypt("");
	println!("Keys has been initialized");
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

/// Return a auth response
///
/// headers is a JSON string
/// queries is a JSON string
///
/// Return (status: u32, headers: JSON string, body: Vec<u8>)
#[wasmedge_bindgen]
pub fn auth(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let code = match serde_json::from_str::<Value>(queries.as_str()) {
		Ok(v) => {
			if v["code"].is_string() {
				Some(v["code"].as_str().unwrap().to_string())
			} else {
				None
			}
		}
		Err(_) => None,
	};

	if code.is_none() {
		return (400, String::new(), "No code".as_bytes().to_vec());
	}

	match get_access_token(code.unwrap().as_str()) {
		Ok(at) => {
			if at.ok {
				let authed_user = at.authed_user.unwrap();
				match get_authed_user(&authed_user.access_token) {
					Ok(gu) => {
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}",
							HAIKU_API_PREFIX.as_str(),
							authed_user.id,
							gu,
							encrypt(at.access_token.unwrap().as_str())
						);

						let headers = serde_json::json!({ "Location": location });
						let headers = serde_json::to_string(&headers).unwrap();
						(302, headers, vec![])
					}
					Err(err_msg) => (500, String::new(), err_msg.as_bytes().to_vec()),
				}
			} else {
				(400, String::new(), "Invalid code".as_bytes().to_vec())
			}
		}
		Err(err_msg) => (500, String::new(), err_msg.as_bytes().to_vec()),
	}
}

fn get_access_token(code: &str) -> Result<OAuthAccessBody, String> {
	let req_body = serde_json::json!({
		"client_id": SLACK_APP_CLIENT_ID.as_str(),
		"client_secret": SLACK_APP_CLIENT_SECRET.as_str(),
		"code": code,
	});
	let req_body = serde_urlencoded::to_string(&req_body)
		.unwrap()
		.as_bytes()
		.to_vec();

	let mut headers = HashMap::new();
	headers.insert(
		"Content-Type",
		String::from("application/x-www-form-urlencoded"),
	);

	match request(
		String::from("https://slack.com/api/oauth.v2.access"),
		RequestMethod::POST,
		headers,
		req_body,
	) {
		Ok((status, r)) => match status {
			200..=299 => match serde_json::from_slice::<OAuthAccessBody>(&r) {
				Ok(oauth_body) => Ok(oauth_body),
				Err(_) => Err(String::from("Failed to get access token")),
			},
			_ => Err(String::from("Failed to get access token")),
		},
		Err(_) => Err(String::from("Failed to get access token")),
	}
}

fn get_authed_user(access_token: &str) -> Result<String, String> {
	let mut headers = HashMap::new();
	headers.insert("Authorization", format!("Bearer {}", access_token));

	match request(
		String::from("https://slack.com/api/users.profile.get"),
		RequestMethod::GET,
		headers,
		vec![],
	) {
		Ok((status, r)) => match status {
			200..=299 => match serde_json::from_slice::<Value>(&r) {
				Ok(v) => Ok(v["profile"]["real_name"].as_str().unwrap().to_string()),
				Err(e) => {
					println!("{:?}", e);
					Err(String::from("Failed to get user's name"))
				}
			},
			_ => Err(String::from("Failed to get user's profile")),
		},
		Err(_) => Err(String::from("Failed to get user's profile")),
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
	// name: String,
// mimetype: String,
// url_private: String,
}

#[wasmedge_bindgen]
pub fn event(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let evt_body: EventBody = match serde_json::from_slice(&body) {
		Ok(s) => s,
		Err(_) => return (400, String::from("Invalid input"), vec![]),
	};

	// For slack to verify
	if let Some(challenge) = evt_body.challenge {
		return (200, String::new(), challenge.as_bytes().to_vec());
	}

	if let Some(evt) = evt_body.event {
		// Only handle message which is sent by user
		if evt.bot_id.is_none() {
			let user = evt.user.unwrap_or_else(|| String::from(""));
			let text = evt.text.unwrap_or_else(|| String::from(""));
			let files = evt.files.unwrap_or_else(|| Vec::new());
			let channel = evt.channel.unwrap_or_default();
			post_event_to_reactor(user, text, files, channel);
		}
	}

	(200, String::new(), vec![])
}

fn post_event_to_reactor(user: String, text: String, files: Vec<File>, channel: String) {
	if files.len() == 0 {
		let req_body = serde_json::json!({
			"user": user,
			"text": text,
			"triggers": {
				"channels": channel
			}
		});
		let req_body = serde_json::to_vec(&req_body).unwrap();

		let mut headers = HashMap::new();
		headers.insert("Authorization", HAIKU_AUTH_TOKEN.to_string());
		headers.insert("Content-Type", String::from("application/json"));

		let _ = async_request(
			String::from(format!("{}/api/_funcs/_post", HAIKU_API_PREFIX.as_str())),
			RequestMethod::POST,
			headers,
			req_body,
		);
	}
}

fn get_author_token_from_reactor(user: &str) -> Result<String, ()> {
	let req_body = serde_json::json!({ "author": user });
	let req_body = serde_json::to_vec(&req_body).unwrap();

	let mut headers = HashMap::new();
	headers.insert("Authorization", HAIKU_AUTH_TOKEN.to_string());
	headers.insert("Content-Type", String::from("application/json"));

	match request(
		String::from(format!(
			"{}/api/_funcs/_author_state",
			HAIKU_API_PREFIX.as_str()
		)),
		RequestMethod::POST,
		headers,
		req_body,
	) {
		Ok((status, r)) => {
			if status >= 200 && status <= 299 {
				match String::from_utf8(r) {
					Ok(s) => Ok(decrypt(s.as_str())),
					Err(_) => Err(()),
				}
			} else {
				Err(())
			}
		}
		Err(_) => Err(()),
	}
}
