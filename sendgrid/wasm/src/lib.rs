#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;
use wasmhaiku_glue::{async_request, RequestMethod};

use std::{collections::HashMap, env};

use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use regex::Regex;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use url::form_urlencoded::parse;

static RSA_BITS: usize = 2048;

lazy_static! {
	// static ref HAIKU_API_PREFIX: String = env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
	// static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED").expect("Env variable RSA_RAND_SEED not set").as_bytes().try_into().unwrap();
	static ref HAIKU_API_PREFIX: String = String::from("http://127.0.0.1:3000");
	static ref RSA_RAND_SEED: [u8; 32] = "wWuE6hfm7mMCjq$2eefEv2Y@2aeLYNUn".as_bytes().try_into().unwrap();
	static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
	static ref PRIV_KEY: RsaPrivateKey = RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
	static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
}

static CONNECT_HTML: &str = include_str!("../../src/connect.html");

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

/// Return a connect html
///
/// headers is a JSON string
/// queries is a JSON string
///
/// Return (status: u32, headers: JSON string, body: Vec<u8>)
#[wasmedge_bindgen]
pub fn connect(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let headers = serde_json::json!({
		"Content-Type": "text/html"
	});
	let headers = serde_json::to_string(&headers).unwrap();
	return (200, headers, CONNECT_HTML.as_bytes().to_vec());
}

#[wasmedge_bindgen]
pub fn auth(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let parsed_form = parse(&body);
	let (sender_email, api_key) = parsed_form.into_iter().fold((None, None), |accu, x| {
		if x.0.eq("sender_email") {
			return (Some(x.1.into_owned()), accu.1);
		} else if x.0.eq("api_key") {
			return (accu.0, Some(x.1.into_owned()));
		}
		return accu;
	});

	if sender_email.is_none() || api_key.is_none() {
		return (
			400,
			String::new(),
			String::from("Params are required").as_bytes().to_vec(),
		);
	}
	let sender_email = sender_email.unwrap();
	let api_key = api_key.unwrap();

	let email_regex = Regex::new(r#"^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"#).unwrap();
	if !email_regex.is_match(&sender_email.to_lowercase()) {
		return (
			400,
			String::new(),
			String::from("Invalid email").as_bytes().to_vec(),
		);
	}
	let api_key_regex = Regex::new(r"^.{50,}$").unwrap();
	if !api_key_regex.is_match(&api_key) {
		return (
			400,
			String::new(),
			String::from("Invalid api key").as_bytes().to_vec(),
		);
	}
	let location = format!(
		"{}/api/connected?authorId={}&authorName={}&authorState={}",
		HAIKU_API_PREFIX.as_str(),
		sender_email,
		sender_email,
		encrypt(&api_key)
	);

	let headers = serde_json::json!({ "Location": location });
	let headers = serde_json::to_string(&headers).unwrap();
	(302, headers, Vec::new())
}

#[derive(Debug, Serialize, Deserialize)]
struct MailBody {
	to_email: String,
	subject: String,
	content: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
}

#[wasmedge_bindgen]
pub fn post(_: String, _: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let pb: PostBody = match serde_json::from_slice(&body) {
		Ok(b) => b,
		Err(_) => {
			return (400, String::new(), b"Invalid body".to_vec());
		}
	};

	return match serde_json::from_str::<MailBody>(&pb.text) {
		Ok(mb) => {
			let req_body = serde_json::json!({
				"personalizations": [
					{
						"to": [
							{
								"email": mb.to_email
							}
						]
					}
				],
				"from": {
					"email": pb.user
				},
				"subject": mb.subject,
				"content": [
					{
						"type": "text/html",
						"value": mb.content
					}
				]
			});
			let req_body = serde_json::to_vec(&req_body).unwrap();

			let mut headers = HashMap::new();
			headers.insert("Authorization", format!("Bearer {}", decrypt(&pb.state)));
			headers.insert("Content-Type", String::from("application/json"));

			match async_request(
				String::from("https://api.sendgrid.com/v3/mail/send"),
				RequestMethod::POST,
				headers,
				req_body,
			) {
				Ok(_) => (200, String::new(), vec![]),
				Err(e) => (500, String::new(), e.as_bytes().to_vec()),
			}
		}
		Err(_) => (400, String::new(), b"Invalid mail body".to_vec()),
	};
}
