#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;
use wasmhaiku_glue::{request, RequestMethod};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use serde_json::Value;

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
		return (400, String::new(), b"No code".to_vec());
	}

	match get_access_token(code.unwrap().as_str()) {
		Ok(at) => {
			if at.ok {
				let authed_user = at.authed_user.unwrap();
				match get_authed_user(&authed_user.access_token) {
					Ok(gu) => {
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}",
							crate::HAIKU_API_PREFIX.as_str(),
							authed_user.id,
							gu,
							crate::encrypt(at.access_token.unwrap().as_str())
						);

						let headers = serde_json::json!({ "Location": location });
						let headers = serde_json::to_string(&headers).unwrap();
						(302, headers, vec![])
					}
					Err(err_msg) => (500, String::new(), err_msg.as_bytes().to_vec()),
				}
			} else {
				(400, String::new(), b"Invalid code".to_vec())
			}
		}
		Err(err_msg) => (500, String::new(), err_msg.as_bytes().to_vec()),
	}
}

fn get_access_token(code: &str) -> Result<OAuthAccessBody, String> {
	let req_body = serde_json::json!({
		"client_id": crate::SLACK_APP_CLIENT_ID.as_str(),
		"client_secret": crate::SLACK_APP_CLIENT_SECRET.as_str(),
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
				Err(_) => Err(String::from("Failed to get user's name")),
			},
			_ => Err(String::from("Failed to get user's profile")),
		},
		Err(_) => Err(String::from("Failed to get user's profile")),
	}
}
