#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;
use wasmhaiku_glue::{
	async_fileparts_request, async_request,
	fileparts::{FilePart, FileParts},
	request, RequestMethod,
};

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct EventBody {
	challenge: Option<String>,
	event: Option<Event>,
}

#[derive(Debug, Deserialize)]
struct Event {
	bot_id: Option<String>,
	client_msg_id: Option<String>,
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

	(100, String::new(), vec![])
}

#[wasmedge_bindgen]
pub fn async_event(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
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
		headers.insert("Authorization", crate::HAIKU_AUTH_TOKEN.to_string());
		headers.insert("Content-Type", String::from("application/json"));

		let _ = async_request(
			String::from(format!(
				"{}/api/_funcs/_post",
				crate::HAIKU_API_PREFIX.as_str()
			)),
			RequestMethod::POST,
			headers,
			req_body,
		);
	} else if let Ok(access_token) = get_author_token_from_reactor(&user) {
		let req_body = serde_json::json!({
			"user": user,
			"text": text,
			"triggers": format!(r#"{{"channels": "{}"}}"#, channel),
		});
		let req_body = serde_json::to_vec(&req_body).unwrap();

		let fileparts: Vec<FilePart> = files
			.into_iter()
			.filter_map(|f| {
				if let Ok(b) = get_file(&access_token, &f.url_private) {
					return Some(FilePart {
						file_name: f.name,
						mime_str: f.mimetype,
						bytes: b,
					});
				}
				None
			})
			.collect();
		let fileparts = FileParts { inner: fileparts };

		let mut headers = HashMap::new();
		headers.insert("Authorization", crate::HAIKU_AUTH_TOKEN.to_string());

		let _ = async_fileparts_request(
			String::from(format!(
				"{}/api/_funcs/_upload",
				crate::HAIKU_API_PREFIX.as_str()
			)),
			RequestMethod::POST,
			headers,
			req_body,
			fileparts,
		);
	}
}

fn get_author_token_from_reactor(user: &str) -> Result<String, ()> {
	let req_body = serde_json::json!({ "author": user });
	let req_body = serde_json::to_vec(&req_body).unwrap();

	let mut headers = HashMap::new();
	headers.insert("Authorization", crate::HAIKU_AUTH_TOKEN.to_string());
	headers.insert("Content-Type", String::from("application/json"));

	match request(
		String::from(format!(
			"{}/api/_funcs/_author_state",
			crate::HAIKU_API_PREFIX.as_str()
		)),
		RequestMethod::POST,
		headers,
		req_body,
	) {
		Ok((status, r)) => {
			if status >= 200 && status <= 299 {
				match String::from_utf8(r) {
					Ok(s) => Ok(crate::decrypt(s.as_str())),
					Err(_) => Err(()),
				}
			} else {
				Err(())
			}
		}
		Err(_) => Err(()),
	}
}

fn get_file(access_token: &str, url_private: &str) -> Result<Vec<u8>, ()> {
	let mut headers = HashMap::new();
	headers.insert("Authorization", format!("Bearer {}", access_token));

	match request(
		String::from(url_private),
		RequestMethod::GET,
		headers,
		vec![],
	) {
		Ok((status, r)) => {
			if status >= 200 && status <= 299 {
				Ok(r)
			} else {
				Err(())
			}
		}
		Err(_) => Err(()),
	}
}
