#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;
use wasmhaiku_glue::{async_fileparts_request, async_request, fileparts::FileParts, RequestMethod};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct ForwardRoute {
	route: String,
	value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
	forwards: Vec<ForwardRoute>,
}

#[derive(Debug, Deserialize, Serialize)]
struct UploadBody {
	user: String,
	text: Option<String>,
	state: String,
	forwards: String,
}

#[wasmedge_bindgen]
pub fn post(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let post_body: PostBody = match serde_json::from_slice(&body) {
		Ok(s) => s,
		Err(_) => return (400, String::from("Invalid input"), vec![]),
	};

	for pb in post_body.forwards.iter() {
		if pb.route.eq("channels") {
			let req_body = serde_json::json!({
				"channel": pb.value,
				"text": post_body.text,
			});
			let req_body = serde_json::to_vec(&req_body).unwrap();

			let mut headers = HashMap::new();
			headers.insert(
				"Authorization",
				format!("Bearer {}", crate::decrypt(&post_body.state)),
			);
			headers.insert("Content-Type", String::from("application/json"));

			let _ = async_request(
				String::from("https://slack.com/api/chat.postMessage"),
				RequestMethod::POST,
				headers,
				req_body,
			);
		}
	}

	(200, String::new(), vec![])
}

#[wasmedge_bindgen]
pub fn upload(
	headers: String,
	queries: String,
	body: Vec<u8>,
	fileparts: Vec<u8>,
) -> (u16, String, Vec<u8>) {
	let upload_body: UploadBody = match serde_json::from_slice(&body) {
		Ok(s) => s,
		Err(_) => return (400, String::from("Invalid input"), vec![]),
	};

	let forwards = match serde_json::from_str::<Vec<ForwardRoute>>(&upload_body.forwards) {
		Ok(fws) => fws,
		Err(_) => return (400, String::from("Invalid input"), vec![]),
	};

	let mut upload_channels = vec![];
	for pb in forwards.iter() {
		if pb.route.eq("channels") {
			upload_channels.push(pb.value.as_str());

			if upload_body.text.is_some() {
				let req_body = serde_json::json!({
					"channel": pb.value,
					"text": upload_body.text,
				});
				let req_body = serde_json::to_vec(&req_body).unwrap();

				{
					let mut headers = HashMap::new();
					headers.insert(
						"Authorization",
						format!("Bearer {}", crate::decrypt(&upload_body.state)),
					);
					headers.insert("Content-Type", String::from("application/json"));

					let _ = async_request(
						String::from("https://slack.com/api/chat.postMessage"),
						RequestMethod::POST,
						headers,
						req_body,
					);
				}
			}
		}
	}

	let fps: FileParts = fileparts.into();
	let req_body = serde_json::json!({
		"channels": upload_channels.join(",")
	});
	let req_body = serde_json::to_vec(&req_body).unwrap();
	let mut headers = HashMap::new();
	headers.insert(
		"Authorization",
		format!("Bearer {}", crate::decrypt(&upload_body.state)),
	);

	for fp in fps.inner.into_iter() {
		let _ = async_fileparts_request(
			String::from("https://slack.com/api/files.upload"),
			RequestMethod::POST,
			headers.clone(),
			req_body.clone(),
			FileParts { inner: vec![fp] },
		);
	}

	(200, String::new(), vec![])
}
