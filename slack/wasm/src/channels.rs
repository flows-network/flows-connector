#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;
use wasmhaiku_glue::{request, RequestMethod};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use serde_json::Value;

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

#[derive(Debug, Deserialize)]
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

#[wasmedge_bindgen]
pub fn channels(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let route_req: RouteReq = match serde_json::from_slice(&body) {
		Ok(s) => s,
		Err(_) => return (400, String::from("Invalid input"), vec![]),
	};

	let access_token = crate::decrypt(route_req.state.as_str());
	let cursor = route_req.cursor.unwrap_or_default();

	let resp_headers = serde_json::json!({
		"Content-Type": "application/json",
	});
	let resp_headers = serde_json::to_string(&resp_headers).unwrap();

	match get_channels(&access_token, cursor) {
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
						&& ch.user.take().unwrap().eq(&route_req.user)
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
			(200, resp_headers, serde_json::to_vec(&result).unwrap())
		}
		Err(err_msg) => (500, String::new(), err_msg.as_bytes().to_vec()),
	}
}

fn get_channels(access_token: &str, cursor: String) -> Result<Channels, String> {
	let mut headers = HashMap::new();
	headers.insert("Authorization", format!("Bearer {}", access_token));

	if let Ok((status, body)) = request(
		format!("https://slack.com/api/conversations.list?limit={}&cursor={}&types=public_channel,private_channel,im", CHANNELS_PER_PAGE, cursor),
		RequestMethod::GET,
		headers,
		vec![]
	) {
		if (200..=299).contains(&status) {
			if let Ok(chs) = serde_json::from_slice::<Channels>(&body) {
				if chs.ok {
					return Ok(chs);
				}
			}
		}
	}

	Err(String::from("Failed to get installed repositories"))
}

#[derive(Debug, Deserialize)]
struct JoinChannelReq {
	// user: String,
	state: String,
	// field: String,
	value: String,
}

#[wasmedge_bindgen]
pub fn join_channel(headers: String, queries: String, body: Vec<u8>) -> (u16, String, Vec<u8>) {
	let join_req: JoinChannelReq = match serde_json::from_slice(&body) {
		Ok(s) => s,
		Err(_) => return (400, String::from("Invalid input"), vec![]),
	};

	let access_token = crate::decrypt(join_req.state.as_str());

	let resp_headers = serde_json::json!({
		"Content-Type": "application/json",
	});
	let resp_headers = serde_json::to_string(&resp_headers).unwrap();

	match view_channel(&access_token, &join_req.value) {
		Some(ch) => match ch.is_channel.is_some()
			&& ch.is_channel.unwrap()
			&& (ch.is_member.is_some() && !ch.is_member.unwrap())
		{
			true => match join_channel_inner(&join_req.value, &access_token) {
				Ok(v) => (201, resp_headers, b"{}".to_vec()),
				Err(err_msg) => (500, String::new(), err_msg.as_bytes().to_vec()),
			},
			false => (200, resp_headers, b"{}".to_vec()),
		},
		None => (400, String::new(), b"Channel not found".to_vec()),
	}
}

fn view_channel(access_token: &str, channel: &str) -> Option<Channel> {
	let mut headers = HashMap::new();
	headers.insert("Authorization", format!("Bearer {}", access_token));

	if let Ok((status, body)) = request(
		format!(
			"https://slack.com/api/conversations.info?channel={}",
			channel
		),
		RequestMethod::GET,
		headers,
		vec![],
	) {
		if (200..=299).contains(&status) {
			if let Ok(ci) = serde_json::from_slice::<ChannelInfo>(&body) {
				if ci.ok {
					return ci.channel;
				}
			}
		}
	}

	None
}

fn join_channel_inner(channel: &str, access_token: &str) -> Result<(), String> {
	let req_body = serde_json::json!({ "channel": channel });
	let req_body = serde_json::to_vec(&req_body).unwrap();

	let mut headers = HashMap::new();
	headers.insert("Authorization", format!("Bearer {}", access_token));
	headers.insert("Content-Type", String::from("application/json"));

	if let Ok((status, body)) = request(
		String::from("https://slack.com/api/conversations.join"),
		RequestMethod::POST,
		headers,
		req_body,
	) {
		if (200..=299).contains(&status) {
			if let Ok(body) = serde_json::from_slice::<Value>(&body) {
				if let Some(ok) = body["ok"].as_bool() {
					if ok {
						return Ok(());
					}
				}
			}
		}
	}

	Err("Failed to create hook".to_string())
}
