use std::env;
use std::time::{Duration};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};
use reqwest::{Client, ClientBuilder};
use axum::{
	Router,
	routing::{get, post, delete},
	extract::{Query, Json},
	response::{IntoResponse},
	http::{StatusCode,header},
};

lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");

	static ref GITLAB_APP_CLIENT_ID: String = env::var("GITLAB_APP_CLIENT_ID").expect("Env variable GITLAB_APP_CLIENT_ID not set");
	static ref GITLAB_APP_CLIENT_SECRET: String = env::var("GITLAB_APP_CLIENT_SECRET").expect("Env variable GITLAB_APP_CLIENT_SECRET not set");
	static ref GITLAB_REDIRECT_URL: String = env::var("GITLAB_REDIRECT_URL").expect("Env variable GITLAB_REDIRECT_URL not set");
	static ref SERVICE_API_PREFIX: String = env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");

	static ref PASSPHRASE: String = env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref PRIVATE_KEY_PEM: String = env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");

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
}

async fn get_access_token(code: &str) -> Result<OAuthBody, String> {

	let params = [
		("client_id", GITLAB_APP_CLIENT_ID.as_str()), 
		("client_secret", GITLAB_APP_CLIENT_SECRET.as_str()),
	    ("grant_type", "authorization_code"),
		("code", &code),
		("redirect_uri", GITLAB_REDIRECT_URL.as_str()),
	];

	let response = new_http_client().post("https://gitlab.com/oauth/token")
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

	// println!("{}",access_token);

	let response = new_http_client().get("https://gitlab.com/api/v4/user")
		.bearer_auth(access_token)
		.send()
		.await;

	match response {
		Ok(res) => {
			match res.text().await {
				Ok(body) => {
					if let Ok(v) = serde_json::from_str::<Value>(&body) {
						let user_id = v["id"].to_string();
						let user_name = v["username"].as_str().unwrap().to_string();
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

#[derive(Deserialize)]
struct RefreshState {
	refresh_state: String,
}

async fn refresh_token(Json(msg_body): Json<RefreshState>) -> impl IntoResponse {

	let params = [
		("client_id", GITLAB_APP_CLIENT_ID.as_str()), 
		("client_secret", GITLAB_APP_CLIENT_SECRET.as_str()),
	    ("grant_type", "refresh_token"),
		("refresh_token", &decrypt(&msg_body.refresh_state)),
	];

	let response = new_http_client().post("https://gitlab.com/oauth/token")
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
struct ProjectName {
	id: u64,
	name: String,
}

#[derive(Deserialize)]
struct RouteReq {
	state: String,
}

async fn get_projects(token: &str) -> Result<Vec<ProjectName>, String> {
	let response = new_http_client()
		.get(format!("https://gitlab.com/api/v4/projects?access_token={}&owned=true",token))
		.send()
		.await;
	if let Ok(r) = response {
		let data = r.text().await.unwrap();
		let channels: Vec<ProjectName> = serde_json::from_str(&data).unwrap();
		return Ok(channels);
	}
	Err("Failed to get channels".to_string())
}

async fn projects(Json(body): Json<RouteReq>) -> impl IntoResponse {
	let authstate = decrypt(&body.state);
	let mut token = body.state;


	if let Ok(v) = serde_json::from_str::<Value>(&authstate) {
		token = v["access_token"].as_str().unwrap().to_string();
	}

	// println!("{}",token);

	match get_projects(&token).await {
		Ok(mut chs) => {
			let rs: Vec<Value> = chs.iter_mut().filter_map(|ch| {
				if true {
					return Some(serde_json::json!({
						"field": format!("# {}", ch.name),
						"value": ch.id.to_string()
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

#[derive(Debug, Deserialize)]
struct FieldValue {
	// field: String,
	value: String,
}
#[derive(Debug, Deserialize)]
struct HookEvents {
	events: Vec<FieldValue>,
}
#[derive(Debug, Deserialize)]
struct HookReq {
	user: String,
    state: String,
	field: String,
	value: String,
	flow: Option<String>,
	custom: Option<HookEvents>,
}

async fn hook_events() -> impl IntoResponse {
	let events = serde_json::json!({
		"list": [
			{
				"field": "push",
				"value": "push"
			},
			{
				"field": "issue",
				"value": "issue"
			}
		]
	});
	Json(events)
}

#[derive(Serialize, Deserialize)]
struct OAuthState {
	access_token: String,
}

async fn create_hook(Json(req): Json<HookReq>) -> impl IntoResponse {
	if req.custom.is_none() || req.flow.is_none() {
		return Err((StatusCode::BAD_REQUEST, "Not enough parameter".to_string()));
	}

	let auth_state = serde_json::from_str::<OAuthState>(&decrypt(&req.state)).unwrap();

	let events: Vec<String> = req.custom.unwrap().events.iter().map(|e| {e.value.clone()}).collect();
			
	// println!("{}",auth_state.access_token);
	// println!("{:?}",events);

	match create_hook_inner(&req.user, &req.flow.unwrap(), &req.field, events, &auth_state.access_token, &req.value).await {
		Ok(v) => {
			Ok((StatusCode::CREATED, Json(v)))
		}
		Err(err_msg) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn create_hook_inner(connector: &str, flow_id: &str, repo_full_name: &str, events: Vec<String>, token: &str, id: &str) -> Result<Value, String> {
	let param = json!({
		"id": id,
		"url": format!("{}/event?connector={connector}&flow={flow_id}",SERVICE_API_PREFIX.as_str()),
		"token": token,
		"push_events": true,
		"tag_push_events": true,
		"merge_requests_events": true,
		"issues_events": true
	});
	let response = new_http_client().post(format!("https://gitlab.com/api/v4/projects/{}/hooks",id))
		.header("Accept", "application/json")
		.bearer_auth(token)
		.json(&param)
		.send()
		.await;
	if let Ok(r) = response {
		if r.status().is_success() {
			if let Ok(body) = r.bytes().await {
				let json_body: Value = serde_json::from_slice(&body).unwrap();
				let hook_id = json_body["id"].to_string();
				let result = serde_json::json!({
					"revoke": format!("{}/revoke-hook?hook_id={hook_id}&project={id}", SERVICE_API_PREFIX.as_str()),
				});
				return Ok(result);
			}
		}
	}
	Err("Failed to create hook".to_string())
}

#[derive(Deserialize)]
struct EventQuery {
	connector: String,
	flow: String
}

async fn capture_event(Json(event): Json<Value>, Query(query): Query<EventQuery>) -> impl IntoResponse {
	// println!("{:?} {} {}",event,query.connector,query.flow);
	let connector = query.connector;
	let flow = query.flow;
	tokio::spawn(capture_event_inner(event,connector,flow));
	(StatusCode::OK, String::new())
}

async fn capture_event_inner(event: Value, connector: String, flow: String) {
	let te = event["object_kind"].as_str().unwrap();

	let mut project: Value = serde_json::from_str(&event["project"].to_string()).unwrap();

	let triggers = serde_json::json!({
		"events": "issue",
		"projects": project["id"],
	});

	// println!("{} {} {} {}",&connector, &flow, &event.to_string(), triggers);

	post_event_to_reactor(&connector, &flow, &event.to_string(), triggers).await;

}

async fn post_event_to_reactor(user: &str, flow: &str, text: &str, triggers: Value) {
	let request = serde_json::json!({
		"user": user,
		"flow": flow,
		"text": text,
		"triggers": triggers,
	});

	let response = new_http_client().post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
		.header(header::AUTHORIZATION, REACTOR_AUTH_TOKEN.as_str())
		.json(&request)
		.send()
		.await;
	if let Err(e) = response {
		println!("{:?}", e);
	}
}

#[derive(Deserialize)]
struct RevokeQuery {
	hook_id: String,
	project: String
}

#[derive(Debug, Deserialize)]
struct RevokeHookReq {
    state: String
}

async fn revoke_hook(Json(req): Json<RevokeHookReq>, Query(query): Query<RevokeQuery>) -> impl IntoResponse {
	let auth_state = serde_json::from_str::<OAuthState>(&decrypt(&req.state)).unwrap();

	match revoke_hook_inner(&query.project, &query.hook_id, &auth_state.access_token).await {
		Ok(()) => {
			Ok(StatusCode::OK)
		}
		Err(err_msg) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn revoke_hook_inner(project: &str, hook_id: &str, token: &str) -> Result<(), String> {
	let response = new_http_client().delete(format!("https://gitlab.com/api/v4/projects/{}/hooks/{}",project,hook_id))
		.bearer_auth(token)
		.send()
		.await;
	
	return Ok(());
}

#[tokio::main]
async fn main() {
	let app = Router::new()
		.route("/auth", get(auth))
		.route("/refresh", post(refresh_token))
		.route("/projects", post(projects))
		.route("/create-hook", post(create_hook))
		.route("/revoke-hook", delete(revoke_hook))
		.route("/hook-events", post(hook_events))
		.route("/event", post(capture_event));

	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));

	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}