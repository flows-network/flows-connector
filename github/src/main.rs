use std::env;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{Public, Private};
use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};
use reqwest::{Client, ClientBuilder};
use axum::{
	Router,
	routing::{get, post, delete},
	extract::{Query, Json, Form},
	response::{IntoResponse},
	http::{StatusCode, header},
};

#[derive(Debug, Deserialize, Serialize)]
struct AuthBody {
	code: String,
	installation_id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct AccessTokenBody {
	access_token: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenBody {
	token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuthState {
	access_token: String,
	installation_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstRepo {
	node_id: String,
	name: String,
	full_name: String,
	html_url: String,
	hooks_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstalledRepos {
	total_count: u32,
	repositories: Vec<InstRepo>,
}

const REPOS_PER_PAGE: u32 = 20;

lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
	static ref GITHUB_APP_INSTALL_LOCATION: String = env::var("GITHUB_APP_INSTALL_LOCATION").expect("Env variable GITHUB_APP_INSTALL_LOCATION not set");

	static ref GITHUB_APP_ID: String = env::var("GITHUB_APP_ID").expect("Env variable GITHUB_APP_ID not set");
	static ref GITHUB_PRIVATE_KEY: String = env::var("GITHUB_APP_PRIVATE_KEY").expect("Env variable GITHUB_APP_PRIVATE_KEY not set");

	static ref SERVICE_API_PREFIX: String = env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");

	static ref GITHUB_CLIENT_ID: String = env::var("GITHUB_APP_CLIENT_ID").expect("Env variable GITHUB_APP_CLIENT_ID not set");
	static ref GITHUB_CLIENT_SECRET: String = env::var("GITHUB_APP_CLIENT_SECRET").expect("Env variable GITHUB_APP_CLIENT_SECRET not set");

	static ref PASSPHRASE: String = env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref PRIVATE_KEY_PEM: String = env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");

	
	static ref RSA_PRIVATE_KEY: Rsa<Private> = Rsa::private_key_from_pem_passphrase(PRIVATE_KEY_PEM.as_bytes(), PASSPHRASE.as_bytes()).unwrap();
	static ref RSA_PUBLIC_KEY: Rsa<Public> = Rsa::public_key_from_pem(PUBLIC_KEY_PEM.as_bytes()).unwrap();
}

const TIMEOUT: u64 = 120;

fn new_http_client() -> Client {
	let cb = ClientBuilder::new().timeout(Duration::from_secs(TIMEOUT));
	return cb.build().unwrap();
}

fn get_now() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
	return since_the_epoch.as_secs();
}

fn encrypt(data: &str) -> String {
	let mut buf: Vec<u8> = vec![0; RSA_PUBLIC_KEY.size() as usize];
	RSA_PUBLIC_KEY.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
	hex::encode(buf)
}

fn decrypt(hex: &str) -> String {
	let mut buf: Vec<u8> = vec![0; RSA_PRIVATE_KEY.size() as usize];
	let l = RSA_PRIVATE_KEY.private_decrypt(&hex::decode(hex).unwrap(), &mut buf, Padding::PKCS1).unwrap();
	String::from_utf8(buf[..l].to_vec()).unwrap()
}

async fn auth(Query(auth_body): Query<AuthBody>) -> impl IntoResponse {
	if auth_body.code.eq("") {
		Err((StatusCode::BAD_REQUEST, "No code".to_string()))
	} else {
		match get_access_token(&auth_body.code).await {
			Ok(at) => {
				match get_authed_user(&at.access_token).await {
					Ok(gu) => {
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}",
							REACTOR_API_PREFIX.as_str(),
							gu.node_id,
							gu.login,
							encrypt(&serde_json::to_string(&AuthState {
								access_token: at.access_token,
								installation_id: auth_body.installation_id,
							}).unwrap())
						);
						Ok((StatusCode::FOUND, [(header::LOCATION, location)]))
					}
					Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
				}
			}
			Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn get_access_token(code: &str) -> Result<AccessTokenBody, String> {
	let params = [
		("client_id", GITHUB_CLIENT_ID.as_ref()),
		("client_secret", GITHUB_CLIENT_SECRET.as_ref()),
		("code", code)
	];

	let response = new_http_client().post("https://github.com/login/oauth/access_token")
		.header(header::ACCEPT, "application/json")
		.form(&params)
		.send()
		.await;
	match response {
		Ok(r) => {
			let token_body = r.json::<AccessTokenBody>().await;
			match token_body {
				Ok(at) => {
					return Ok(at)
				},
				Err(_) => {
					return Err("Failed to get access token".to_string());
				}
			}
		},
		Err(_) => {
			return Err("Failed to get access token".to_string());
		}
	}
}

async fn get_installation_token(installation_id: u64) -> Result<String, String> {
	let now = get_now();
	let jwt_payload = json!({
		"iat": now - 60,
		"exp": now + 10 * 60,
		"iss": GITHUB_APP_ID.as_ref() as &str,
	});
	let jwt = encode(&Header::new(Algorithm::RS256), &jwt_payload, &EncodingKey::from_rsa_pem(GITHUB_PRIVATE_KEY.as_bytes()).unwrap()).unwrap();

	let response = new_http_client().post(format!("https://api.github.com/app/installations/{installation_id}/access_tokens"))
		.header(header::ACCEPT, "application/vnd.github.v3+json")
		.header(header::USER_AGENT, "Github Connector of Second State Reactor")
		.bearer_auth(jwt)
		.send()
		.await;
	match response {
		Ok(r) => {
			let token_body = r.json::<InstallationTokenBody>().await;
			match token_body {
				Ok(at) => {
					return Ok(at.token)
				},
				Err(_) => {
					return Err("Failed to get installation token".to_string());
				}
			}
		},
		Err(_) => {
			return Err("Failed to get installation token".to_string());
		}
	}
}

async fn get_installed_repositories(install_token: &str, page: u32) -> Result<InstalledRepos, String> {
	let response = new_http_client()
		.get(format!("https://api.github.com/installation/repositories?per_page={}&page={}", REPOS_PER_PAGE, page))
		.header(header::ACCEPT, "application/vnd.github.v3+json")
		.header(header::USER_AGENT, "Github Connector of Second State Reactor")
		.bearer_auth(install_token)
		.send()
		.await;
	match response {
		Ok(r) => {
			match r.json::<InstalledRepos>().await {
				Ok(repos) => {
					return Ok(repos)
				},
				Err(_) => {
					return Err("Failed to get installed repositories".to_string());
				}
			}
		},
		Err(_) => {
			return Err("Failed to get installed repositories".to_string());
		}
	}
}

#[derive(Debug, Deserialize)]
struct Event {
    connector: String,
	flow: String,
	payload: String,
}

async fn capture_event(Form(event): Form<Event>) -> impl IntoResponse {
	tokio::spawn(capture_event_inner(event));
	(StatusCode::OK, String::new())
}

async fn capture_event_inner(event: Event) {
	if let Ok(auth_state) = get_author_token_from_reactor(&event.connector).await {
		let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
		// println!("{}", serde_json::to_string_pretty(&payload).unwrap());
		let auth_state = serde_json::from_str::<AuthState>(&auth_state).unwrap();
		if let Ok(github_user) = get_github_user(payload["sender"]["url"].as_str().unwrap(), &auth_state.access_token).await {
			if let Some(email) = github_user.email {
				let obj = payload.as_object_mut().unwrap();
				obj.insert("sender_email".to_string(), email.into());
			}
			let te = match payload.get("starred_at") {
				Some(_) => {
					"star"
				}
				_ => {
					match payload["issue"] {
						Value::Object(_) => {
							match payload["comment"] {
								Value::Object(_) => {
									"issue_comment"
								}
								_ => "issues"
							}
						}
						_ => ""
					}
				}
			};
			let triggers = serde_json::json!({
				"events": te,
				"repo": payload["repository"]["node_id"].as_str().unwrap(),
			});

			post_event_to_reactor(&event.connector, &event.flow, &payload.to_string(), triggers).await;
		}
	}
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

#[derive(Debug, Deserialize)]
struct GithubUser {
	login: String,
	node_id: String,
	email: Option<String>
}


async fn get_authed_user(access_token: &str) -> Result<GithubUser, String> {
	let response = new_http_client().get("https://api.github.com/user")
		.bearer_auth(access_token)
		.header(header::USER_AGENT, "Github Connector of Second State Reactor")
		.send()
		.await;

	match response {
		Ok(res) => {
			let body = res.json::<GithubUser>().await;
			match body {
				Ok(gu) => {
					return Ok(gu);
				}
				Err(_) => {
					return Err("Failed to get user".to_string());
				}
			}
		}
		Err(_) => {
			return Err("Failed to get user".to_string());
		}
	}
}

async fn get_github_user(api_url: &str, access_token: &str) -> Result<GithubUser, ()> {
	let response = new_http_client().get(api_url)
		.bearer_auth(access_token)
		.header(header::USER_AGENT, "Github Connector of Second State Reactor")
		.send()
		.await;

	if let Ok(res) = response {
		if let Ok(gu) = res.json::<GithubUser>().await {
			return Ok(gu);
		}
	}
	Err(())
}

async fn get_author_token_from_reactor(user: &str) -> Result<String, ()> {
	let request = serde_json::json!({
		"author": user
	});

	let response = new_http_client().post(format!("{}/api/_funcs/_author_state", REACTOR_API_PREFIX.as_str()))
		.header(header::AUTHORIZATION, REACTOR_AUTH_TOKEN.as_str())
		.json(&request)
		.send()
		.await;

	if let Ok(res) = response {
		if res.status().is_success() {
			if let Ok(body) = res.text().await {
				return Ok(decrypt(&body));
			}
		}
	}
	Err(())
}

#[derive(Debug, Deserialize)]
struct FieldValue {
	field: String,
	// value: String,
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
	// value: String,
	flow: Option<String>,
	custom: Option<HookEvents>,
}

async fn create_hook(Json(req): Json<HookReq>) -> impl IntoResponse {
	if req.custom.is_none() || req.flow.is_none() {
		return Err((StatusCode::BAD_REQUEST, "Not enough parameter".to_string()));
	}

	let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

	match get_installation_token(auth_state.installation_id).await {
		Ok(install_token) => {
			let events: Vec<String> = req.custom.unwrap().events.iter().map(|e| {e.field.clone()}).collect();
			match create_hook_inner(&req.user, &req.flow.unwrap(), &req.field, events, &install_token).await {
				Ok(v) => {
					Ok((StatusCode::CREATED, Json(v)))
				}
				Err(err_msg) => {
					Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
				}
			}
		},
		Err(err_msg) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn create_hook_inner(connector: &str, flow_id: &str, repo_full_name: &str, events: Vec<String>, install_token: &str) -> Result<Value, String> {
	let param = json!({
		"name": "web",
		"active": true,
		"events": events,
		"config": {
			"url": format!("{}/event?connector={connector}&flow={flow_id}", SERVICE_API_PREFIX.as_str()),
			"content_type": "form",
		}
	});
	let response = new_http_client().post(format!("https://api.github.com/repos/{repo_full_name}/hooks"))
		.header("Accept", "application/vnd.github.v3+json")
		.header("User-Agent", "Github Connector of Second State Reactor")
		.bearer_auth(install_token)
		.json(&param)
		.send()
		.await;
	if let Ok(r) = response {
		if r.status().is_success() {
			if let Ok(body) = r.bytes().await {
				let json_body: Value = serde_json::from_slice(&body).unwrap();
				let hook_id = json_body["id"].to_string();
				let result = serde_json::json!({
					"revoke": format!("{}/revoke-hook?hook_id={hook_id}", SERVICE_API_PREFIX.as_str()),
				});
				return Ok(result);
			}
		}
	}
	Err("Failed to create hook".to_string())
}

#[derive(Deserialize)]
struct RevokeQuery {
	hook_id: String
}

async fn revoke_hook(Json(req): Json<HookReq>, Query(query): Query<RevokeQuery>) -> impl IntoResponse {
	let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

	match get_installation_token(auth_state.installation_id).await {
		Ok(install_token) => {
			match revoke_hook_inner(&req.field, &query.hook_id, &install_token).await {
				Ok(()) => {
					Ok(StatusCode::OK)
				}
				Err(err_msg) => {
					Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
				}
			}
		},
		Err(err_msg) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

async fn revoke_hook_inner(repo_full_name: &str, hook_id: &str, install_token: &str) -> Result<(), String> {
	let response = new_http_client().delete(format!("https://api.github.com/repos/{repo_full_name}/hooks/{hook_id}"))
		.header(header::ACCEPT, "application/vnd.github.v3+json")
		.header(header::USER_AGENT, "Github Connector of Second State Reactor")
		.bearer_auth(install_token)
		.send()
		.await;
	if let Ok(_) = response {
		// the status can be 204 or 404
		// so no need to check r.status().is_success()
		// always return ok
		return Ok(());
	}
	Err("Failed to revoke hook".to_string())
}


#[derive(Debug, Deserialize)]
struct RouteReq {
	// user: String,
	state: String,
	cursor: Option<String>,
}

async fn hook_events() -> impl IntoResponse {
	let events = serde_json::json!({
		"list": [
			{
				"field": "issues",
				"value": "issues"
			},
			{
				"field": "issue_comment",
				"value": "issue_comment"
			},
			{
				"field": "star",
				"value": "star"
			}
		]
	});
	Json(events)
}

async fn repos(Json(body): Json<RouteReq>) -> impl IntoResponse {
	let auth_state = serde_json::from_str::<AuthState>(&decrypt(&body.state)).unwrap();
	match get_installation_token(auth_state.installation_id).await {
		Ok(install_token) => {
			let page = body.cursor.unwrap_or_else(|| "1".to_string());
			if let Ok(page) = page.parse::<u32>() {
				match get_installed_repositories(&install_token, page).await {
					Ok(irs) => {
						let rs: Vec<Value> = irs.repositories.iter().map(|ir| {serde_json::json!({
							"field": ir.full_name,
							"value": ir.node_id
						})}).collect();
						let result = match irs.total_count > page * REPOS_PER_PAGE {
							true => {
								serde_json::json!({
									"next_cursor": page + 1,
									"list": rs
								})
							}
							false => {
								serde_json::json!({
									"list": rs
								})
							}
						};
						Ok(Json(result))
					}
					Err(err_msg) => Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
				}
			} else {
				Err((StatusCode::BAD_REQUEST, "Invalid cursor".to_string()))
			}
		}
		Err(err_msg) => {
			Err((StatusCode::INTERNAL_SERVER_ERROR, err_msg))
		}
	}
}

#[tokio::main]
async fn main() {
	let app = Router::new()
		.route("/auth", get(auth))
		.route("/event", post(capture_event))
		.route("/create-hook", post(create_hook))
		.route("/revoke-hook", delete(revoke_hook))
		.route("/hook-events", post(hook_events))
		.route("/repos", post(repos));

	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));

	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}