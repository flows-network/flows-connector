use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use actix_web::{web, App, body::Body, HttpResponse, HttpServer, ResponseError};
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{Public, Private};
use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};

#[derive(Debug, Deserialize, Serialize)]
struct AuthBody {
	code: String,
	installation_id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct AccessTokenBody {
	access_token: Option<String>,
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

fn new_http_client() -> awc::Client {
	let connector = awc::Connector::new()
		.timeout(std::time::Duration::from_secs(TIMEOUT))
		.finish();
	return awc::ClientBuilder::default().timeout(std::time::Duration::from_secs(TIMEOUT)).connector(connector).finish();
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

async fn auth<'a>(auth_body: web::Query<AuthBody>) -> HttpResponse {
	if auth_body.code.eq("") {
		HttpResponse::BadRequest().body("No code")
	} else {
		match get_access_token(&auth_body.code).await {
			Ok(access_token) => {
				match get_authed_user(&access_token).await {
					Ok(gu) => {
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}",
							REACTOR_API_PREFIX.as_str(),
							gu.node_id,
							gu.login,
							encrypt(&serde_json::to_string(&AuthState {
								access_token: access_token,
								installation_id: auth_body.installation_id,
							}).unwrap())
						);
						HttpResponse::Found().header("Location", location).finish()
					}
					Err(failed_resp) => failed_resp
				}
			},
			Err(failed_resp) => failed_resp
		}
	}
}

async fn get_access_token(code: &str) -> Result<String, HttpResponse> {
	let params = [
		("client_id", GITHUB_CLIENT_ID.as_ref()),
		("client_secret", GITHUB_CLIENT_SECRET.as_ref()),
		("code", code)
	];

	let response = new_http_client().post("https://github.com/login/oauth/access_token")
		.header("Accept", "application/json")
		.send_form(&params)
		.await;
	match response {
		Ok(mut r) => {
			let token_body = r.json::<AccessTokenBody>().await;
			match token_body {
				Ok(at) => {
					return Ok(at.access_token.unwrap_or_default())
				},
				Err(e) => {
					return Err(e.error_response());
				}
			}
		},
		Err(e) => {
			return Err(e.error_response());
		}
	}
}

async fn get_installation_token(installation_id: u64) -> Result<String, HttpResponse> {
	let now = get_now();
	let jwt_payload = json!({
		"iat": now - 60,
		"exp": now + 10 * 60,
		"iss": GITHUB_APP_ID.as_ref() as &str,
	});
	let jwt = encode(&Header::new(Algorithm::RS256), &jwt_payload, &EncodingKey::from_rsa_pem(GITHUB_PRIVATE_KEY.as_bytes()).unwrap()).unwrap();

	let response = new_http_client().post(format!("https://api.github.com/app/installations/{installation_id}/access_tokens"))
		.header("Accept", "application/vnd.github.v3+json")
		.header("User-Agent", "Github Connector of Second State Reactor")
		.header("Authorization", format!("Bearer {jwt}"))
		.send()
		.await;
	match response {
		Ok(mut r) => {
			let token_body = r.json::<InstallationTokenBody>().await;
			match token_body {
				Ok(at) => {
					return Ok(at.token)
				},
				Err(e) => {
					return Err(e.error_response());
				}
			}
		},
		Err(e) => {
			return Err(e.error_response());
		}
	}
}

async fn get_installed_repositories(install_token: &str, page: u32) -> Result<InstalledRepos, HttpResponse> {
	let response = new_http_client()
		.get(format!("https://api.github.com/installation/repositories?per_page={}&page={}", REPOS_PER_PAGE, page))
		.header("Accept", "application/vnd.github.v3+json")
		.header("User-Agent", "Github Connector of Second State Reactor")
		.header("Authorization", format!("Bearer {install_token}"))
		.send()
		.await;
	match response {
		Ok(mut r) => {
			match r.json::<InstalledRepos>().limit(1 * 1024 * 1024).await {
				Ok(repos) => {
					return Ok(repos)
				},
				Err(e) => {
					return Err(e.error_response());
				}
			}
		},
		Err(e) => {
			return Err(e.error_response());
		}
	}
}

#[derive(Debug, Deserialize)]
struct Event {
    connector: String,
	flow: String,
	payload: String,
}

async fn capture_event(form: web::Form<Event>) -> HttpResponse {
	let event = form.into_inner();
	let result = get_author_token_from_reactor(&event.connector).await;
	match result {
		Err(failed_resp) => {
			return failed_resp;
		}
		Ok(auth_state) => {
			let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
			let auth_state = serde_json::from_str::<AuthState>(&decrypt(&auth_state)).unwrap();
			let result = get_github_user(payload["sender"]["url"].as_str().unwrap(), &auth_state.access_token).await;
			match result {
				Err(failed_resp) => {
					return failed_resp;
				}
				Ok(github_user) => {
					if let Some(email) = github_user.email {
						let obj = payload.as_object_mut().unwrap();
						obj.insert("sender_email".to_string(), email.into());
					}
					post_event_to_reactor(&event.connector, &event.flow, &payload.to_string()).await;
				}
			}
		}
	}

	return HttpResponse::Ok().finish();
}

async fn post_event_to_reactor(user: &str, flow: &str, text: &str) {
	let request = serde_json::json!({
		"user": user,
		"flow": flow,
		"text": text
	});

	let response = new_http_client().post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
		.set_header("Authorization", REACTOR_AUTH_TOKEN.as_str())
		.send_json(&request)
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


async fn get_authed_user(access_token: &str) -> Result<GithubUser, HttpResponse> {
	let response = new_http_client().get("https://api.github.com/user")
		.set_header("Authorization", "Bearer ".to_owned() + access_token)
		.set_header("User-Agent", "Github Connector of Second State Reactor")
		.send()
		.await;

	match response {
		Ok(mut res) => {
			let body = res.json::<GithubUser>().await;
			match body {
				Ok(gu) => {
					return Ok(gu);
				}
				Err(e) => {
					return Err(e.error_response());
				}
			}
		}
		Err(e) => {
			return Err(e.error_response());
		}
	}
}

async fn get_github_user(api_url: &str, access_token: &str) -> Result<GithubUser, HttpResponse> {
	let response = new_http_client().get(api_url)
		.set_header("Authorization", "Bearer ".to_owned() + access_token)
		.set_header("User-Agent", "Github Connector of Second State Reactor")
		.send()
		.await;

	match response {
		Ok(mut res) => {
			let body = res.json::<GithubUser>().await;
			match body {
				Ok(gu) => {
					return Ok(gu);
				}
				Err(e) => {
					return Err(e.error_response());
				}
			}
		}
		Err(e) => {
			return Err(e.error_response());
		}
	}
}

async fn get_author_token_from_reactor(connector: &str) -> Result<String, HttpResponse> {
	let request = serde_json::json!({
		"author": connector
	});

	let response = new_http_client().post(format!("{}/api/_funcs/_author_state", REACTOR_API_PREFIX.as_str()))
		.set_header("Authorization", REACTOR_AUTH_TOKEN.as_str())
		.send_json(&request)
		.await;

	match response {
		Ok(mut res) => {
			let msg = res.body().await;
			match msg {
				Ok(bytes) => {
					let body = String::from_utf8_lossy(&bytes.to_vec()).to_string();
					if !res.status().is_success() {
						return Err(HttpResponse::NotFound().body(body));
					}
					return Ok(body);
				}
				Err(e) => {
					return Err(e.error_response());
				}
			}
		}
		Err(e) => {
			return Err(e.error_response());
		}
	}
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

async fn create_hook(body: web::Json<HookReq>) -> HttpResponse {
	let req = body.into_inner();
	if req.custom.is_none() || req.flow.is_none() {
		return HttpResponse::BadRequest().finish();
	}

	let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

	match get_installation_token(auth_state.installation_id).await {
		Ok(install_token) => {
			let events: Vec<String> = req.custom.unwrap().events.iter().map(|e| {e.field.clone()}).collect();
			create_hook_inner(&req.user, &req.flow.unwrap(), &req.field, events, &install_token).await
		},
		Err(failed_resp) => {
			return failed_resp;
		}
	}
}

async fn create_hook_inner(connector: &str, flow_id: &str, repo_full_name: &str, events: Vec<String>, install_token: &str) -> HttpResponse {
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
		.header("Authorization", format!("Bearer {install_token}"))
		.send_json(&param)
		.await;
	if let Ok(mut r) = response {
		if let Ok(body) = r.body().await {
			if r.status().is_success() {
				let json_body: Value = serde_json::from_slice(&body).unwrap();
				let hook_id = json_body["id"].to_string();
				let result = serde_json::json!({
					"revoke": format!("{}/revoke-hook?hook_id={hook_id}", SERVICE_API_PREFIX.as_str()),
				});
				return HttpResponse::Created().json(result);
			}
			return HttpResponse::with_body(r.status(), Body::Bytes(body));
		}
	}
	return HttpResponse::ServiceUnavailable().finish();
}

#[derive(Deserialize)]
struct RevokeQuery {
	hook_id: String
}

async fn revoke_hook(body: web::Json<HookReq>, query: web::Query<RevokeQuery>) -> HttpResponse {
	let req = body.into_inner();

	let auth_state = serde_json::from_str::<AuthState>(&decrypt(&req.state)).unwrap();

	match get_installation_token(auth_state.installation_id).await {
		Ok(install_token) => {
			revoke_hook_inner(&req.field, &query.hook_id, &install_token).await
		},
		Err(failed_resp) => {
			return failed_resp;
		}
	}
}

async fn revoke_hook_inner(repo_full_name: &str, hook_id: &str, install_token: &str) -> HttpResponse {
	let response = new_http_client().delete(format!("https://api.github.com/repos/{repo_full_name}/hooks/{hook_id}"))
		.header("Accept", "application/vnd.github.v3+json")
		.header("User-Agent", "Github Connector of Second State Reactor")
		.header("Authorization", format!("Bearer {install_token}"))
		.send()
		.await;
	if let Ok(_) = response {
		// the status can be 204 or 404
		// so no need to check r.status().is_success()
		// always return ok
		return HttpResponse::Ok().finish();
	}
	return HttpResponse::ServiceUnavailable().finish();
}


#[derive(Debug, Deserialize)]
struct TriggerRouteReq {
	// user: String,
	state: String,
	page: Option<u32>,
}

async fn hook_events(_: web::Json<TriggerRouteReq>) -> HttpResponse {
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
	return HttpResponse::Ok().json(events);
}

async fn hook_repos(body: web::Json<TriggerRouteReq>) -> HttpResponse {
	let auth_state = serde_json::from_str::<AuthState>(&decrypt(&body.state)).unwrap();
	match get_installation_token(auth_state.installation_id).await {
		Ok(install_token) => {
			match get_installed_repositories(&install_token, body.page.unwrap_or_default()).await {
				Ok(irs) => {
					let total_page = (irs.total_count as f32 / REPOS_PER_PAGE as f32).ceil() as u32;
					let irs: Vec<Value> = irs.repositories.iter().map(|ir| {serde_json::json!({
						"field": ir.full_name,
						"value": ir.node_id
					})}).collect();
					let result = serde_json::json!({
						"total_page": total_page,
						"list": irs
					});
					return HttpResponse::Ok().json(result);
				}
				Err(failed_resp) => failed_resp
			}
		}
		Err(_) => {
			// Reconnect if installation_id has not found
			HttpResponse::Found().header("Location", GITHUB_APP_INSTALL_LOCATION.as_ref() as &str).finish()
		}
	}
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	HttpServer::new(|| {
		App::new()
			.route("/auth", web::get().to(auth))
			.route("/event", web::post().to(capture_event))
			.route("/create-hook", web::post().to(create_hook))
			.route("/revoke-hook", web::delete().to(revoke_hook))
			.route("/hook-events", web::post().to(hook_events))
			.route("/hook-repos", web::post().to(hook_repos))
	})
	.bind(("0.0.0.0", port))?
	.run()
	.await
}
