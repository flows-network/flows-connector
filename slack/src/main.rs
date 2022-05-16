use std::env;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use actix_web::{web, App, HttpResponse, HttpServer, ResponseError};
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};

#[derive(Deserialize, Serialize)]
struct EventBody {
	challenge: Option<String>,
	event: Option<Event>,
}

#[derive(Deserialize, Serialize)]
struct Event {
	bot_id: Option<String>,
	user: Option<String>,
	text: Option<String>,
}

lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");

	static ref PASSPHRASE: String = env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref PRIVATE_KEY_PEM: String = env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");
}

const TIMEOUT: u64 = 120;

fn new_http_client() -> awc::Client {
	let connector = awc::Connector::new()
		.timeout(std::time::Duration::from_secs(TIMEOUT))
		.finish();
	return awc::ClientBuilder::default().timeout(std::time::Duration::from_secs(TIMEOUT)).connector(connector).finish();
}

async fn capture_event(evt_body: web::Json<EventBody>) -> HttpResponse {
	let eb = evt_body.into_inner();
	if let Some(challenge) = eb.challenge {
		return HttpResponse::Ok().body(challenge);
	}

	if let Some(evt) = eb.event {
		// Only handle message which is sent by user
		if evt.bot_id.is_none() {
			let user = evt.user.unwrap_or_else(|| String::from(""));
			let text = evt.text.unwrap_or_else(|| String::from(""));
			post_event_to_reactor(user, text).await;
		}
	}

	return HttpResponse::Ok().finish();
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

fn encrypt(data: String) -> String {
	let rsa = Rsa::public_key_from_pem(PUBLIC_KEY_PEM.as_bytes()).unwrap();
	let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
	rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
	hex::encode(buf)
}

fn decrypt(hex: String) -> String {
	let rsa = Rsa::private_key_from_pem_passphrase(PRIVATE_KEY_PEM.as_bytes(), PASSPHRASE.as_bytes()).unwrap();
	let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
	let l = rsa.private_decrypt(&hex::decode(hex).unwrap(), &mut buf, Padding::PKCS1).unwrap();
	String::from_utf8(buf[..l].to_vec()).unwrap()
}

async fn auth<'a>(auth_body: web::Query<AuthBody>) -> HttpResponse {
	if auth_body.code.eq("") {
		HttpResponse::BadRequest().body("No code")
	} else {
		match get_access_token(&auth_body.code).await {
			Ok(at) => {
				let authed_user = at.authed_user.unwrap();
				match get_authed_user(&authed_user.access_token).await {
					Ok(gu) => {
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}",
							REACTOR_API_PREFIX.as_str(),
							authed_user.id,
							gu,
							encrypt(at.access_token.unwrap())
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

async fn get_access_token(code: &str) -> Result<OAuthAccessBody, HttpResponse> {
	let slack_client_id = env::var("SLACK_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
	let slack_client_secret = env::var("SLACK_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");

	let params = [
		("client_id", slack_client_id.as_str()),
		("client_secret", slack_client_secret.as_str()),
		("code", &code)
	];

	let response = new_http_client().post("https://slack.com/api/oauth.v2.access")
		.send_form(&params)
		.await;
	match response {
		Ok(mut r) => {
			let oauth_body = r.json::<OAuthAccessBody>().await;
			match oauth_body {
				Ok(at) => {
					if at.ok {
						return Ok(at)
					} else {
						let err_msg = at.error.unwrap_or_else(|| "unknown error".to_string());
						return Err(HttpResponse::BadRequest().body(err_msg));
					}
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

async fn get_authed_user(access_token: &str) -> Result<String, HttpResponse> {
	let response = new_http_client().get("https://slack.com/api/users.profile.get")
		.set_header("Authorization", "Bearer ".to_owned() + access_token)
		.send()
		.await;

	match response {
		Ok(mut res) => {
			match res.body().await {
				Ok(body) => {
					if let Ok(v) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&body.to_vec())) {
						return Ok(v["profile"]["real_name"].as_str().unwrap().to_string());
					}
				}
				Err(e) => {
					return Err(e.error_response());
				}
			}
		}
		Err(e) => {
			return Err(e.error_response());
		}
	};
	return Err(HttpResponse::ServiceUnavailable().finish());
}

async fn post_event_to_reactor(user: String, text: String) {
	let request = serde_json::json!({
		"user": user,
		"text": text
	});
	let reactor_auth_token = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");

	let response = new_http_client().post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
		.set_header("Authorization", reactor_auth_token)
		.send_json(&request)
		.await;
	if let Err(e) = response {
		println!("{:?}", e);
	}
}

#[derive(Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
}

async fn post_msg(msg_body: web::Json<PostBody>) -> HttpResponse {
	let mb = msg_body.into_inner();

	let request = serde_json::json!({
		"channel": mb.user,
		"text": mb.text,
	});

	let response = new_http_client().post("https://slack.com/api/chat.postMessage")
		.set_header("Authorization", format!("Bearer {}", decrypt(mb.state)))
		.send_json(&request)
		.await;
	match response {
		Ok(_) => HttpResponse::Ok().finish(),
		Err(e) => HttpResponse::InternalServerError().body(format!("{}", e))
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
			.route("/post", web::post().to(post_msg))
	})
	.bind(("0.0.0.0", port))?
	.run()
	.await
}
