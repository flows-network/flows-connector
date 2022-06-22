use std::{env, net::SocketAddr, time::Duration};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use axum::{Router,routing::get, extract::Query, response::IntoResponse, http::{header}};
use reqwest::{StatusCode, Client, ClientBuilder};
use serde_json::Value;
use openssl::rsa::{Rsa, Padding};


lazy_static! {
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
}

#[derive(Deserialize, Serialize)]
struct AuthBody {
	code: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct OAuthAccessBody {
	expires_in: Option<u32>,
	access_token: Option<String>,
	token_type: Option<String>,
	id_token: Option<String>,
	scope: Option<String>
}

fn encrypt(data: String) -> String {
	let rsa = Rsa::public_key_from_pem(PUBLIC_KEY_PEM.as_bytes()).unwrap();
	let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
	rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
	hex::encode(buf)
}

async fn auth(Query(auth_body):Query<AuthBody>) -> impl IntoResponse {
	if auth_body.code.eq(""){
		Err((StatusCode::BAD_REQUEST, "No code".to_string()))
	}else {
		match get_access_token(&auth_body.code).await {
				Ok(at) => {
					match get_authed_user(&at.access_token.unwrap()).await {
						Ok(gu) => {
							let location = format!(
								"{}/api/connected?authorId={}&authorName={}&authorState={}",
								REACTOR_API_PREFIX.as_str(),
								"2323",
								gu,
								encrypt("sdsd".to_string())
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

const TIMEOUT: u64 = 120;

fn new_http_client() -> Client {
	let cb = ClientBuilder::new().timeout(Duration::from_secs(TIMEOUT));
	 cb.build().unwrap()
}

async fn get_access_token(code:&str) -> Result<OAuthAccessBody, String>{
	println!("{}", code);
	// let form_client_id = env::var("FORM_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
	// let form_client_secret = env::var("FORM_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");
	let params = [
		("client_id", "522267809353-naogc5pmqtc1nfdkg4m2p5gr1rj0f8r3.apps.googleusercontent.com"),
		("client_secret", "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"),
		("code", &code),
		("grant_type",  "authorization_code"),
		("redirect_uri", "http://localhost:8091")
	];
	
	let response = new_http_client().post("https://accounts.google.com/o/oauth2/token")
		.form(&params)
		.send()
		.await;
		println!("{:?}",response);
	match response {
		Ok(r) => {
			println!("{:?}", r);
			let oauth_body = r.json::<OAuthAccessBody>().await;
			match oauth_body {
				Ok(at) => {
					Ok(at)
				}
				Err(_) => {
					Err("Failed to get access token".to_string())
				}
			}
		},
		Err(a) => {
			println!("{:?}", a);
			Err("Failed to get access token".to_string())
		}
	}
}

async fn get_authed_user(access_token: &str) -> Result<String, String>{
	let Bearer = format!("Bearer {}", access_token);
	let response = new_http_client().get("https://www.googleapis.com/oauth2/v1/userinfo").header("Authorization", Bearer).bearer_auth(access_token).send().await;
	match response {
		Ok(res) => {
			match res.text().await {
				Ok(body) => {
					if let Ok(v) = serde_json::from_str::<Value>(&body) {
						Ok(v["profile"]["real_name"].as_str().unwrap().to_string())
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

#[tokio::main]
async fn main() {
	let app = Router::new().route("/auth", get(auth));
	let port = env::var("PORT").unwrap_or_else(|_| "8091".to_string());
	let port:u16 = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));
	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}