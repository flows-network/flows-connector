use std::env;
use std::time::{Duration};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use lazy_static::lazy_static;
use reqwest::{Client, ClientBuilder};
use axum::{
	Router,
	routing::{get, post, delete},
	extract::{Query, Json},
	response::{IntoResponse},
	http::{StatusCode,header},
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

const TIMEOUT: u64 = 120;

const RSA_BITS: usize = 2048;

lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
	static ref REACTOR_AUTH_TOKEN: String = env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");

	static ref JIRA_APP_CLIENT_ID: String = env::var("JIRA_APP_CLIENT_ID").expect("Env variable JIRA_APP_CLIENT_ID not set");
	static ref JIRA_APP_CLIENT_SECRET: String = env::var("JIRA_APP_CLIENT_SECRET").expect("Env variable JIRA_APP_CLIENT_SECRET not set");
	static ref JIRA_REDIRECT_URL: String = env::var("JIRA_REDIRECT_URL").expect("Env variable JIRA_REDIRECT_URL not set");
	static ref SERVICE_API_PREFIX: String = env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");

	// static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
    //     .expect("Env variable RSA_RAND_SEED not set")
    //     .as_bytes()
    //     .try_into()
    //     .unwrap();
	static ref RSA_RAND_SEED: [u8; 32] = [8;32];
	
    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIV_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);

	static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
}

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
							"id":&gu.0
						});
						let location = format!(
							"{}/api/connected?authorId={}&authorName={}&authorState={}&refreshState={}",
							REACTOR_API_PREFIX.as_str(),
							gu.0,
							gu.1,
							serde_json::to_string(&encrypted).unwrap(),
							at.refresh_token
							// encrypt(&serde_json::to_string(&encrypted).unwrap()),
							// encrypt(&at.refresh_token)
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

	println!("{}",code);

	let params = [
		("client_id", JIRA_APP_CLIENT_ID.as_str()), 
		("client_secret", JIRA_APP_CLIENT_SECRET.as_str()),
	    ("grant_type", "authorization_code"),
		("code", &code),
		("redirect_uri", JIRA_REDIRECT_URL.as_str()),
	];

	let response = HTTP_CLIENT
		.post("https://auth.atlassian.com/oauth/token")
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

	println!("{}",access_token);

	let response = HTTP_CLIENT
		.get("https://api.atlassian.com/oauth/token/accessible-resources")
		.bearer_auth(access_token)
		.send()
		.await;

	match response {
		Ok(res) => {
			match res.text().await {
				Ok(body) => {
					if let Ok(v) = serde_json::from_str::<Value>(&body) {
						let user_id = v[0]["id"].to_string().replace("\"","");
						let user_name = v[0]["name"].to_string().replace("\"","");
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
		("client_id", JIRA_APP_CLIENT_ID.as_str()), 
		("client_secret", JIRA_APP_CLIENT_SECRET.as_str()),
	    ("grant_type", "refresh_token"),
		("refresh_token", &decrypt(&msg_body.refresh_state)),
	];

	let response = HTTP_CLIENT
		.post("https://auth.atlassian.com/oauth/token")
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
	id: String,
	name: String,
}

#[derive(Deserialize)]
struct RouteReq {
	state: String,
}

async fn get_projects(token: &str, id: &str) -> Result<Vec<ProjectName>, String> {
	let response = HTTP_CLIENT
		.get(format!("https://api.atlassian.com/ex/jira/{}/rest/api/latest/project",id))
		.bearer_auth(token)
		.send()
		.await;
	if let Ok(r) = response {
		let data = r.text().await.unwrap();
		let channels: Vec<ProjectName> = serde_json::from_str(&data).unwrap();
		return Ok(channels);
	}
	Err("Failed to get channels".to_string())
}

async fn projects(Json(body): Json<Value>) -> impl IntoResponse {

	let mut token = "".to_string();
	let mut id = "".to_string();


	if let Ok(v) = serde_json::from_str::<Value>(body["state"].as_str().unwrap()) {
		token = v["access_token"].as_str().unwrap().to_string();
		id = v["id"].as_str().unwrap().to_string();
	}


	match get_projects(&token,&id).await {
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


#[derive(Debug, Deserialize, Serialize)]
struct ForwardRoute {
	route: String,
	value: String,
}

#[derive(Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
	forwards: Vec<ForwardRoute>,
}

async fn post_msg(Json(msg_body): Json<PostBody>) -> Result<StatusCode, (StatusCode, &'static str)> {
	println!("{}",msg_body.text);
	
	tokio::spawn(async move {
		for pb in msg_body.forwards.iter() {
			if pb.route.eq("projects") {
				let request = serde_json::json!({
					"fields": {
					   "project":
					   {
						  "id": pb.value
					   },
					   "summary": msg_body.text,
					   "description": "",
					   "issuetype": {
						  "id": "10001"
					   }
				   }
				}
				);

				let mut token = "".to_string();
				let mut id = "".to_string();

				if let Ok(v) = serde_json::from_str::<Value>(msg_body.state.as_str()) {
					token = v["access_token"].as_str().unwrap().to_string();
					id = v["id"].as_str().unwrap().to_string();
				}
	
				tokio::spawn(HTTP_CLIENT
					.post(format!("https://api.atlassian.com/ex/jira/{}/rest/api/latest/issue",id))
					.bearer_auth(token)
					.json(&request)
					.send());
			}
		}
	});

	Ok(StatusCode::OK)
}


#[tokio::main]
async fn main() {
	let app = Router::new()
		.route("/auth", get(auth))
		.route("/refresh", post(refresh_token))
		.route("/projects", post(projects))
		.route("/post", post(post_msg));

	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));

	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}