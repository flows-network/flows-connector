use std::env;
use serde::{Serialize, Deserialize};
use actix_web::{web, App, HttpResponse, HttpServer};
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};
use regex::Regex;


lazy_static! {
	static ref REACTOR_API_PREFIX: String = env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");

	static ref PASSPHRASE: String = env::var("PASSPHRASE").expect("Env variable PASSPHRASE not set");
	static ref PUBLIC_KEY_PEM: String = env::var("PUBLIC_KEY_PEM").expect("Env variable PUBLIC_KEY_PEM not set");
	static ref PRIVATE_KEY_PEM: String = env::var("PRIVATE_KEY_PEM").expect("Env variable PRIVATE_KEY_PEM not set");
}

static CONNECT_HTML: &str = include_str!("./connect.html");

const TIMEOUT: u64 = 120;

fn new_http_client() -> awc::Client {
	let connector = awc::Connector::new()
		.timeout(std::time::Duration::from_secs(TIMEOUT))
		.finish();
	return awc::ClientBuilder::default().timeout(std::time::Duration::from_secs(TIMEOUT)).connector(connector).finish();
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


async fn connect() -> HttpResponse {
    return HttpResponse::Ok().body(CONNECT_HTML);
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthBody {
	sender_email: String,
	api_key: String,
}

async fn auth(auth_body: web::Form<AuthBody>) -> HttpResponse {
	let email_regex = Regex::new(r#"^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"#).unwrap();
	if !email_regex.is_match(&auth_body.sender_email.to_lowercase()) {
		return HttpResponse::BadRequest().body("Invalid email");
	}
	let api_key_regex = Regex::new(r"^.{50,}$").unwrap();
	if !api_key_regex.is_match(&auth_body.api_key) {
		return HttpResponse::BadRequest().body("Invalid api key");
	}
	let location = format!(
		"{}/api/connected?authorId={}&authorName={}&authorState={}",
		REACTOR_API_PREFIX.as_str(),
		auth_body.sender_email,
		auth_body.sender_email,
		encrypt(&auth_body.api_key)
	);
	HttpResponse::Found().header("Location", location).finish()
}

#[derive(Debug, Serialize, Deserialize)]
struct MailBody {
	to_email: String,
	subject: String,
	content: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PostBody {
	user: String,
	text: String,
	state: String,
}

async fn post_msg(msg_body: web::Json<PostBody>) -> HttpResponse {
	let pb = msg_body.into_inner();

	match serde_json::from_str::<MailBody>(&pb.text) {
		Ok(mb) => {
			let request = serde_json::json!({
				"personalizations": [
					{
						"to": [
							{
								"email": mb.to_email
							}
						]
					}
				],
				"from": {
					"email": pb.user
				},
				"subject": mb.subject,
				"content": [
					{
						"type": "text/html",
						"value": mb.content
					}
				]
			});

			let response = new_http_client().post("https://api.sendgrid.com/v3/mail/send")
				.set_header("Authorization", format!("Bearer {}", decrypt(&pb.state)))
				.send_json(&request)
				.await;
			match response {
				Ok(_) => HttpResponse::Ok().finish(),
				Err(e) => HttpResponse::InternalServerError().body(format!("{}", e))
			}
		}
		Err(_) => {
			HttpResponse::BadRequest().finish()
		}
	}
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	HttpServer::new(|| {
		App::new()
			.route("/connect", web::get().to(connect))
			.route("/auth", web::post().to(auth))
			.route("/post", web::post().to(post_msg))
	})
	.bind(("0.0.0.0", port))?
	.run()
	.await
}