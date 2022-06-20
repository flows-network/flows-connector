use std::{env, net::SocketAddr};

use axum::{Router,routing::{get,post}, extract::Query};

#[derive(Debug, Deserialize, Serialize)]
struct OAuthAccessBody {
	ok: bool,
	authed_user: Option<AuthedUser>,
	access_token: Option<String>,
	error: Option<String>,
}

async fn auth(Query(auth_body):Query<>)

#[tokio::main]
async fn main() {
	let app = Router::new().route("/auth", get(auth))
	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port:u16 = port.parse::<u16>().unwrap();
	let addr = SocketAddr::from(([127, 0, 0, 1], port));
	axum::Server::bind(&addr)
		.serve(app.into_make_service())
		.await
		.unwrap();
}