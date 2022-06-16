use std::env;
use serde::{Serialize, Deserialize};
use actix_web::{web, App, HttpResponse, HttpServer};
use lazy_static::lazy_static;
use openssl::rsa::{Rsa, Padding};

static CONNECT_HTML: &str = include_str!("./connect.html");

async fn connect() -> HttpResponse {
	return HttpResponse::Ok().body(CONNECT_HTML);
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string());
	let port = port.parse::<u16>().unwrap();
	HttpServer::new(|| {
		App::new()
			.route("/connect", web::get().to(connect))
	})
	.bind(("0.0.0.0", port))?
	.run()
	.await