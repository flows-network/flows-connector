#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;

use std::env;

use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

mod auth;
mod channels;
mod event;
mod post;

static RSA_BITS: usize = 2048;

lazy_static! {
	// static ref HAIKU_API_PREFIX: String = env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
	// static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED").expect("Env variable RSA_RAND_SEED not set").as_bytes().try_into().unwrap();
	// static ref HAIKU_AUTH_TOKEN: String = env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
	// static ref SLACK_APP_CLIENT_ID: String = env::var("SLACK_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
	// static ref SLACK_APP_CLIENT_SECRET: String = env::var("SLACK_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");

	static ref HAIKU_API_PREFIX: String = String::from("http://127.0.0.1:3000");
	static ref RSA_RAND_SEED: [u8; 32] = "wWuE6hfm7mMCjq$2eefEv2Y@2aeLYNUn".as_bytes().try_into().unwrap();
	static ref HAIKU_AUTH_TOKEN: String = String::from("2b72aea305fd3ac2dd1f903fb1dbdf050c113aca");
	static ref SLACK_APP_CLIENT_ID: String = String::from("");
	static ref SLACK_APP_CLIENT_SECRET: String = String::from("");

	static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
	static ref PRIV_KEY: RsaPrivateKey = RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
	static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
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

#[wasmedge_bindgen]
pub fn init() {
	/// Init PRIV_KEY for its slow generation time
	encrypt("");
	println!("Keys has been initialized");
}
