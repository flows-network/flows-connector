use core::time::Duration;

use rand::SeedableRng;
use reqwest::{Client, ClientBuilder};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::Value;
use std::env;

use lazy_static::lazy_static;
use rand_chacha::ChaCha8Rng;

pub const RSA_BITS: usize = 2048;

pub const REPOS_PER_PAGE: u32 = 20;

pub const TIMEOUT: u64 = 120;

lazy_static! {
    pub static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    pub static ref REACTOR_AUTH_TOKEN: String =
        env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
    pub static ref GITHUB_APP_INSTALL_LOCATION: String = env::var("GITHUB_APP_INSTALL_LOCATION")
        .expect("Env variable GITHUB_APP_INSTALL_LOCATION not set");
    pub static ref GITHUB_APP_ID: String =
        env::var("GITHUB_APP_ID").expect("Env variable GITHUB_APP_ID not set");
    pub static ref GITHUB_PRIVATE_KEY: String =
        env::var("GITHUB_APP_PRIVATE_KEY").expect("Env variable GITHUB_APP_PRIVATE_KEY not set");
    pub static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    pub static ref GITHUB_CLIENT_ID: String =
        env::var("GITHUB_APP_CLIENT_ID").expect("Env variable GITHUB_APP_CLIENT_ID not set");
    pub static ref GITHUB_CLIENT_SECRET: String = env::var("GITHUB_APP_CLIENT_SECRET")
        .expect("Env variable GITHUB_APP_CLIENT_SECRET not set");
    pub static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    pub static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    pub static ref PRIV_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    pub static ref PUB_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIV_KEY);
    pub static ref HTTP_CLIENT: Client = ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT))
        .build()
        .expect("Can't build the reqwest client");
    pub static ref EVENTS: Value = {
        let content = include_str!("../src/events.json");
        serde_json::from_str(content).unwrap()
    };
}
