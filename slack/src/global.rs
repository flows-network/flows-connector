use std::{env, time::Duration};

use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{Client, ClientBuilder};
use rsa::{RsaPrivateKey, RsaPublicKey};

const RSA_BITS: usize = 2048;

const TIMEOUT: u64 = 120;

pub const CHANNELS_PER_PAGE: u32 = 20;

lazy_static! {
    pub static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    pub static ref REACTOR_AUTH_TOKEN: String =
        env::var("REACTOR_AUTH_TOKEN").expect("Env variable REACTOR_AUTH_TOKEN not set");
    pub static ref SLACK_CLIENT_ID: String =
        env::var("SLACK_APP_CLIENT_ID").expect("Env variable SLACK_APP_CLIENT_ID not set");
    pub static ref SLACK_CLIENT_SECRET: String =
        env::var("SLACK_APP_CLIENT_SECRET").expect("Env variable SLACK_APP_CLIENT_SECRET not set");
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
    pub static ref EVENTS: &'static str = include_str!("./data/events.json");
    pub static ref ACTIONS: &'static str = include_str!("./data/actions.json");
}
