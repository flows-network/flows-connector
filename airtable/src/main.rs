use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use reqwest::{header, Client};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, env, net::SocketAddr};

const RSA_BITS: usize = 2048;

static CONNECT_HTML: &str = include_str!("./connect.html");

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    // static ref HAIKU_AUTH_TOKEN: String =
    //     env::var("HAIKU_AUTH_TOKEN").expect("Env variable HAIKU_AUTH_TOKEN not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env var SERVICE_API_PREFIX not set");
    static ref AIRTABLE_CLIEN_SECRET: String = env::var("AIRTABLE_CLIEN_SECRET")
        .expect("Env variable AIRTABLE_CLIEN_SECRET not set");

    static ref RSA_RAND_SEED: [u8; 32] = env::var("RSA_RAND_SEED")
        .expect("Env variable RSA_RAND_SEED not set")
        .as_bytes()
        .try_into()
        .unwrap();
    static ref CHACHA8RNG: ChaCha8Rng = ChaCha8Rng::from_seed(*RSA_RAND_SEED);
    static ref PRIVATE_KEY: RsaPrivateKey =
        RsaPrivateKey::new(&mut CHACHA8RNG.clone(), RSA_BITS).expect("failed to generate a key");
    static ref PUBLIC_KEY: RsaPublicKey = RsaPublicKey::from(&*PRIVATE_KEY);
    static ref HTTP_CLIENT: Client = Client::new();
}

fn encrypt(data: &str) -> String {
    hex::encode(
        PUBLIC_KEY
            .encrypt(
                &mut CHACHA8RNG.clone(),
                PaddingScheme::new_pkcs1v15_encrypt(),
                data.as_bytes(),
            )
            .unwrap_or_default(),
    )
}

fn decrypt<T: AsRef<[u8]>>(data: T) -> String {
    String::from_utf8(
        PRIVATE_KEY
            .decrypt(
                PaddingScheme::new_pkcs1v15_encrypt(),
                &hex::decode(data).unwrap(),
            )
            .unwrap_or_default(),
    )
    .unwrap_or_default()
}

async fn connect() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        CONNECT_HTML,
    )
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

async fn auth(req: Query<TokenBody>) -> impl IntoResponse {
    HTTP_CLIENT
        .get("https://api.airtable.com/v0/meta/bases")
        .bearer_auth(&req.token)
        .header("X-Airtable-Client-Secret", &*AIRTABLE_CLIEN_SECRET)
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        .and_then(|resp| {
            if resp.status().is_success() {
                Ok((
                    StatusCode::OK,
                    format!(
                        "{}/api/connected?authorId={}&authorName={}&authorState={}",
                        *HAIKU_API_PREFIX,
                        req.token,
                        req.token,
                        encrypt(&req.token)
                    ),
                ))
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        })
}

#[derive(Deserialize)]
struct Base {
    id: String,
    name: String,

    #[serde(rename = "permissionLevel")]
    permission_level: String,
}

#[derive(Deserialize)]
struct Bases {
    bases: Vec<Base>,
}

#[derive(Deserialize, Serialize, Default)]
struct ForwardRoute {
    field: String,
    value: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    desc: Option<String>,
}

#[derive(Deserialize)]
struct Forwards {
    base: Vec<ForwardRoute>,
    table: Option<Vec<ForwardRoute>>,
}

#[derive(Deserialize)]
struct HaikuReqBody {
    state: String,
    text: Option<String>,
    forwards: Option<Forwards>,
}

async fn bases(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let list = HTTP_CLIENT
        .get("https://api.airtable.com/v0/meta/bases")
        .bearer_auth(decrypt(&req.state))
        .header("X-Airtable-Client-Secret", &*AIRTABLE_CLIEN_SECRET)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .json::<Bases>()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .bases
        .into_iter()
        .filter(|base| base.permission_level.eq("create"))
        .map(|base| ForwardRoute {
            field: base.name,
            value: base.id,
            desc: None,
        })
        .collect::<Vec<_>>();

    let ret: Result<_, (StatusCode, String)> = Ok(Json(json!({ "list": list })));
    ret
}

#[derive(Deserialize)]
struct Table {
    name: String,
    description: Option<String>,
}

#[derive(Deserialize)]
struct Tables {
    tables: Vec<Table>,
}

async fn tables(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let base_id = match req.forwards.as_ref() {
        Some(f) => {
            &f.base
                .first()
                .ok_or((StatusCode::BAD_REQUEST, "Missing base".to_string()))?
                .value
        }
        None => return Err((StatusCode::BAD_REQUEST, "Missing forwards".to_string())),
    };

    let list = HTTP_CLIENT
        .get(format!(
            "https://api.airtable.com/v0/meta/bases/{base_id}/tables"
        ))
        .bearer_auth(decrypt(&req.state))
        .header("X-Airtable-Client-Secret", &*AIRTABLE_CLIEN_SECRET)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .json::<Tables>()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .tables
        .into_iter()
        .map(|table| ForwardRoute {
            field: table.name.clone(),
            value: table.name,
            desc: table.description,
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({ "list": list })))
}

async fn post_item(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let fields = serde_json::from_str::<HashMap<String, Value>>(
        &req.text
            .as_ref()
            .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let forwards = req
        .forwards
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing forwards".to_string()))?;

    let base_id = &forwards
        .base
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing base".to_string()))?
        .value;

    let table = &forwards
        .table
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing table".to_string()))?
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing table item".to_string()))?
        .value;

    let resp = HTTP_CLIENT
        .post(format!("https://api.airtable.com/v0/{base_id}/{table}"))
        .bearer_auth(decrypt(&req.state))
        .json(&json!({
            "records": [
                {
                    "fields": fields,
                }
            ]
        }))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match resp.status().is_success() {
        true => Ok(StatusCode::OK),
        false => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.text().await.unwrap_or_default(),
        )),
    }
}

async fn actions() -> impl IntoResponse {
    let actions = serde_json::json!({
        "list": [
            {
                "field": "Create an item",
                "value": "create",
                "desc": "This connector takes the return value of the flow function, and create a new item with the given value."
            }
        ]
    });
    Json(actions)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    let app = Router::new()
        .route("/connect", get(connect))
        .route("/auth", get(auth))
        .route("/bases", post(bases))
        .route("/tables", post(tables))
        .route("/actions", post(actions))
        .route("/post", post(post_item));

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
