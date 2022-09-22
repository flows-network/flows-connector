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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

    static ref WEBHOOK_URL: String = format!("{}/webhook", &*SERVICE_API_PREFIX);
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
            .expect("failed to decrypt"),
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
enum MondayResult<T> {
    #[serde(rename = "data")]
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    Data(T),

    #[serde(rename = "errors")]
    Errors(Vec<String>),
}

#[derive(Deserialize)]
struct MondayBody<T> {
    #[serde(flatten)]
    #[serde(bound(deserialize = "T: DeserializeOwned"))]
    result: MondayResult<T>,
    // account_id: Option<u64>,
}

#[inline]
async fn monday_query<D: DeserializeOwned, T: AsRef<str>, Q: AsRef<str>>(
    token: T,
    query: Q,
) -> Result<D, String> {
    HTTP_CLIENT
        .post("https://api.monday.com/v2")
        .header(header::AUTHORIZATION, token.as_ref())
        .json(&json!({ "query": query.as_ref() }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<MondayBody<D>>()
        .await
        .map_err(|e| e.to_string())
        .and_then(|res| match res.result {
            MondayResult::Data(d) => Ok(d),
            MondayResult::Errors(e) => Err(e.join(", ")),
        })
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct User {
    email: String,
    name: String,
    id: u64,
}

#[derive(Deserialize)]
struct Me {
    me: User,
}

async fn auth(req: Query<TokenBody>) -> impl IntoResponse {
    monday_query(&req.token, "query {me { email name id }}")
        .await
        .map(|me: Me| {
            (
                StatusCode::OK,
                format!(
                    "{}/api/connected?authorId={}&authorName={}&authorState={}",
                    &*HAIKU_API_PREFIX,
                    me.me.id,
                    format!("{} ({})", me.me.name, me.me.email),
                    encrypt(&req.token)
                ),
            )
        })
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))
}

#[derive(Deserialize, Serialize)]
struct ForwardRoute {
    field: String,
    value: String,
}

#[derive(Deserialize)]
struct Forwards {
    board: Vec<ForwardRoute>,
}

#[derive(Deserialize)]
struct HaikuReqBody {
    state: String,
    text: Option<String>,
    forwards: Option<Forwards>,
}

#[derive(Deserialize)]
struct Board {
    #[serde(default = "String::new")]
    id: String,
    #[serde(default = "String::new")]
    name: String,
    #[serde(default = "Vec::new")]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct Boards {
    boards: Vec<Board>,
}

async fn boards(req: Json<HaikuReqBody>) -> impl IntoResponse {
    monday_query(decrypt(&req.state), "query {boards { id name }}")
        .await
        .map(|boards: Boards| {
            let mut list = Vec::new();
            for board in boards.boards {
                list.push(ForwardRoute {
                    field: board.name,
                    value: board.id.to_string(),
                });
            }
            Json(json!({ "list": list }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Deserialize)]
struct ItemValues {
    item: String,
    values: Value,
}

async fn post_item(req: Json<HaikuReqBody>) -> impl IntoResponse {
    let board_id = &req
        .forwards
        .as_ref()
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Missing forwords.board.0".to_string(),
        ))?
        .board
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "Missing forwards".to_string()))?
        .value;

    let items = monday_query(
        decrypt(&req.state),
        format!(
            "query {{ boards(ids: {}) {{ items {{ id name }} }} }}",
            board_id
        ),
    )
    .await
    .and_then(|boards: Boards| {
        boards
            .boards
            .into_iter()
            .next()
            .ok_or("Boards is empty".to_string())
    })
    .map(|board| {
        let mut items = HashMap::new();
        for item in board.items {
            items.insert(item.name, item.id);
        }
        items
    })
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let new_values = serde_json::from_str::<ItemValues>(
        req.text
            .as_ref()
            .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("new_values parsing failed: {}", e.to_string()),
        )
    })?;

    let item_id = items
        .get(&new_values.item)
        .ok_or((StatusCode::BAD_REQUEST, "Invaild item name".to_string()))?;

    monday_query(
        decrypt(&req.state),
        format!(
            "mutation {{
            change_multiple_column_values (
                item_id: {item_id},
                board_id: {board_id},
                column_values: \"{}\"
            ) {{id}}
        }}",
            new_values.values.to_string().replace("\"", "\\\"")
        ),
    )
    .await
    .map(|_: Value| ())
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn actions() -> impl IntoResponse {
    let actions = serde_json::json!({
        "list": [
            {
                "field": "Update item values",
                "value": "update",
                "desc": "This connector takes the return value of the flow function, and updates values of a specific item column."
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
        .route("/boards", post(boards))
        .route("/post", post(post_item))
        .route("/actions", post(actions));

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
