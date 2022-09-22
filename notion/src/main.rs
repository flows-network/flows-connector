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
use serde_json::{json, Value, Map};
use std::{env, net::SocketAddr, collections::HashMap};

const RSA_BITS: usize = 2048;

lazy_static! {
    static ref HAIKU_API_PREFIX: String =
        env::var("HAIKU_API_PREFIX").expect("Env variable HAIKU_API_PREFIX not set");
    static ref SERVICE_API_PREFIX: String =
        env::var("SERVICE_API_PREFIX").expect("Env variable SERVICE_API_PREFIX not set");
    static ref NOTION_APP_CLIENT_ID: String =
        env::var("NOTION_APP_CLIENT_ID").expect("Env variable NOTION_APP_CLIENT_ID not set");
    static ref NOTION_APP_CLIENT_SECRET: String = env::var("NOTION_APP_CLIENT_SECRET")
        .expect("Env variable NOTION_APP_CLIENT_SECRET not set");
    static ref REDIRECT_URL: String = format!("{}/auth", *SERVICE_API_PREFIX);
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
            .expect("failed to encrypt"),
    )
}

fn decrypt(data: &str) -> String {
    String::from_utf8(
        PRIVATE_KEY
            .decrypt(
                PaddingScheme::new_pkcs1v15_encrypt(),
                &hex::decode(data).unwrap(),
            )
            .expect("failed to decrypt"),
    )
    .unwrap()
}

async fn connect() -> impl IntoResponse {
    (StatusCode::FOUND, [("Location", format!(
        "https://api.notion.com/v1/oauth/authorize?owner=user&client_id={}&redirect_uri={}&response_type=code",
        *NOTION_APP_CLIENT_ID,
        urlencoding::encode(&*REDIRECT_URL)))]
    )
}

#[derive(Deserialize)]
struct AuthBody {
    code: String, // Temporary authorization code
}

// ref https://developers.notion.com/docs/authorization
async fn auth(auth_body: Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No code".to_string()));
    }

    let at = get_access_token(&auth_body.code)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let location = format!(
        "{}/api/connected?authorId={}&authorName={}&authorState={}",
        HAIKU_API_PREFIX.as_str(),
        at.workspace_id,
        urlencoding::encode(
            &at.workspace_name
                .unwrap_or_else(|| "Unknown workspace name".to_string())
        ),
        encrypt(&at.access_token),
    );
    Ok((StatusCode::FOUND, [("Location", location)]))
}

#[derive(Deserialize)]
struct AccessTokenBody {
    access_token: String,
    workspace_id: String,
    workspace_name: Option<String>,
}

async fn get_access_token(code: &str) -> Result<AccessTokenBody, String> {
    let body = json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": &*REDIRECT_URL,
    });

    let resp = HTTP_CLIENT
        .post("https://api.notion.com/v1/oauth/token")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .header(header::CONTENT_TYPE, "application/json")
        .basic_auth(&*NOTION_APP_CLIENT_ID, Some(&*NOTION_APP_CLIENT_SECRET))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok(resp
        .json::<AccessTokenBody>()
        .await
        .map_err(|e| e.to_string())?)
}

#[derive(Deserialize)]
struct ReactorReqBody {
    // user: String,                   // Workspace ID
    state: String,
    text: Option<String>,
    cursor: Option<String>,
    forwards: Option<DatabaseRoute>,
}

#[derive(Deserialize)]
struct TitleItem {
    plain_text: String,
}

#[derive(Deserialize)]
struct DatabaseListItem {
    id: String,
    title: Vec<TitleItem>,
}

#[derive(Deserialize)]
struct DatabaseList {
    results: Vec<DatabaseListItem>,
    next_cursor: Value,
}

#[derive(Serialize, Deserialize)]
struct RouteItem {
    field: String,
    value: String,
}

#[derive(Serialize)]
struct RouteList {
    cursor: Option<String>,
    list: Vec<RouteItem>,
}

// ref https://developers.notion.com/reference/post-search
async fn databases(req: Json<ReactorReqBody>) -> impl IntoResponse {
    let mut body = json!({
        "filter": {
            "value": "database",
            "property": "object",
        },
        "page_size": 10,
    });

    if let Some(cursor) = &req.cursor {
        body.as_object_mut()
            .unwrap()
            .insert("start_cursor".to_string(), Value::String(cursor.clone()));
    }

    let response = HTTP_CLIENT
        .post("https://api.notion.com/v1/search")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .header("Notion-Version", "2022-06-28")
        .bearer_auth(decrypt(&req.state))
        .json(&body)
        .send()
        .await;

    let list = match response {
        Ok(resp) => resp
            .json::<DatabaseList>()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    let mut ret = RouteList {
        cursor: None,
        list: Vec::new(),
    };

    if let Value::String(cursor) = &list.next_cursor {
        ret.cursor = Some(cursor.clone());
    }

    for item in list.results {
        ret.list.push(RouteItem {
            field: item
                .title
                .first()
                .unwrap_or(&TitleItem {
                    plain_text: format!("Untitled ({})", item.id),
                })
                .plain_text
                .clone(),
            value: item.id,
        });
    }

    Ok((StatusCode::OK, Json(ret)))
}

#[derive(Deserialize)]
struct Property {
    r#type: String,
}

#[derive(Deserialize)]
struct Database {
    properties: HashMap<String, Property>,
}

#[derive(Deserialize)]
struct DatabaseRoute {
    databases: Vec<RouteItem>,
}

// ref https://developers.notion.com/reference/retrieve-a-database
async fn properties(access_token: &String, database_id: &String) -> Result<HashMap<String, String>, String> {
    let database = HTTP_CLIENT
        .get(format!(
            "https://api.notion.com/v1/databases/{}",
            database_id
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .header("Notion-Version", "2022-06-28")
        .bearer_auth(decrypt(&access_token))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Database>()
        .await
        .map_err(|e| format!("Parse database object failed: {}", e.to_string()))?;

    let ret = database.properties.into_iter()
        .filter_map(|(name, property)| {
            match property.r#type.as_str() {
                "title" | "rich_text" | "url" | "email" | "phone_number" => Some((name, property.r#type)),
                _ => None
            }
        })
        .collect::<HashMap<String, String>>();

    match ret.len() {
        0 => Err("Properties was empty".to_string()),
        _ => Ok(ret)
    }
}

// ref https://developers.notion.com/docs/working-with-databases
//     https://developers.notion.com/reference/post-page
async fn post_msg(req: Json<ReactorReqBody>) -> impl IntoResponse {
    let forwards = req.forwards.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "Invalid JSON data: Missing forwards".to_string(),
    ))?;

    let database_id = &forwards
        .databases
        .first()
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Invalid JSON data: Missing database".to_string(),
        ))?
        .value;

    let text = req
        .text
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?;

    let property_values = serde_json::from_str::<HashMap<String, String>>(&text)
        .map_err(|_|(StatusCode::BAD_REQUEST, "Invalid text: Invalid JSON data".to_string()))?;

    let db_properties = properties(&req.state, database_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let mut properties = Map::new();

    let to_property = |r#type, value| {
        match r#type {
            "title" | "rich_text" => {
                json!({
                    *r#type: [
                        {
                            "text": {
                                "content": value
                            }
                        }
                    ]
                })
            },
            "url" | "email" | "phone_number" => {
                json!({
                    *r#type: value
                })
            },
            _ => unreachable!()
        }
    };

    for (name, p) in property_values {
        let t = db_properties.get(&name)
            .ok_or((StatusCode::BAD_REQUEST, format!("Property {} dose not exist", name)))?;

        properties.insert(name.clone(), to_property(t, p));
    }

    // ref https://developers.notion.com/docs/working-with-databases#adding-pages-to-a-database
    let body = json!({
        "parent": {
            "type": "database_id",
            "database_id": database_id,
        },
        "properties": properties,
    });

    let response = HTTP_CLIENT
        .post("https://api.notion.com/v1/pages")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            "Github Connector of Second State Reactor",
        )
        .bearer_auth(decrypt(&req.state))
        .header("Notion-Version", "2022-06-28")
        .json(&body)
        .send()
        .await;

    match response {
        Ok(r) => Ok((StatusCode::OK, r.bytes().await.unwrap_or_default().to_vec())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Post database item failed: {}.", e.to_string()),
        )),
    }
}

async fn actions() -> impl IntoResponse {
    let actions = serde_json::json!({
        "list": [
            {
                "field": "To create a new page",
                "value": "add_page",
                "desc": "This connector takes the return value of the flow function to create a new page in a database in the connected Notion account. It corresponds to the `Create a page` call in the Notion API."
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
        .route("/databases", post(databases))
        .route("/post", post(post_msg))
        .route("/actions", post(actions));

    axum::Server::bind(&SocketAddr::from(([127, 0, 0, 1], port)))
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
