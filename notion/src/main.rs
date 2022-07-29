use axum::{
    extract::{Query, Json},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router};
use axum_server::tls_rustls::RustlsConfig;
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme, PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{env, net::SocketAddr, collections::HashMap};
use reqwest::{Client, header};

const RSA_BITS: usize = 2048;

lazy_static! {
    static ref REACTOR_API_PREFIX: String =
        env::var("REACTOR_API_PREFIX").expect("Env variable REACTOR_API_PREFIX not set");
    static ref NOTION_APP_REDIRECT_URL: String =
        env::var("NOTION_APP_REDIRECT_URL").expect("Env variable NOTION_APP_REDIRECT_URL not set");
    static ref NOTION_APP_CLIENT_ID: String =
        env::var("NOTION_APP_CLIENT_ID").expect("Env variable NOTION_APP_CLIENT_ID not set");
    static ref NOTION_APP_CLIENT_SECRET: String = env::var("NOTION_APP_CLIENT_SECRET")
        .expect("Env variable NOTION_APP_CLIENT_SECRET not set");

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

#[derive(Deserialize)]
struct AuthBody {
    code: String,       // Temporary authorization code
}

// ref https://developers.notion.com/docs/authorization
async fn auth(auth_body: Query<AuthBody>) -> impl IntoResponse {
    if auth_body.code.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No code".to_string()));
    }

    match get_access_token(&auth_body.code).await {
        Ok(at) => {
            let location = format!(
                "{}/api/connected?authorId={}&authorName={}&authorState={}",
                REACTOR_API_PREFIX.as_str(),
                at.workspace_id,
                urlencoding::encode(&at.workspace_name
                    .unwrap_or_else(|| "Unknown workspace name".to_string())),
                encrypt(&at.access_token),
            );
            Ok((StatusCode::FOUND, [("Location", location)]))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

#[derive(Deserialize)]
struct AccessTokenBody {
    access_token: String,
    workspace_id: String,
    workspace_name: Option<String>
}

async fn get_access_token(code: &str) -> Result<AccessTokenBody, String> {
    let body = json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": NOTION_APP_REDIRECT_URL.as_str(),
    });

    let response = HTTP_CLIENT
        .post("https://api.notion.com/v1/oauth/token")
        .header(header::USER_AGENT, "Github Connector of Second State Reactor")
        .header(header::CONTENT_TYPE, "application/json")
        .basic_auth(&*NOTION_APP_CLIENT_ID, Some(&*NOTION_APP_CLIENT_SECRET))
        .json(&body)
        .send()
        .await;

    match response {
        Ok(resp) => {
            match resp.json::<AccessTokenBody>().await {
                Ok(at) => Ok(at),
                Err(e) => Err(e.to_string()),
            }
        },
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Deserialize)]
struct ForwardRoute {
    route: String,
    value: String,
}

#[derive(Deserialize)]
struct ReactorReqBody {
    // user: String,                   // Workspace ID
    state: String,
    text: Option<String>,
    cursor: Option<String>,
    forwards: Option<Vec<ForwardRoute>>,
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


#[derive(Serialize)]
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
            "value": "2022-06-28",
            "property": "object",
        },
        "page_size": 10,
    });

    if let Some(cursor) = &req.cursor {
        body.as_object_mut().unwrap()
            .insert("start_cursor".to_string(), Value::String(cursor.clone()));
    }

    let response = HTTP_CLIENT
        .post("https://api.notion.com/v1/search")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "Github Connector of Second State Reactor")
        .header("Notion-Version", "2022-06-28")
        .bearer_auth(decrypt(&req.state))
        .json(&body)
        .send()
        .await;

    let list = match response {
        Ok(resp) => {
            match resp.json::<DatabaseList>().await {
                Ok(list) => list,
                Err(e) => { return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())) },
            }
        },
        Err(e) => { return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())) },
    };

    let mut ret = RouteList { cursor: None, list: Vec::new() };

    if let Value::String(cursor) = &list.next_cursor {
        ret.cursor = Some(cursor.clone());
    }

    for item in list.results {
        ret.list.push(RouteItem { field: item.title[0].plain_text.clone(), value: item.id });
    }

    Ok((StatusCode::OK, Json(ret)))
}

// ref https://developers.notion.com/docs/working-with-databases
//     https://developers.notion.com/reference/post-page
async fn post_msg(req: Json<ReactorReqBody>) -> impl IntoResponse {
    let routes = if let Some(f) = &req.forwards {
        f.iter().map(|route| { (route.route.clone(), route.value.clone()) })
            .collect::<HashMap<String, String>>()
    } else {
        return Err((StatusCode::BAD_REQUEST, "Invalid JSON data: Missing forwards".to_string()));
    };

    let database_id = if let Some(id) = routes.get("database") {
        id
    } else {
        return Err((StatusCode::BAD_REQUEST, "Invalid JSON data: Missing database".to_string()));
    };

    let property = if let Some(p) = routes.get("property") {
        p
    } else {
        return Err((StatusCode::BAD_REQUEST, "Invalid JSON data: Missing property".to_string()));
    };

    let text = if let Some(t) = &req.text {
        t
    } else {
        return Err((StatusCode::BAD_REQUEST, "Missing text".to_string()));
    };

    // ref https://developers.notion.com/docs/working-with-databases#adding-pages-to-a-database
    let body = json!({
        "parent": {
            "type": "database_id", 
            "database_id": database_id,
        },
        "properties": {
            property: {
                "title": [
                    {
                        "text": {
                            "content": text,
                        }
                    }
                ]
            }
        },
    });

    let response = HTTP_CLIENT
        .post("https://api.notion.com/v1/pages")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "Github Connector of Second State Reactor")
        .bearer_auth(decrypt(&req.state))
        .header("Notion-Version", "2022-06-28")
        .json(&body)
        .send()
        .await;

    match response {
        Ok(_) => Ok((StatusCode::OK, "Ok.".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR,
            format!("Post database item failed: {}.", e.to_string()))),
    }
}

#[derive(Deserialize)]
struct Database {
    properties: Value,
}

// ref https://developers.notion.com/reference/retrieve-a-database
async fn properties(req: Json<ReactorReqBody>) -> impl IntoResponse {
    let database_id = if let Some(forwards) = &req.forwards {
        if let Some(route) = forwards.first() {
            if route.route.eq("database") {
                route.value.clone()
            } else {
                return Err((StatusCode::BAD_REQUEST, "Invalid JSON data: Missing database".to_string()));
            }
        } else {
            return Err((StatusCode::BAD_REQUEST, "Invalid JSON data: Missing database".to_string()));
        }
    } else {
        return Err((StatusCode::BAD_REQUEST, "Invalid JSON data: Missing forwards".to_string()));
    };
    
    let response = HTTP_CLIENT
        .get(format!("https://api.notion.com/v1/databases/{}", database_id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "Github Connector of Second State Reactor")
        .header("Notion-Version", "2022-06-28")
        .bearer_auth(decrypt(&req.state))
        .send()
        .await;

    let properties = match response {
        Ok(resp) => {
            match resp.json::<Database>().await {
                Ok(db) => {
                    if let Value::Object(p) = db.properties {
                        p
                    } else {
                        return Err((StatusCode::INTERNAL_SERVER_ERROR,
                            "Parse properties failed".to_string()));
                    }
                },
                Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Parse database object failed: {}", e.to_string()))),
            }
        },
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR,
            format!("Get database failed: {}", e.to_string()))),
    };

    let mut ret = RouteList { cursor: None, list: Vec::new() };

    for (name, _) in properties {
        ret.list.push(RouteItem { field: name.clone(), value: name });
    }

    Ok((StatusCode::OK, Json(ret)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("PORT").unwrap_or_else(|_| "8090".to_string())
        .parse::<u16>()?;

    let app = Router::new()
        .route("/auth", get(auth))
        .route("/databases", post(databases))
        .route("/post-msg", post(post_msg))
        .route("/properties", post(properties));

    let config = RustlsConfig::from_pem_file(
            "./cert.pem",
            "./key.pem",
    )
    .await
    .expect("Can not found certificate(./cert.pem) and private key(./key.pem).");

    axum_server::bind_rustls(SocketAddr::from(([127, 0, 0, 1], port)), config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
