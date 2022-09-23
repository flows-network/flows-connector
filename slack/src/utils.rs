use crate::global::HTTP_CLIENT;
use crate::global::REACTOR_API_PREFIX;
use crate::global::REACTOR_AUTH_TOKEN;
use reqwest::multipart;
use rsa::{PaddingScheme, PublicKey};

use crate::{
    global::{CHACHA8RNG, PRIV_KEY, PUB_KEY},
    models::File,
};

pub fn encrypt(data: &str) -> String {
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

pub fn decrypt(data: &str) -> String {
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

pub async fn post_event_to_reactor(
    user: String,
    text: String,
    files: Vec<File>,
    channel: String,
    event: String,
) {
    if files.is_empty() {
        let request = serde_json::json!({
            "user": user,
            "text": text,
            "triggers": {
                "channels": channel,
                "event": event,
            }
        });

        _ = HTTP_CLIENT
            .post(format!("{}/api/_funcs/_post", REACTOR_API_PREFIX.as_str()))
            .header("Authorization", REACTOR_AUTH_TOKEN.as_str())
            .json(&request)
            .send()
            .await;
    } else if let Ok(access_token) = get_author_token_from_reactor(&user).await {
        let mut request = multipart::Form::new()
            .text("user", user)
            .text("text", text)
            .text(
                "triggers",
                format!(r#"{{"channels": "{}", "event": "message"}}"#, channel),
            );

        for f in files.into_iter() {
            if let Ok(b) = get_file(&access_token, &f.url_private).await {
                if let Ok(part) = multipart::Part::bytes(b)
                    .file_name(f.name)
                    .mime_str(&f.mimetype)
                {
                    request = request.part("file", part);
                }
            }
        }

        let _ = HTTP_CLIENT
            .post(format!(
                "{}/api/_funcs/_upload",
                REACTOR_API_PREFIX.as_str()
            ))
            .header("Authorization", REACTOR_AUTH_TOKEN.as_str())
            .multipart(request)
            .send()
            .await;
    }
}

async fn get_file(access_token: &str, url_private: &str) -> Result<Vec<u8>, ()> {
    let response = HTTP_CLIENT
        .get(url_private)
        .bearer_auth(access_token)
        .send()
        .await;

    if let Ok(res) = response {
        if res.status().is_success() {
            if let Ok(body) = res.bytes().await {
                return Ok(body.to_vec());
            }
        }
    }

    Err(())
}

async fn get_author_token_from_reactor(user: &str) -> Result<String, ()> {
    let request = serde_json::json!({ "author": user });

    let response = HTTP_CLIENT
        .post(format!(
            "{}/api/_funcs/_author_state",
            REACTOR_API_PREFIX.as_str()
        ))
        .header("Authorization", REACTOR_AUTH_TOKEN.as_str())
        .json(&request)
        .send()
        .await;

    if let Ok(res) = response {
        if res.status().is_success() {
            if let Ok(body) = res.text().await {
                return Ok(decrypt(body.as_str()));
            }
        }
    }
    Err(())
}
