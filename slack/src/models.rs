use serde::{Deserialize, Serialize};

// auth {{{
#[derive(Deserialize, Serialize)]
pub struct AuthBody {
    pub code: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthedUser {
    pub id: String,
    pub access_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OAuthAccessBody {
    pub ok: bool,
    pub authed_user: Option<AuthedUser>,
    pub access_token: Option<String>,
    pub error: Option<String>,
}
// }}}

// channels {{{

#[derive(Deserialize)]
#[serde(untagged)]
pub enum MaybeChannels {
    Channels(Channels),
    Failure(Failure),
}

#[derive(Deserialize)]
pub struct Channels {
    pub ok: bool,
    pub channels: Vec<Channel>,
    pub response_metadata: RespMeta,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: Option<String>,
    pub is_channel: Option<bool>,
    pub is_im: Option<bool>,
    pub is_member: Option<bool>,
    pub user: Option<String>,
}

#[derive(Deserialize)]
pub struct RespMeta {
    pub next_cursor: String,
}

#[derive(Deserialize)]
pub struct Failure {
    // pub ok: bool,
    pub error: String,
}

#[derive(Deserialize)]
pub struct RouteReq {
    pub user: String,
    pub state: String,
    pub cursor: Option<String>,
}

// }}}

// event {{{

#[derive(Debug, Deserialize)]
pub struct EventBody {
    pub challenge: Option<String>,
    pub event: Option<Event>,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub typ: String,
    pub bot_id: Option<String>,
    pub channel: Option<String>,
    // channel_type: Option<String>,
    pub user: Option<String>,
    pub text: Option<String>,
    pub files: Option<Vec<File>>,
}

#[derive(Debug, Deserialize)]
pub struct File {
    pub name: String,
    pub mimetype: String,
    pub url_private: String,
}

// }}}

// inter {{{

#[derive(Debug, Serialize, Deserialize)]
pub struct Shortcut {
    pub user: User,
    pub channel: ShortcutChannel,
    pub callback_id: String,
    // #[serde(rename = "response_url")]
    // pub response_url: String,
    pub message: Message,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShortcutChannel {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub text: String,
}

// }}}

// join channels {{{

#[derive(Debug, Deserialize)]
pub struct JoinChannelReq {
    // pub user: String,
    pub state: String,
    pub routes: HookRoutes,
}

#[derive(Debug, Deserialize)]
pub struct HookRoutes {
    pub channels: Vec<RouteObject>,
}

#[derive(Debug, Deserialize)]
pub struct ChannelInfo {
    pub ok: bool,
    pub channel: Option<Channel>,
}

// }}}

// post {{{

#[derive(Debug, Deserialize, Serialize)]
pub struct PostBody {
    pub user: String,
    pub text: String,
    pub state: String,
    pub forwards: ForwardRoutes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardRoutes {
    pub channels: Vec<RouteObject>,
    pub action: Vec<Action>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteObject {
    // field: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Action {
    // field: String,
    pub value: ActionValue,
    // desc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ActionValue {
    #[serde(rename = "send_message")]
    SendMessage,
    #[serde(rename = "send_dm")]
    SendDM,
}

// }}}
