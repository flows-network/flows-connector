use headers::{Header, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

// post {{{
#[derive(Deserialize, Serialize)]
pub struct PostBody {
    pub user: String,
    pub text: String,
    pub state: String,
    pub forwards: ForwardRoutes,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForwardRoutes {
    pub action: Vec<RouteObject>,
    pub repo: Vec<RouteObject>,
    // pub installations: Vec<RouteObject>,
}

// }}}

// hook {{{

#[derive(Debug, Deserialize)]
pub struct HookRoutes {
    pub event: Vec<RouteObject>,
    pub repo: Vec<RouteObject>,
}
#[derive(Debug, Deserialize)]
pub struct HookReq {
    pub user: String,
    pub state: String,
    pub flow: String,
    pub routes: HookRoutes,
}
// }}}

// post & hook {{{
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteObject {
    pub field: String,
    pub value: String,
}
// }}}

// auth {{{
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthState {
    pub access_token: String,
    pub installation_id: u64,
}
// }}}

// installations {{{

#[derive(Debug, Deserialize, Serialize)]
pub struct Installations {
    // pub total_count: i64,
    pub installations: Vec<Installation>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Installation {
    pub id: u64,
    pub repositories_url: String,
    pub account: Account,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Account {
    pub login: String,
    #[serde(rename = "type")]
    pub type_field: String,
}

// }}}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthBody {
    pub code: String,
    pub installation_id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessTokenBody {
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct InstallationTokenBody {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstRepoPerms {
    pub admin: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstRepo {
    pub node_id: String,
    pub name: String,
    pub full_name: String,
    pub html_url: String,
    pub hooks_url: String,
    pub permissions: InstRepoPerms,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstalledRepos {
    pub total_count: u32,
    pub repositories: Vec<InstRepo>,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    pub connector: String,
    pub flow: String,
    pub payload: String,
}

pub struct GithubEvent(pub String);

// header name must be lowercase
pub static HN: HeaderName = HeaderName::from_static("x-github-event");

impl Header for GithubEvent {
    fn name() -> &'static HeaderName {
        &HN
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i headers::HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        Ok(Self(value.to_str().unwrap().to_owned()))
    }

    fn encode<E: Extend<headers::HeaderValue>>(&self, values: &mut E) {
        let value = HeaderValue::from_str(&self.0).unwrap();
        values.extend(std::iter::once(value));
    }
}

#[derive(Deserialize)]
pub struct RevokeQuery {
    pub hook_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RouteReq {
    // user: String,
    pub state: String,
    pub cursor: Option<String>,
    pub routes: Option<Routes>,
}

#[derive(Debug, Deserialize)]
pub struct Routes {
    pub installation: Option<Vec<RouteObject>>,
}

#[derive(Debug, Deserialize)]
pub struct GithubUser {
    pub login: String,
    pub node_id: String,
    pub email: Option<String>,
}
