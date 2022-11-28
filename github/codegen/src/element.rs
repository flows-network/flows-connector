use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::EnumMap;
use std::collections::HashMap;

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Element {
    pub tags: Vec<Tag>,
    pub servers: Vec<Server>,
    pub paths: HashMap<String, Path>,
    // webhooks: HashMap<String, Webhook>,
    pub components: Components,
}

// {{{ tag

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    pub description: String,
}

// }}}

// {{{ server

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Server {
    pub url: String,
}

// }}}

// {{{ Path

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct PVe {
    #[serde(rename = "operationId")]
    pub operation_id: String,
    pub summary: String,
    // pub tags: Vec<String>,
    pub parameters: Option<Vec<Parameter>>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<RequestBody>,
    pub description: String,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Parameter {
    // either
    pub name: Option<String>,
    #[serde(rename = "in")]
    pub in_: Option<In_>,
    pub required: Option<bool>,
    pub schema: Option<Schema>,

    // or
    #[serde(rename = "$ref")]
    pub ref_: Option<String>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum In_ {
    #[serde(rename = "path")]
    Path,
    #[serde(rename = "query")]
    Query,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Schema {
    // either
    #[serde(rename = "type")]
    pub type_: Option<SchemaValue>,

    // or
    // #[serde(rename = "oneOf")]
    // one_of: Option<Vec<serde_json::Value>>,

    // or
    #[serde(rename = "$ref")]
    pub ref_: Option<String>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaValue {
    TypeS(TypeSValue),
    TypeL(Vec<String>),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum TypeSValue {
    String(String),
    Number(String),
    Integer(String),
    Array(String),
    Boolean(String),
    Object(String),
}

#[serde_with::serde_as]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct RequestBody {
    #[serde_as(as = "EnumMap")]
    pub content: Vec<Content>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Content {
    #[serde(rename = "application/json")]
    AppJson { schema: Value },
    #[serde(rename = "text/plain")]
    TextPlain(Value),
    #[serde(rename = "text/x-markdown")]
    TextXMD(Value),
    #[serde(rename = "*/*")]
    Raw(Value),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppJsonValue {
    RealSchema(AppJV),
    // RefSchema {
    //     #[serde(rename = "$ref")]
    //     ref_: String,
    // },
    // OneOfSchema {
    //     #[serde(rename = "oneOf")]
    //     one_of: Value,
    // },
    // SeqTypeSchema {
    //     #[serde(rename = "type")]
    //     type_: Vec<String>,
    // },
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AppJV {
    Object {
        properties: HashMap<String, AppJsonValue>,
    },
    String {
        description: Option<String>,
    },
    Boolean {
        description: String,
        default: bool,
    },
    Array {
        description: String,
        items: ArrayItems,
    },
    Integer {
        description: String,
    },
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct ArrayItems {
    #[serde(rename = "type")]
    type_: String,
}

// }}}

#[serde_with::serde_as]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Path(#[serde_as(as = "EnumMap")] pub Vec<PathValue>);

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum PathValue {
    #[serde(rename = "get")]
    GET(PVe),
    #[serde(rename = "post")]
    POST(PVe),
    #[serde(rename = "patch")]
    PATCH(PVe),
    #[serde(rename = "delete")]
    DELETE(PVe),
    #[serde(rename = "put")]
    PUT(PVe),
}

// {{{ webhook
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Webhook {
    pub summary: Option<String>,
    pub tags: Option<Vec<String>>,
    pub parameters: Option<Vec<Parameter>>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Components {
    // responses: Responses,
    pub parameters: Parameters,
    pub schemas: Schemas,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Responses(HashMap<String, CResponse>);

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct CResponse {
    pub description: String,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Parameters(pub HashMap<String, Parameter>);

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Schemas(pub HashMap<String, AppJV>);

// }}}
