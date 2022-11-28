use std::{fs::File, io::Read};

use indexmap::IndexMap;
use openapiv3::PathItem;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};
use serde::Deserialize;
use serde_json::Value;
use syn::{AttributeArgs, ItemFn, Lit, NestedMeta};

use crate::utils::find_return_type;

pub fn impl_events(target_fn: &ItemFn, args: &AttributeArgs) -> TokenStream {
    let return_ty = find_return_type(target_fn);
    let func_name_ident = target_fn.sig.ident.to_token_stream();
    let api_ident = if !args.is_empty() {
        let mut s = String::new();
        for elem in args {
            if let NestedMeta::Lit(l) = elem {
                if let Lit::Str(v) = l {
                    s += v.value().as_str();
                }
            }
        }
        quote!(#s)
    } else {
        panic!("[codegen] Incorrect macro parameter length");
    };

    let mut filename = api_ident.to_string().trim().to_string();
    if filename.ends_with(".json\"") {
        filename = filename
            .trim_start_matches("\"")
            .trim_end_matches("\"")
            .to_string();
    }
    let (const_body, action_body) = if filename.ends_with(".json") {
        let mut json_data = String::new();
        let mut f = File::open(filename.as_str())
            .expect(&format!("File Name = '{}' does not exist", filename));
        f.read_to_string(&mut json_data)
            .expect(&format!("{} read_to_string fail", filename));
        parse_json(&json_data)
    } else {
        panic!("[codegen] Require json");
    };

    quote! {
        #[derive(Debug, serde::Deserialize)]
        pub struct ActionRouteReq {
            pub cursor: Option<String>,
        }

        #const_body

        pub async fn #func_name_ident(axum::Json(body): axum::Json<ActionRouteReq>) -> #return_ty {
            #action_body
        }
    }
    .into()
}

fn parse_json(json: &str) -> (TokenStream2, TokenStream2) {
    let value: OpenAPIWithWebHook =
        serde_json::from_str(&json).expect("[codegen] json parse error");

    let kv: Vec<Value> = value
        .webhooks
        .iter()
        .filter_map(|(_, path_item)| gen_json_res(path_item))
        .collect();

    let total_count = kv.len();

    let events: Vec<String> = kv
        .chunks(20)
        .map(|vs| vs.to_vec().into_iter().collect::<Value>().to_string())
        .collect();
    let ev_count = events.len();

    (
        quote! {
            const TOTAL_COUNT: usize = #total_count;
            const EVENTS: [&'static str; #ev_count] = [
                #(#events,)*
            ];
        },
        quote! {
            let page = body.cursor.unwrap_or_else(|| "1".to_string());
            let event = if let Ok(page) = page.parse::<usize>() {
                let result = if TOTAL_COUNT > page * 20 {
                    serde_json::json!({
                        "next_cursor": page + 1,
                        "list": serde_json::from_str::<serde_json::Value>(EVENTS[page]).unwrap(),
                    })
                } else {
                    serde_json::json!({
                        "list": serde_json::from_str::<serde_json::Value>(EVENTS.first().unwrap()).unwrap()
                    })
                };
                Ok(axum::Json(result))
            } else {
                Err((reqwest::StatusCode::BAD_REQUEST, "Invalid cursor".to_string()))
            };
            ([("content-type", "application/json")], event)
        },
    )
}

fn gen_json_res(path_item: &PathItem) -> Option<Value> {
    let operation = path_item.post.as_ref().unwrap();
    if let (Some(field), Some(value), Some(desc)) = (
        operation.summary.as_ref(),
        operation.operation_id.as_ref(),
        operation.description.as_ref(),
    ) {
        Some(serde_json::json!({
            "field": field,
            "value": value,
            "desc": desc,
        }))
    } else {
        None
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct OpenAPIWithWebHook {
    #[serde(rename = "x-webhooks")]
    webhooks: IndexMap<String, PathItem>,

    // #[serde(flatten)]
    // openapi: OpenAPI,
}
