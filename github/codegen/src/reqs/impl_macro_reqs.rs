use crate::utils::{escape_ident, find_return_type};
use indexmap::IndexMap;
use openapiv3::{Components, OpenAPI, Operation, Parameter, ReferenceOr, Schema, SchemaKind, Type};

use std::{fs::File, io::Read};
use syn::{AttributeArgs, FnArg, ItemFn, Lit, NestedMeta};

use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::{format_ident, quote, ToTokens};

pub fn impl_reqs(target_fn: &ItemFn, args: &AttributeArgs) -> TokenStream {
    let return_ty = find_return_type(target_fn);
    let func_name_ident = target_fn.sig.ident.to_token_stream();

    let mut fl_ident = "".to_token_stream();
    let mut fl_name = String::new();
    for x in &target_fn.sig.inputs {
        if let FnArg::Typed(t) = x {
            let ty_stream = t.ty.to_token_stream().to_string();
            if is_fl_ref(&ty_stream) {
                fl_ident = t.pat.to_token_stream();
                fl_name = fl_ident.to_string().trim_start_matches("mut ").to_string();
                break;
            }
        }
    }

    let api_ident = if !args.is_empty() {
        if fl_name.is_empty() {
            panic!("[codegen] you should")
        }
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
    let req_body = if filename.ends_with(".json") {
        let mut json_data = String::new();
        let mut f = File::open(filename.as_str())
            .expect(&format!("File Name = '{}' does not exist", filename));
        f.read_to_string(&mut json_data)
            .expect(&format!("{} read_to_string fail", filename));
        parse_json(&json_data, fl_ident)
    } else {
        panic!("[codegen] Require json");
    };

    let func_args_stream = target_fn.sig.inputs.to_token_stream();

    quote! {
        #[derive(Clone, Eq, PartialEq, Debug, serde::Serialize)]
        struct WantDisplay<'a>(&'a serde_json::Value);

        impl<'a> std::fmt::Display for WantDisplay<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                if let Some(s) = self.0.as_str() {
                    write!(f, "{}", s)
                } else {
                    write!(f, "{}", self.0)
                }
            }
        }

        fn #func_name_ident(#func_args_stream) -> #return_ty {
            #req_body
        }
    }
    .into()
}

fn is_fl_ref(ty_stream: &str) -> bool {
    ["Client"].iter().any(|n| ty_stream.contains(n))
}

// {{{ parse json

fn parse_json(json: &str, client: TokenStream2) -> TokenStream2 {
    let value: OpenAPI = serde_json::from_str(&json).expect("[codegen] json parse error");

    let url = &value.servers.first().unwrap().url;

    let components = &value.components.as_ref().unwrap();

    let s: TokenStream2 = value
        .operations()
        .map(|n| gen_via_method(n, components, &client, url))
        .collect();

    quote! {
        match action {
            #s
            _ => None,
        }
    }
}

// }}}

// gen_via_method {{{

fn gen_via_method(
    (path, method, operation): (&str, &str, &Operation),
    components: &Components,
    client: &TokenStream2,
    server: &str,
) -> TokenStream2 {
    let method_ident = format_ident!("{}", method);

    let parameters = &components.parameters;
    let schemas = &components.schemas;

    let unknown = String::from("UNKNOWN");
    let oid = operation.operation_id.as_ref().unwrap_or(&unknown);

    let ass_params = gen_params(parameters, schemas, operation);

    let query_kv: TokenStream2 = operation
        .parameters
        .iter()
        .filter_map(|ref_params| {
            let fro = FindableReferenceOr {
                value: ref_params,
                data: parameters,
            };
            fro.as_real_item().map(|p| gen_formatted_query(p))
        })
        .collect();
    let query = if query_kv.is_empty() {
        quote!()
    } else {
        quote! {
            .query(&[#query_kv])
        }
    };

    let (path, path_params_ident) = gen_formatted_path(server, path);

    let json = gen_json_req(operation, schemas);

    quote! {
        #oid => {
            #ass_params
            Some(
                #client
                    .#method_ident(format!(#path #path_params_ident))
                    #query
                    #json
                )
        },
    }
}

// gen_json_req {{{

fn gen_json_req(
    operation: &Operation,
    schemas: &IndexMap<String, ReferenceOr<Schema>>,
) -> TokenStream2 {
    let kv: TokenStream2 = operation
        .request_body
        .iter()
        .filter_map(|ref_rb| {
            ref_rb.as_item().map(|rb| {
                rb.content
                    .iter()
                    .filter_map(|(media, mt)| {
                        if media == "application/json" {
                            mt.schema
                                .as_ref()
                                .map(|ref_scm| {
                                    gen_kv(ref_scm, schemas).map(|vs| {
                                        vs.iter()
                                            .map(|(name, name_ident)| {
                                                quote! {
                                                    #name: #name_ident,
                                                }
                                            })
                                            .collect::<Vec<_>>()
                                    })
                                })
                                .flatten()
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .collect::<TokenStream2>()
            })
        })
        .collect();

    if kv.is_empty() {
        quote!()
    } else {
        quote! {
            .json(&serde_json::json!({
                #kv
            }))
        }
    }
}

fn gen_kv(
    ref_scm: &ReferenceOr<Schema>,
    schemas: &IndexMap<String, ReferenceOr<Schema>>,
) -> Option<Vec<(String, Ident)>> {
    let fro = FindableReferenceOr {
        value: ref_scm,
        data: schemas,
    };
    fro.as_real_item().map(|scm| match &scm.schema_kind {
        SchemaKind::Type(t) => match t {
            Type::String(_) => vec![],
            Type::Number(_) => vec![],
            Type::Integer(_) => vec![],
            Type::Object(obj) => obj
                .properties
                .iter()
                .flat_map(|(name, ref_scm)| {
                    let name = escape_ident(&name);
                    let name_ident = format_ident!("{}", name);
                    let s = (name.to_string(), name_ident);
                    gen_kv(&ref_scm.clone().unbox(), schemas).map(|mut kv| {
                        kv.push(s);
                        kv
                    })
                })
                .flatten()
                .collect(),
            Type::Array(_) => vec![],
            Type::Boolean {} => vec![],
        },
        SchemaKind::OneOf { one_of: _ } => vec![],
        SchemaKind::AllOf { all_of: _ } => vec![],
        SchemaKind::AnyOf { any_of: _ } => vec![],
        SchemaKind::Not { not: _ } => vec![],
        SchemaKind::Any(_) => vec![],
    })
}

// }}}

// gen_formatted_path {{{

fn gen_formatted_path(server: &str, path: &str) -> (String, TokenStream2) {
    fn gen_path_inner(path: &str) -> String {
        let mut pcs = path.chars();

        let path_pre = pcs.by_ref().take_while(|&c| c != '{').collect::<String>();
        let path_args = pcs.by_ref().take_while(|&c| c != '}').collect::<String>();
        let path_post = pcs.collect::<String>();

        if path_args.is_empty() {
            path_pre
        } else {
            format!("{}{{}}", path_pre) + &gen_path_inner(&format!("{},{}", path_post, path_args))
        }
    }

    let fpath = gen_path_inner(path);

    if fpath.contains(",") {
        let mut sn = fpath.split(',');

        let p = sn.by_ref().next().unwrap();
        let a = sn
            .map(|s| {
                let st = format_ident!("{}", escape_ident(s)).to_token_stream();
                quote!(, #st)
            })
            .collect::<TokenStream2>();

        (format!("{}{}", server, p), a)
    } else {
        (format!("{}{}", server, fpath), quote!())
    }
}

// }}}

// gen_formatted_query {{{

fn gen_formatted_query(parameter: &Parameter) -> TokenStream2 {
    if let Parameter::Query {
        parameter_data,
        allow_reserved: _,
        style: _,
        allow_empty_value: _,
    } = parameter
    {
        let name = escape_ident(&parameter_data.name);
        let name_ident = format_ident!("{}", name);
        quote! {
            (#name, format!("{}", #name_ident)),
        }
    } else {
        quote!()
    }
}

// }}}

// gen_params {{{

fn gen_params(
    parameters: &IndexMap<String, ReferenceOr<Parameter>>,
    schemas: &IndexMap<String, ReferenceOr<Schema>>,
    operation: &Operation,
) -> TokenStream2 {
    let pfp: TokenStream2 = operation
        .parameters
        .iter()
        .filter_map(|ref_params| {
            let fro_p = FindableReferenceOr {
                value: ref_params,
                data: parameters,
            };
            fro_p.as_real_item().map(|p| gen_params_vp(p))
        })
        .collect();
    let pfs: TokenStream2 = operation
        .request_body
        .iter()
        .filter_map(|ref_rb| {
            ref_rb.as_item().map(|rb| {
                rb.content
                    .iter()
                    .filter_map(|(media, mt)| {
                        if media == "application/json" {
                            mt.schema
                                .as_ref()
                                .map(|ref_scm| {
                                    gen_kv(ref_scm, schemas).map(|vs| {
                                        vs.iter()
                                            .map(|(name, var)| {
                                                quote! {
                                                    let #var = WantDisplay(&msg[#name]);
                                                }
                                            })
                                            .collect::<Vec<_>>()
                                    })
                                })
                                .flatten()
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .collect::<TokenStream2>()
            })
        })
        .collect();

    quote!(#pfp #pfs)
}

fn gen_params_vp(parameter: &Parameter) -> TokenStream2 {
    let name = match parameter {
        Parameter::Query {
            parameter_data,
            allow_reserved: _,
            style: _,
            allow_empty_value: _,
        }
        | Parameter::Header {
            parameter_data,
            style: _,
        }
        | Parameter::Path {
            parameter_data,
            style: _,
        }
        | Parameter::Cookie {
            parameter_data,
            style: _,
        } => &parameter_data.name,
    };

    let name = escape_ident(&name);
    let var = format_ident!("{}", name);

    quote! {
        let #var = WantDisplay(&msg[#name]);
    }
}

// }}}

// }}}

// ReferenceOr / find {{{

struct FindableReferenceOr<'r, T> {
    value: &'r ReferenceOr<T>,
    data: &'r IndexMap<String, ReferenceOr<T>>,
}

impl<'ro, T> FindableReferenceOr<'ro, T> {
    fn as_real_item(&self) -> Option<&T> {
        match &self.value {
            ReferenceOr::Reference { reference } => self.find_x(reference),
            ReferenceOr::Item(item) => Some(item),
        }
    }

    fn find_x(&self, ref_: &str) -> Option<&T> {
        let mut ref_ = ref_.split('/').skip(1);

        let _fst = ref_.next().expect("invalid ref");
        let _snd = ref_.next().expect("invalid ref");
        let trd = ref_.next().expect("invalid ref");

        self.data.get(trd).map(|d| d.as_item()).flatten()
    }
}

// }}}
