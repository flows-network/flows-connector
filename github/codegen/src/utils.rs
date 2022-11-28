use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{ItemFn, ReturnType};

pub fn find_return_type(target_fn: &ItemFn) -> TokenStream2 {
    let mut return_ty = target_fn.sig.output.to_token_stream();
    match &target_fn.sig.output {
        ReturnType::Type(_, b) => {
            return_ty = b.to_token_stream();
        }
        _ => {}
    }
    return_ty
}

// escape ident {{{

pub fn escape_ident(raw: &str) -> &str {
    match raw {
        "async" => "async_",
        "type" => "type_",
        "ref" => "ref_",
        _ => raw,
    }
}

// }}}
