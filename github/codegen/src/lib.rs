mod actions;
mod reqs;
mod utils;

use actions::impl_macro_actions::impl_actions;
use reqs::impl_macro_reqs::impl_reqs;

use syn::{parse_macro_input, AttributeArgs, ItemFn};

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn reqs_gen(attr: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    let target_fn = parse_macro_input!(input as ItemFn);

    let stream = impl_reqs(&target_fn, &args);

    stream
}

#[proc_macro_attribute]
pub fn action_gen(attr: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    let target_fn = parse_macro_input!(input as ItemFn);

    let stream = impl_actions(&target_fn, &args);

    stream
}