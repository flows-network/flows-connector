use wasmedge_wasi_helper::wasmedge_wasi_helper::_initialize;

#[allow(unused_imports)]
use wasmedge_bindgen::*;
use wasmedge_bindgen_macro::*;

static CONNECT_HTML: &str = include_str!("../../src/connect.html");

/// Return a connect html
/// 
/// headers is a JSON string
/// queries is a JSON string
/// 
/// Return (status: u32, headers: JSON string, body: Vec<u8>)
#[wasmedge_bindgen]
pub fn connect(headers: String, queries: String) -> (u16, String, Vec<u8>) {
	let headers = serde_json::json!({
		"Content-Type": "text/html"
	});
	let headers = serde_json::to_string(&headers).unwrap();
	return (200, headers, CONNECT_HTML.as_bytes().to_vec());
}