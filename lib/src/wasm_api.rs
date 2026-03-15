use js_sys::{JSON, Uint8Array};
use wasm_bindgen::prelude::*;

use crate::{Compiler, Scanner};
use serde_json::json;

#[wasm_bindgen(js_name = "checkRule")]
pub fn check_rule(rule: &str) -> JsValue {
    let mut compiler = Compiler::new();
    compiler.enable_includes(false);

    let _ = compiler.add_source(rule);

    to_js_value(json!({
        "errors": compiler.errors(),
        "warnings": compiler.warnings(),
    }))
}

#[wasm_bindgen(js_name = "scanBytes")]
pub fn scan_bytes(rule: &str, data: Uint8Array) -> JsValue {
    let mut compiler = Compiler::new();
    compiler.enable_includes(false);

    if compiler.add_source(rule).is_err() {
        return to_js_value(json!({
            "errors": compiler.errors(),
            "warnings": compiler.warnings(),
            "matching_rules": [],
            "non_matching_rules": [],
        }));
    }

    let rules = compiler.build();
    let bytes = data.to_vec();
    let mut scanner = Scanner::new(&rules);

    match scanner.scan(&bytes) {
        Ok(results) => {
            let matching_rules: Vec<_> = results.matching_rules().collect();
            let non_matching_rules: Vec<_> =
                results.non_matching_rules().collect();

            to_js_value(json!({
                "errors": [],
                "warnings": rules.warnings(),
                "matching_rules": matching_rules,
                "non_matching_rules": non_matching_rules,
            }))
        }
        Err(err) => {
            wasm_bindgen::throw_str(&err.to_string());
        }
    }
}

fn to_js_value(value: serde_json::Value) -> JsValue {
    let json = serde_json::to_string(&value)
        .expect("WASM API response must serialize");
    JSON::parse(&json).expect("WASM API response must be valid JSON")
}
