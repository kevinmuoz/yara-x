use crate::modules::prelude::*;
use crate::modules::protos::time::*;
#[cfg(target_family = "wasm")]
use js_sys::Date;
#[cfg(not(target_family = "wasm"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[module_main]
fn main(_data: &[u8], _meta: Option<&[u8]>) -> Result<Time, ModuleError> {
    // Nothing to do, but we have to return our protobuf
    Ok(Time::new())
}

#[module_export]
fn now(_ctx: &ScanContext) -> Option<i64> {
    #[cfg(target_family = "wasm")]
    {
        // `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`.
        // Use the browser/JS runtime clock instead and keep the API in
        // seconds since the Unix epoch, matching native builds.
        return Some((Date::now() / 1000.0).floor() as i64);
    }

    #[cfg(not(target_family = "wasm"))]
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use crate::tests::rule_true;
    use crate::tests::test_rule;

    #[test]
    fn now() {
        rule_true!(
            r#"
            import "time"
            rule test { condition: time.now() >= 0 }"#,
            &[]
        );
    }
}
