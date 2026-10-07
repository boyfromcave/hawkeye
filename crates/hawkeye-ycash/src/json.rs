//! Reading the node's JSON without binary floats.
//!
//! `serde_json` would parse `1.23456789` into an `f64`. Rather than enabling its workspace-wide
//! `arbitrary_precision` feature (which changes how every crate in the build sees numbers), the
//! response text is rewritten first: every number literal with a fraction or an exponent becomes a
//! JSON string holding the same characters. [`crate::Amount`] parses those strings exactly, and
//! the few genuinely floating fields (difficulty, verification progress) read them with
//! [`crate::amount::lenient_f64`]. Integers are left as numbers.

use std::borrow::Cow;

use serde::de::DeserializeOwned;

/// Quote every non-integer number literal of a JSON text (strings are copied verbatim).
pub fn preserve_decimals(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    // Fast path: nothing to rewrite when no '.', 'e' or 'E' occurs outside strings.
    let mut out: Option<String> = None;
    let mut i = 0;
    let mut copied = 0; // bytes of `text` already accounted for in `out`
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() {
                    match b[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            c if c == b'-' || c.is_ascii_digit() => {
                let start = i;
                let mut decimal = false;
                while i < b.len() && matches!(b[i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    decimal |= matches!(b[i], b'.' | b'e' | b'E');
                    i += 1;
                }
                if decimal {
                    let o = out.get_or_insert_with(|| String::with_capacity(text.len() + 64));
                    o.push_str(&text[copied..start]);
                    o.push('"');
                    o.push_str(&text[start..i]);
                    o.push('"');
                    copied = i;
                }
            }
            _ => i += 1,
        }
    }
    match out {
        None => Cow::Borrowed(text),
        Some(mut o) => {
            o.push_str(&text[copied.min(text.len())..]);
            Cow::Owned(o)
        }
    }
}

/// Deserialize a node JSON text into `T`, keeping decimals exact.
pub fn from_str<T: DeserializeOwned>(text: &str) -> serde_json::Result<T> {
    serde_json::from_str(&preserve_decimals(text))
}

/// Parse a node JSON text into a [`serde_json::Value`] whose decimals are strings.
pub fn to_value(text: &str) -> serde_json::Result<serde_json::Value> {
    from_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_only_decimals() {
        let t = r#"{"a":1.50000000,"b":-2,"c":"x.5 \"9.1\"","d":[0.00000001,3e2,-4.5E-3],"e":21000000.00000000}"#;
        assert_eq!(
            preserve_decimals(t),
            r#"{"a":"1.50000000","b":-2,"c":"x.5 \"9.1\"","d":["0.00000001","3e2","-4.5E-3"],"e":"21000000.00000000"}"#
        );
        assert!(matches!(
            preserve_decimals(r#"{"a":1,"b":"2.5"}"#),
            Cow::Borrowed(_)
        ));
        assert_eq!(preserve_decimals("1.5"), "\"1.5\"");
        assert_eq!(preserve_decimals(""), "");
    }

    #[test]
    fn amounts_survive() {
        #[derive(serde::Deserialize)]
        struct T {
            v: crate::Amount,
            n: i64,
        }
        let t: T = from_str(r#"{"v": 0.30000000, "n": 7}"#).unwrap();
        assert_eq!(t.v.zat(), 30_000_000);
        assert_eq!(t.n, 7);
    }
}
