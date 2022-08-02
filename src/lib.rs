use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

static HEADER: &[u8] = r#"{"alg":"HS256"}"#.as_bytes();
fn seconds_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
pub enum AuthData<T: Serialize + Deserialize<'static> = ()> {
    Text(String),
    Number(f64),
    TextNumber(String, f64),
    /// Fields `iat`, `exp`, and `__variant` are overriden and will not be visible when the
    /// JWT is decoded.
    Structured(T),
}
fn hmac_sha256(secret: &[u8], bytes: &[u8]) -> impl AsRef<[u8]> {
    type HmacSha256 = Hmac<Sha256>;
    // Hmac can take a key of any length
    let mut hmac = HmacSha256::new_from_slice(secret).unwrap();
    hmac.update(bytes);
    hmac.finalize().into_bytes()
}
impl<T: Serialize + Deserialize<'static>> AuthData<T> {
    /// # Panics
    ///
    /// Panics if a number is `NaN` or an infinity.
    /// The structured data (if that's what this is) must not error when being serialized.
    fn into_jwt(self, secret: &[u8], header: &[u8], seconds_before_expiry: u64) -> String {
        let mut s = String::new();
        base64::encode_config_buf(header, base64::URL_SAFE_NO_PAD, &mut s);
        let mut map = match self {
            Self::Text(t) => {
                let mut map = serde_json::Map::new();
                map.insert("text".to_owned(), serde_json::Value::String(t));
                map.insert("__variant".to_owned(), "t".into());
                map
            }
            Self::Number(n) => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "num".to_owned(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(n)
                            .expect("JWTs cannot contain NaN or infinities"),
                    ),
                );
                map.insert("__variant".to_owned(), "n".into());
                map
            }
            Self::TextNumber(t, n) => {
                let mut map = serde_json::Map::new();
                map.insert("text".to_owned(), serde_json::Value::String(t));
                map.insert(
                    "num".to_owned(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(n)
                            .expect("JWTs cannot contain NaN or infinities"),
                    ),
                );
                map.insert("__variant".to_owned(), "tn".into());
                map
            }
            Self::Structured(t) => {
                let mut v =
                    serde_json::to_value(t).expect("failed to serialize structured auth data");
                if let Some(map) = v.as_object_mut() {
                    let mut map = core::mem::take(map);
                    if map.contains_key("__variant") {
                        log::warn!("`__variant` key in JWT payload will be overridden");
                    }
                    map.insert("__variant".to_owned(), "s".into());
                    map
                } else {
                    let mut map = serde_json::Map::new();
                    map.insert("v".to_owned(), v);
                    map.insert("deserialize_v".to_owned(), serde_json::Value::Bool(true));
                    map.insert("__variant".to_owned(), "s".into());
                    map
                }
            }
        };
        if map.contains_key("iat") {
            log::warn!("`iat` key in JWT payload will be overridden");
        }
        if map.contains_key("exp") {
            log::warn!("`exp` key in JWT payload will be overridden");
        }
        let now = seconds_since_epoch();
        map.insert("iat".to_owned(), serde_json::Value::Number(now.into()));
        map.insert(
            "exp".to_owned(),
            serde_json::Value::Number((now + seconds_before_expiry).into()),
        );
        let value = serde_json::Value::Object(map);
        let payload = value.to_string();
        s.push('.');
        base64::encode_config_buf(payload.as_bytes(), base64::URL_SAFE_NO_PAD, &mut s);

        let signature = hmac_sha256(secret, s.as_bytes());
        s.push('.');
        base64::encode_config_buf(signature, base64::URL_SAFE_NO_PAD, &mut s);
        s
    }
}
pub enum Validation<T: Serialize + Deserialize<'static>> {
    /// This can come from multiple sources, including but not limited to:
    /// - invalid base64 encoding
    /// - invalid JWT structure
    /// - mismatched hash (the user changed their privilege)
    /// - serialization errors to the desired structured type
    /// - unexpected data in the JSON
    /// - failed to parse JSON
    /// - expiry date is not included
    Unauthorized,
    Authorized(AuthData<T>),
}
impl<T: Serialize + DeserializeOwned> Validation<T> {
    #[allow(clippy::match_result_ok)] // macro
    fn inner_validate(s: &str, secret: &[u8], ip: Option<IpAddr>) -> Self {
        macro_rules! or_unauthorized {
            ($v: expr) => {
                if let Some(v) = $v {
                    v
                } else {
                    return Self::Unauthorized;
                }
            };
        }

        let parts = s.splitn(3, '.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Self::Unauthorized;
        }
        let signature_input = &s[..parts[0].len() + parts[1].len() + 1];
        let signature = hmac_sha256(secret, signature_input.as_bytes());
        let remote_signature =
            or_unauthorized!(base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD).ok());
        if signature.as_ref() != remote_signature {
            return Self::Unauthorized;
        }
        let payload = or_unauthorized!(base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
            .ok()
            .and_then(|p| String::from_utf8(p).ok()));
        let mut payload: serde_json::Value = or_unauthorized!(payload.parse().ok());
        let payload = or_unauthorized!(payload.as_object_mut());
        let exp = or_unauthorized!(payload.get("exp").and_then(|v| v.as_u64()));
        let iat = or_unauthorized!(payload.get("iat").and_then(|v| v.as_u64()));
        let now = seconds_since_epoch();
        if exp < now || iat > now {
            return Self::Unauthorized;
        }
        let variant = or_unauthorized!(payload.get("__variant").and_then(|v| v.as_str()));
        let data = match variant {
            "t" => {
                let s = or_unauthorized!(payload.get("text").and_then(|v| v.as_str()));
                AuthData::Text(s.to_owned())
            }
            "n" => {
                let n = or_unauthorized!(payload.get("num").and_then(|v| v.as_f64()));
                AuthData::Number(n)
            }
            "tn" => {
                let s = or_unauthorized!(payload.get("text").and_then(|v| v.as_str()));
                let n = or_unauthorized!(payload.get("num").and_then(|v| v.as_f64()));
                AuthData::TextNumber(s.to_owned(), n)
            }
            "s" => {
                let serialize_v = payload.get("serialize_v").map_or(false, |v| v == true);
                let v = if serialize_v {
                    or_unauthorized!(payload.get_mut("v")).take()
                } else {
                    payload.remove("iat");
                    payload.remove("exp");
                    payload.remove("__variant");
                    serde_json::Value::Object(std::mem::take(payload))
                };
                AuthData::Structured(or_unauthorized!(serde_json::from_value(v).ok()))
            }
            _ => return Self::Unauthorized,
        };
        Self::Authorized(data)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn serde() {
        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        let token = d.into_jwt(b"secretkey", HEADER, 60);

        let v = Validation::<HashMap<String, String>>::inner_validate(&token, b"secretkey", None);
        match v {
            Validation::Authorized(AuthData::Structured(map)) => {
                assert_eq!(map["loggedInAs"], "admin");
                assert_eq!(map.len(), 1)
            }
            Validation::Authorized(_) => panic!("wrong __variant"),
            Validation::Unauthorized => panic!("unauthorized"),
        }
    }
    #[test]
    fn tampering_1() {
        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        // eyJhbGciOiJIUzI1NiJ9.eyJfX3ZhcmlhbnQiOiJzIiwiZXhwIjoxNjU5NDc3MjA4LCJpYXQiOjE2NTk0NzcxNDgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.p4V5nMMHYbri-na4aEPJzVIMb2U1XhEH9RmL8Hurra4
        let _token = d.into_jwt(b"secretkey", HEADER, 60);

        // changed `loggedInAs` to `superuser`
        let tampered_token = "eyJhbGciOiJIUzI1NiJ9.eyJfX3ZhcmlhbnQiOiJzIiwiZXhwIjoxNjU5NDc3MjA4LCJpYXQiOjE2NTk0NzcxNDgsImxvZ2dlZEluQXMiOiJzdXBlcnVzZXIifQ.p4V5nMMHYbri-na4aEPJzVIMb2U1XhEH9RmL8Hurra4";

        let v = Validation::<HashMap<String, String>>::inner_validate(
            tampered_token,
            b"secretkey",
            None,
        );
        match v {
            Validation::Authorized(_) => panic!("should be unauthorized"),
            Validation::Unauthorized => {}
        }
    }
    #[test]
    fn tampering_2() {
        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "user".to_owned());
        let d = AuthData::Structured(map);
        let _token = d.into_jwt(b"secretkey", HEADER, 60);

        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        let tampered_token = d.into_jwt(b"the hacker's secret", HEADER, 60);

        let v = Validation::<HashMap<String, String>>::inner_validate(
            &tampered_token,
            b"secretkey",
            None,
        );
        match v {
            Validation::Authorized(_) => panic!("should be unauthorized"),
            Validation::Unauthorized => {}
        }
    }
}
