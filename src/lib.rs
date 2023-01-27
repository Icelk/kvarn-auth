#![doc = include_str!("../README.md")]
// See https://doc.rust-lang.org/beta/unstable-book/language-features/doc-cfg.html & https://github.com/rust-lang/rust/pull/89596
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(dead_code)]
#![deny(missing_docs)]
use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(not(feature = "structured"))]
mod unescape;

use futures::FutureExt;

#[cfg(any(feature = "ecdsa", feature = "hmac"))]
use rand::Rng;
#[cfg(any(feature = "ecdsa", feature = "rsa", feature = "hmac"))]
use sha2::Digest;

#[cfg(feature = "structured")]
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "chacha20")]
use chacha20::cipher::{KeyIvInit, StreamCipher};
#[cfg(feature = "hmac")]
use hmac::{Hmac, Mac};
#[cfg(feature = "ecdsa")]
use p256::ecdsa::signature::{Signer, Verifier};
#[cfg(feature = "rsa")]
use rsa::PublicKey;

#[cfg(feature = "chacha20")]
pub use chacha20;
#[cfg(feature = "hmac")]
pub use hmac;
#[cfg(feature = "ecdsa")]
pub use p256;
#[cfg(feature = "rsa")]
pub use rsa;

#[cfg(not(any(feature = "ecdsa", feature = "rsa", feature = "hmac")))]
compile_error!("At least one algorithm has to be enabled.");

/// Trait to allow type bounds when serde isn't enabled.
#[cfg(not(feature = "structured"))]
pub trait Serialize {}
#[cfg(not(feature = "structured"))]
impl<T> Serialize for T {}
/// Trait to allow type bounds when serde isn't enabled.
#[cfg(not(feature = "structured"))]
pub trait DeserializeOwned {}
#[cfg(not(feature = "structured"))]
impl<T> DeserializeOwned for T {}

const BASE64_ENGINE: base64::engine::fast_portable::FastPortable =
    base64::engine::fast_portable::FastPortable::from(
        &base64::alphabet::URL_SAFE,
        base64::engine::fast_portable::FastPortableConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

fn seconds_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get_cookie<'a, T>(req: &'a kvarn::prelude::Request<T>, name: &str) -> Option<(&'a str, usize)> {
    get_cookie_with_header_pos(req, name).map(|(c, p, _)| (c, p))
}
fn get_cookie_with_header_pos<'a, T>(
    req: &'a kvarn::prelude::Request<T>,
    name: &str,
) -> Option<(&'a str, usize, usize)> {
    let mut cookie = None;
    let filter = format!("{}=", name);
    for (header_pos, header) in req
        .headers()
        .get_all("cookie")
        .into_iter()
        .enumerate()
        .filter_map(|(p, h)| h.to_str().ok().map(|h| (p, h)))
    {
        if let Some(pos) = header.find(&filter) {
            cookie = Some((header, pos + filter.len(), header_pos));
            break;
        }
    }
    cookie
}
fn extract_cookie_value(d: (&str, usize)) -> &str {
    let s = &d.0[d.1..];
    s.split(';').next().unwrap_or(s)
}
fn remove_cookie(req: &mut kvarn::FatRequest, cookie_name: &str) -> bool {
    use kvarn::prelude::*;
    if let Some((cookie, pos, header_pos)) = get_cookie_with_header_pos(req, cookie_name) {
        let value_start = pos - cookie_name.len() - 1;
        let value_end = cookie[value_start..]
            .find("; ")
            .map(|v| v + 2)
            .unwrap_or_else(|| cookie.len() - value_start)
            + value_start;
        let mut new_cookie_header = cookie.to_owned();
        new_cookie_header.drain(value_start..value_end);
        let header_to_change = req.headers_mut().entry("cookie");
        if let header::Entry::Occupied(mut entry) = header_to_change {
            let header_to_change = entry.iter_mut().nth(header_pos).unwrap();
            *header_to_change = HeaderValue::from_str(&new_cookie_header)
                .expect("unreachable, as we just removed bytes");
        } else {
            unreachable!(
                "The header must be present, since we got the data from it in the previous call"
            );
        }
        true
    } else {
        false
    }
}
fn remove_set_cookie(
    response: &mut kvarn::prelude::Response<kvarn::prelude::Bytes>,
    cookie_name: &str,
    cookie_path: &str,
) {
    let remove_cookie = format!(
        "{cookie_name}=\"\"; \
        Path={cookie_path}; \
        Max-Age=1"
    );
    response.headers_mut().append(
        "set-cookie",
        kvarn::prelude::HeaderValue::from_str(&remove_cookie)
            .expect("a user-supplied cookie_name or the cookie_path contains illegal bytes for use in a header"),
    );
}
/// The data in the JWT.
///
/// This stores any data attached to a logged in user.
/// This data is not secret - it can be ready by the receiver.
/// The authenticity of the message is however always conserved (as long as your secret hasn't
/// leaked).
#[derive(Debug)]
pub enum AuthData<T: Serialize + DeserializeOwned = ()> {
    /// No data.
    None,
    /// Text data.
    Text(String),
    /// A number.
    Number(f64),
    /// Text and a number.
    TextNumber(String, f64),
    /// Fields `iat`, `exp`, and `__variant` are overriden and will not be visible when the
    /// JWT is decoded.
    ///
    /// This panics when the serde feature is not enabled.
    Structured(T),
}
#[cfg(feature = "hmac")]
fn hmac_sha256(secret: &[u8], bytes: &[u8]) -> impl AsRef<[u8]> {
    type HmacSha256 = Hmac<sha2::Sha256>;
    // Hmac can take a key of any length
    let mut hmac = HmacSha256::new_from_slice(secret).unwrap();
    hmac.update(bytes);
    hmac.finalize().into_bytes()
}
fn ip_to_bytes(ip: IpAddr, buf: &mut Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => buf.extend(v4.octets()),
        IpAddr::V6(v6) => buf.extend(v6.octets()),
    }
}
impl<T: Serialize + DeserializeOwned> AuthData<T> {
    /// # Panics
    ///
    /// Panics if a number is `NaN` or an infinity.
    /// The structured data (if that's what this is) must not error when being serialized.
    #[cfg(feature = "structured")]
    fn into_jwt(
        self,
        signing_algo: &ComputedAlgo,
        header: &[u8],
        seconds_before_expiry: u64,
        ip: Option<IpAddr>,
    ) -> String {
        let mut s = base64::encode_engine(header, &BASE64_ENGINE);
        let mut map = match self {
            Self::None => {
                let mut map = serde_json::Map::new();
                map.insert("__variant".to_owned(), "e".into());
                map
            }
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
                    if map.contains_key("__deserialize_v") {
                        log::warn!("`__deserialize_v` key in JWT payload will be overridden");
                        map.insert("__deserialize_v".to_owned(), serde_json::Value::Bool(false));
                    }
                    map.insert("__variant".to_owned(), "s".into());
                    map
                } else {
                    let mut map = serde_json::Map::new();
                    map.insert("v".to_owned(), v);
                    map.insert("__deserialize_v".to_owned(), serde_json::Value::Bool(true));
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
        base64::encode_engine_string(payload.as_bytes(), &mut s, &BASE64_ENGINE);
        match signing_algo {
            #[cfg(feature = "hmac")]
            ComputedAlgo::HmacSha256 { secret, .. } => {
                // Hmac can take a key of any length
                let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
                hmac.update(s.as_bytes());
                if let Some(ip) = ip {
                    hmac.update(IpBytes::from(ip).as_ref());
                }
                let sig = hmac.finalize().into_bytes();
                s.push('.');
                base64::encode_engine_string(sig, &mut s, &BASE64_ENGINE);
            }
            #[cfg(feature = "rsa")]
            ComputedAlgo::RSASha256 {
                private_key,
                public_key: _,
            } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(s.as_bytes());
                if let Some(ip) = ip {
                    hasher.update(IpBytes::from(ip).as_ref());
                }
                let hash = hasher.finalize();
                let signature = private_key
                    .sign(
                        rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>(),
                        &hash,
                    )
                    .expect("failed to sign JWT with RSA key");
                s.push('.');
                base64::encode_engine_string(signature, &mut s, &BASE64_ENGINE);
            }
            #[cfg(feature = "ecdsa")]
            ComputedAlgo::EcdsaP256 { private_key, .. } => {
                let signature = if let Some(ip) = ip {
                    let mut v = s.as_bytes().to_vec();
                    v.extend_from_slice(IpBytes::from(ip).as_ref());
                    private_key.sign(&v)
                } else {
                    private_key.sign(s.as_bytes())
                };
                s.push('.');
                base64::encode_engine_string(signature, &mut s, &BASE64_ENGINE);
            }
        }
        s
    }
    /// # Panics
    ///
    /// Panics if a number is `NaN` or an infinity.
    /// The structured data (if that's what this is) must not error when being serialized.
    #[cfg(not(feature = "structured"))]
    fn into_jwt(
        self,
        signing_algo: &ComputedAlgo,
        header: &[u8],
        seconds_before_expiry: u64,
        ip: Option<IpAddr>,
    ) -> String {
        let mut s = base64::encode_engine(header, &BASE64_ENGINE);
        let mut json = String::new();
        json.push_str(r#"{"__variant":"#);
        match self {
            Self::None => {
                json.push_str(r#""e","#);
            }
            Self::Text(t) => {
                json.push_str(r#""t","text":""#);
                json.push_str(&t.escape_default().to_string());
                json.push_str("\",");
            }
            Self::Number(n) => {
                json.push_str(r#""n","num":"#);
                json.push_str(&n.to_string());
                json.push(',');
            }
            Self::TextNumber(t, n) => {
                json.push_str(r#""tn","text":""#);
                json.push_str(&t.escape_default().to_string());
                json.push_str("\",");
                json.push_str(r#""num":"#);
                json.push_str(&n.to_string());
                json.push(',');
            }
            Self::Structured(_t) => {
                panic!("Using AuthData::Structured without the serde feature enabled")
            }
        };
        let now = seconds_since_epoch();
        json.push_str(r#""iat":"#);
        json.push_str(&now.to_string());
        json.push(',');
        json.push_str(r#""exp":"#);
        json.push_str(&(now + seconds_before_expiry).to_string());
        json.push('}');
        let payload = json;
        s.push('.');
        base64::encode_engine_string(payload.as_bytes(), &mut s, &BASE64_ENGINE);

        match signing_algo {
            #[cfg(feature = "hmac")]
            ComputedAlgo::HmacSha256 { secret, .. } => {
                // Hmac can take a key of any length
                let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
                hmac.update(s.as_bytes());
                if let Some(ip) = ip {
                    hmac.update(IpBytes::from(ip).as_ref());
                }
                let sig = hmac.finalize().into_bytes();
                s.push('.');
                base64::encode_engine_string(sig, &mut s, &BASE64_ENGINE);
            }
            #[cfg(feature = "rsa")]
            ComputedAlgo::RSASha256 {
                private_key,
                public_key: _,
            } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(s.as_bytes());
                if let Some(ip) = ip {
                    hasher.update(IpBytes::from(ip).as_ref());
                }
                let hash = hasher.finalize();
                let signature = private_key
                    .sign(
                        rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>(),
                        &hash,
                    )
                    .expect("failed to sign JWT with RSA key");
                s.push('.');
                base64::encode_engine_string(signature, &mut s, &BASE64_ENGINE);
            }
            #[cfg(feature = "ecdsa")]
            ComputedAlgo::EcdsaP256 { private_key, .. } => {
                let signature = if let Some(ip) = ip {
                    let mut v = s.as_bytes().to_vec();
                    v.extend_from_slice(IpBytes::from(ip).as_ref());
                    private_key.sign(&v)
                } else {
                    private_key.sign(s.as_bytes())
                };
                s.push('.');
                base64::encode_engine_string(signature, &mut s, &BASE64_ENGINE);
            }
        }
        s
    }
    /// # Panics
    ///
    /// See [`Self::into_jwt`].
    fn into_jwt_with_default_header(
        self,
        signing_algo: &ComputedAlgo,
        seconds_before_expiry: u64,
        ip: Option<IpAddr>,
    ) -> String {
        static HS_HEADER: &[u8] = r#"{"alg":"HS256"}"#.as_bytes();
        static RS_HEADER: &[u8] = r#"{"alg":"RS256"}"#.as_bytes();
        static EP_HEADER: &[u8] = r#"{"alg":"ES256"}"#.as_bytes();
        let header = match signing_algo {
            #[cfg(feature = "hmac")]
            ComputedAlgo::HmacSha256 { .. } => HS_HEADER,
            #[cfg(feature = "rsa")]
            ComputedAlgo::RSASha256 { .. } => RS_HEADER,
            #[cfg(feature = "ecdsa")]
            ComputedAlgo::EcdsaP256 { .. } => EP_HEADER,
        };
        self.into_jwt(signing_algo, header, seconds_before_expiry, ip)
    }
}
/// The state of the user in question.
#[derive(Debug)]
pub enum Validation<T: Serialize + DeserializeOwned> {
    /// This can come from multiple sources, including but not limited to:
    /// - invalid base64 encoding
    /// - invalid JWT structure
    /// - mismatched hash (the user changed their privilege)
    /// - serialization errors to the desired structured type
    /// - unexpected data in the JSON
    /// - failed to parse JSON
    /// - expiry date is not included
    Unauthorized,
    /// The user is authorized with the provided data.
    /// The data is guaranteed to be what you authorized.
    Authorized(AuthData<T>),
}

enum IpBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}
impl From<IpAddr> for IpBytes {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip.octets()),
            IpAddr::V6(ip) => Self::V6(ip.octets()),
        }
    }
}
impl AsRef<[u8]> for IpBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::V4(addr) => addr,
            Self::V6(addr) => addr,
        }
    }
}

trait Validate {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()>;
}
#[cfg(any(feature = "rsa", feature = "ecdsa"))]
impl Validate for ValidationAlgo {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        (&self).validate(data, signature, ip)
    }
}
#[cfg(any(feature = "rsa", feature = "ecdsa"))]
impl<'a> Validate for &'a ValidationAlgo {
    #[allow(unused_variables)] // cfg
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        match *self {
            #[cfg(feature = "rsa")]
            ValidationAlgo::RSASha256 { public_key } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                if let Some(ip) = ip {
                    hasher.update(IpBytes::from(ip).as_ref());
                }
                let hash = hasher.finalize();
                public_key
                    .verify(
                        rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>(),
                        &hash,
                        signature,
                    )
                    .map_err(|_| ())
            }
            #[cfg(feature = "ecdsa")]
            ValidationAlgo::EcdsaP256 { public_key } => {
                let sig = p256::ecdsa::Signature::try_from(signature).map_err(|_| ())?;
                public_key.verify(data, &sig).map_err(|_| ())
            }
        }
    }
}
impl Validate for ComputedAlgo {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        (&self).validate(data, signature, ip)
    }
}
impl<'a> Validate for &'a ComputedAlgo {
    #[allow(unused_variables)] // cfg
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        match *self {
            #[cfg(feature = "rsa")]
            ComputedAlgo::RSASha256 { public_key, .. } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                if let Some(ip) = ip {
                    hasher.update(IpBytes::from(ip).as_ref());
                }
                let hash = hasher.finalize();
                public_key
                    .verify(
                        rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>(),
                        &hash,
                        signature,
                    )
                    .map_err(|_| ())
            }
            #[cfg(feature = "hmac")]
            ComputedAlgo::HmacSha256 { secret, .. } => {
                // Hmac can take a key of any length
                let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
                hmac.update(data);
                if let Some(ip) = ip {
                    hmac.update(IpBytes::from(ip).as_ref());
                }
                let hash = hmac.finalize().into_bytes();
                if &*hash == signature {
                    Ok(())
                } else {
                    Err(())
                }
            }
            #[cfg(feature = "ecdsa")]
            ComputedAlgo::EcdsaP256 { public_key, .. } => {
                let sig = p256::ecdsa::Signature::try_from(signature).map_err(|_| ())?;
                if let Some(ip) = ip {
                    let mut buf = Vec::with_capacity(data.len() + 16);
                    buf.extend_from_slice(data);
                    buf.extend_from_slice(IpBytes::from(ip).as_ref());
                    public_key.verify(&buf, &sig).map_err(|_| ())
                } else {
                    public_key.verify(data, &sig).map_err(|_| ())
                }
            }
        }
    }
}
impl Validate for Mode {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        (&self).validate(data, signature, ip)
    }
}
impl<'a> Validate for &'a Mode {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        match *self {
            Mode::Sign(s) => s.validate(data, signature, ip),
            #[cfg(any(feature = "rsa", feature = "ecdsa"))]
            Mode::Validate(v) => v.validate(data, signature, ip),
        }
    }
}
#[cfg(all(test, feature = "ecdsa"))]
impl<'a> Validate for &'a [u8] {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        let public_key = ecdsa_sk(self).verifying_key();
        let sig = p256::ecdsa::Signature::try_from(signature).map_err(|_| ())?;
        if let Some(ip) = ip {
            let mut buf = Vec::with_capacity(data.len() + 16);
            buf.extend_from_slice(data);
            buf.extend_from_slice(IpBytes::from(ip).as_ref());
            public_key.verify(&buf, &sig).map_err(|_| ())
        } else {
            public_key.verify(data, &sig).map_err(|_| ())
        }
    }
}
#[cfg(all(test, feature = "ecdsa"))]
impl<'a, const LEN: usize> Validate for &'a [u8; LEN] {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        (&self[..]).validate(data, signature, ip)
    }
}

macro_rules! or_unauthorized {
    ($v: expr) => {
        if let Some(v) = $v {
            v
        } else {
            return Self::Unauthorized;
        }
    };
}
/// Returns [`None`] if `s` is not a valid JWT for `secret` and the current time.
#[cfg(feature = "structured")]
fn validate(s: &str, validate: impl Validate, ip: Option<IpAddr>) -> Option<serde_json::Value> {
    let parts = s.splitn(3, '.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let signature_input = &s[..parts[0].len() + 1 + parts[1].len()];
    let remote_signature = base64::decode_engine(parts[2], &BASE64_ENGINE).ok()?;
    if validate
        .validate(signature_input.as_bytes(), &remote_signature, ip)
        .is_err()
    {
        return None;
    }
    let payload = base64::decode_engine(parts[1], &BASE64_ENGINE)
        .ok()
        .and_then(|p| String::from_utf8(p).ok())?;
    let mut payload_value: serde_json::Value = payload.parse().ok()?;
    let payload = payload_value.as_object_mut()?;
    let exp = payload.get("exp").and_then(|v| v.as_u64())?;
    let iat = payload.get("iat").and_then(|v| v.as_u64())?;
    let now = seconds_since_epoch();
    if exp < now || iat > now {
        return None;
    }
    Some(payload_value)
}
/// Returns [`None`] if `s` is not a valid JWT for `secret` and the current time.
#[cfg(not(feature = "structured"))]
fn validate(s: &str, validate: impl Validate, ip: Option<IpAddr>) -> Option<JwtData> {
    let parts = s.splitn(3, '.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let signature_input = &s[..parts[0].len() + 1 + parts[1].len()];
    let remote_signature = base64::decode_engine(parts[2], &BASE64_ENGINE).ok()?;
    if validate
        .validate(signature_input.as_bytes(), &remote_signature, ip)
        .is_err()
    {
        return None;
    }
    let payload = base64::decode_engine(parts[1], &BASE64_ENGINE)
        .ok()
        .and_then(|p| String::from_utf8(p).ok())?;
    let mut entries = payload.strip_prefix('{')?.strip_suffix('}')?.trim();
    let mut data = JwtData::default();
    let mut last_missed_comma = false;
    loop {
        entries = if let Some(s) = entries.strip_prefix(',') {
            s
        } else {
            if last_missed_comma {
                break;
            }
            last_missed_comma = true;
            entries
        };
        entries = entries.strip_prefix('"')?;
        let (key, value) = unescape::unescape_until_quote(entries).and_then(|(name, pos)| {
            // +1 for the quote
            entries = entries[pos + 1..].trim_start();
            entries = entries.strip_prefix(',')?.trim_start();
            entries = entries.strip_prefix('"')?.trim_start();
            unescape::unescape_until_quote(entries).map(|(value, pos)| {
                entries = &entries[pos + 1..];
                (name, value)
            })
        })?;
        match key.as_str() {
            "iat" => data.iat = value.parse().ok()?,
            "exp" => data.exp = value.parse().ok()?,
            "num" => data.num = Some(value.parse().ok()?),
            "text" => data.text = Some(value),
            _ => log::warn!("Tried to parse JWT with unrecognized field: {key:?}"),
        }
    }
    let now = seconds_since_epoch();
    if (data.exp as u64) < now || (data.iat as u64) > now {
        return None;
    }
    Some(data)
}
#[derive(Debug, Default)]
struct JwtData {
    pub iat: f64,
    pub exp: f64,
    pub num: Option<f64>,
    pub text: Option<String>,
}
#[cfg(feature = "structured")]
impl<T: Serialize + DeserializeOwned> Validation<T> {
    #[allow(clippy::match_result_ok)] // macro
    fn from_jwt(s: &str, validator: impl Validate, ip: Option<IpAddr>) -> Self {
        let mut payload = or_unauthorized!(validate(s, validator, ip));
        let payload = payload
            .as_object_mut()
            .expect("we just did this conversion in the function above");
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
                let serialize_v = payload.get("__deserialize_v").map_or(false, |v| v == true);
                let v = if serialize_v {
                    or_unauthorized!(payload.get_mut("v")).take()
                } else {
                    payload.remove("iat");
                    payload.remove("exp");
                    payload.remove("__variant");
                    payload.remove("__deserialize_v");
                    serde_json::Value::Object(std::mem::take(payload))
                };
                AuthData::Structured(or_unauthorized!(serde_json::from_value(v).ok()))
            }
            "e" => AuthData::None,
            _ => return Self::Unauthorized,
        };
        Self::Authorized(data)
    }
}
#[cfg(not(feature = "structured"))]
impl<T: Serialize + DeserializeOwned> Validation<T> {
    #[allow(clippy::match_result_ok)] // macro
    fn from_jwt(s: &str, validator: impl Validate, ip: Option<IpAddr>) -> Self {
        let data = or_unauthorized!(validate(s, validator, ip));
        let data = match (data.num, data.text) {
            (Some(num), Some(text)) => AuthData::TextNumber(text, num),
            (Some(num), None) => AuthData::Number(num),
            (None, Some(text)) => AuthData::Text(text),
            (None, None) => AuthData::None,
        };
        Self::Authorized(data)
    }
}

#[derive(Debug)]
struct CredentialsStore<'a> {
    pub username: &'a str,
    pub password: &'a str,
}
impl<'a> CredentialsStore<'a> {
    pub fn new(username: impl Into<&'a str>, password: impl Into<&'a str>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
    pub fn to_bytes(&self, ip: Option<IpAddr>) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            1 + ip.map_or(0, |ip| if ip.is_ipv4() { 4 } else { 16 })
                + 8
                + self.username.len()
                + self.password.len(),
        );
        if let Some(ip) = ip {
            let ident = if ip.is_ipv4() { 0x1 } else { 0x2 };
            v.push(ident);
            v.extend_from_slice(IpBytes::from(ip).as_ref());
        } else {
            v.push(0)
        }
        let len = (self.username.len() as u64).to_le_bytes();
        v.extend_from_slice(&len);
        v.extend_from_slice(self.username.as_bytes());
        v.extend_from_slice(self.password.as_bytes());
        v
    }
    pub fn from_bytes(mut b: &'a [u8]) -> Result<(Self, Option<&'a [u8]>), ()> {
        (|| {
            let mut take_n = |n: usize| {
                let v = b.get(..n)?;
                b = &b[n..];
                Some(v)
            };
            let ip_type = take_n(1)?;
            let ip = match ip_type[0] {
                0x0 => None,
                0x1 => Some(take_n(4)?),
                0x2 => Some(take_n(16)?),
                _ => return None,
            };
            let len = take_n(8)?;
            let mut array = [0; 8];
            array.copy_from_slice(len);
            let len = u64::from_le_bytes(array);
            let username = std::str::from_utf8(take_n(len as usize)?).ok()?;
            let password = std::str::from_utf8(b).ok()?;
            Some((Self { username, password }, ip))
        })()
        .ok_or(())
    }
}

/// The algorithm used when running in validation mode.
///
/// `hmac` isn't available, as that doesn't use asymmetric cryptography.
#[derive(Debug)]
#[cfg(any(feature = "rsa", feature = "ecdsa"))]
pub enum ValidationAlgo {
    /// Validate RSA-signed JWTs.
    #[cfg(feature = "rsa")]
    RSASha256 {
        /// The RSA public key.
        public_key: rsa::RsaPublicKey,
    },
    /// Validate ecdsa-signed JWTs.
    #[cfg(feature = "ecdsa")]
    EcdsaP256 {
        /// The ecdsa public key.
        public_key: p256::ecdsa::VerifyingKey,
    },
}
#[derive(Debug)]
enum ComputedAlgo {
    #[cfg(feature = "hmac")]
    HmacSha256 {
        secret: Vec<u8>,
        credentials_key: chacha20::cipher::Key<chacha20::ChaCha12>,
    },
    #[cfg(feature = "rsa")]
    RSASha256 {
        private_key: Box<rsa::RsaPrivateKey>,
        public_key: Box<rsa::RsaPublicKey>,
    },
    #[cfg(feature = "ecdsa")]
    EcdsaP256 {
        private_key: p256::ecdsa::SigningKey,
        public_key: p256::ecdsa::VerifyingKey,
        credentials_key: chacha20::cipher::Key<chacha20::ChaCha12>,
    },
}
impl ComputedAlgo {
    fn encrypt(&self, b: &[u8]) -> Vec<u8> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RSASha256 {
                private_key: _,
                public_key,
            } => public_key
                .encrypt(
                    &mut rand::thread_rng(),
                    rsa::PaddingScheme::PKCS1v15Encrypt,
                    b,
                )
                .expect("failed to encrypt with RSA"),
            #[cfg(feature = "hmac")]
            Self::HmacSha256 {
                credentials_key, ..
            } => {
                let mut nonce = [0_u8; 12];
                rand::thread_rng().fill(&mut nonce);
                let mut cipher = chacha20::ChaCha12::new(credentials_key, &nonce.into());
                let mut vec = Vec::with_capacity(12 + b.len());
                vec.extend_from_slice(&nonce);
                vec.extend_from_slice(b);
                cipher.apply_keystream(&mut vec[12..]);
                vec
            }
            #[cfg(feature = "ecdsa")]
            Self::EcdsaP256 {
                credentials_key, ..
            } => {
                let mut nonce = [0_u8; 12];
                rand::thread_rng().fill(&mut nonce);
                let mut cipher = chacha20::ChaCha12::new(credentials_key, &nonce.into());
                let mut vec = Vec::with_capacity(12 + b.len());
                vec.extend_from_slice(&nonce);
                vec.extend_from_slice(b);
                cipher.apply_keystream(&mut vec[12..]);
                vec
            }
        }
    }
    #[allow(clippy::match_same_arms)] // cfg
    fn decrypt<'a>(&self, b: &'a mut [u8]) -> Option<Cow<'a, [u8]>> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RSASha256 {
                private_key,
                public_key: _,
            } => private_key
                .decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, b)
                .map(Cow::Owned)
                .ok(),
            #[cfg(feature = "hmac")]
            Self::HmacSha256 {
                credentials_key, ..
            } => {
                let mut nonce = [0_u8; 12];
                nonce.copy_from_slice(b.get(..12)?);
                let mut cipher = chacha20::ChaCha12::new(credentials_key, &nonce.into());
                cipher.apply_keystream(&mut b[12..]);
                Some(Cow::Borrowed(&b[12..]))
            }

            #[cfg(feature = "ecdsa")]
            Self::EcdsaP256 {
                credentials_key, ..
            } => {
                let mut nonce = [0_u8; 12];
                nonce.copy_from_slice(b.get(..12)?);
                let mut cipher = chacha20::ChaCha12::new(credentials_key, &nonce.into());
                cipher.apply_keystream(&mut b[12..]);
                Some(Cow::Borrowed(&b[12..]))
            }
        }
    }
}
impl From<CryptoAlgo> for ComputedAlgo {
    fn from(alg: CryptoAlgo) -> Self {
        match alg {
            #[cfg(feature = "hmac")]
            CryptoAlgo::HmacSha256 { secret } => Self::HmacSha256 {
                credentials_key: {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(&secret);
                    hasher.finalize()
                },
                secret,
            },
            #[cfg(feature = "rsa")]
            CryptoAlgo::RSASha256 { private_key } => Self::RSASha256 {
                public_key: Box::new(rsa::RsaPublicKey::from(&private_key)),
                private_key: Box::new(private_key),
            },
            #[cfg(feature = "ecdsa")]
            CryptoAlgo::EcdsaP256 { secret } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(&secret);
                let hash = hasher.finalize();
                let private_key = p256::ecdsa::SigningKey::from_bytes(&hash)
                    .expect("failed to construct a Ecdsa key");
                Self::EcdsaP256 {
                    public_key: private_key.verifying_key(),
                    private_key,
                    credentials_key: hash,
                }
            }
        }
    }
}
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // this is just the user-facing algo selector, it quickly gets
// converted to a smaller enum
/// The cryptographic algorithm to use to ensure the authenticity of the data.
///
/// I recommend `ecdsa`, as it's the fastest and has support for validation mode.
/// `hmac` is the most common algorithm used on the web right now, so it could be useful for
/// compatibility.
pub enum CryptoAlgo {
    /// Sign using Hmac.
    #[cfg(feature = "hmac")]
    HmacSha256 {
        /// The Hmac secret to sign with.
        secret: Vec<u8>,
    },
    /// Sign using RSA.
    #[cfg(feature = "rsa")]
    RSASha256 {
        /// The RSA public key to sign with.
        private_key: rsa::RsaPrivateKey,
    },
    #[cfg(feature = "ecdsa")]
    /// Sign using Ecdsa.
    ///
    /// This is the recommended algo, as it allows verification without the secret (see
    /// [`ecdsa_sk`] for more details on how to share the verification key) (RSA can also do this), is 1000x faster than
    /// RSA, and takes up 70% less space than RSA. It's also takes any byte array as a secret.
    EcdsaP256 {
        /// The Ecdsa secret to sign with.
        ///
        /// Does currently not correspond to PKCS#8 certificates.
        /// This can be anything you'd like.
        secret: Vec<u8>,
    },
}
/// Get the signing key for `secret`.
///
/// # Sharing verifying key
///
/// Get the verifying key by using the `verifying_key` method on the returned value.
/// You can then use the methods [`to_encoded_point`](https://docs.rs/ecdsa/0.14.1/ecdsa/struct.VerifyingKey.html#method.to_encoded_point)
/// and [`from_encoded_point`](https://docs.rs/ecdsa/0.14.1/ecdsa/struct.VerifyingKey.html#method.from_encoded_point)
/// (or any similar methods, like the Serialize serde implementation of the struct)
/// to serialize and share the verifying key, and then constructing [`ValidationAlgo::EcdsaP256`]
/// with that key.
#[cfg(feature = "ecdsa")]
pub fn ecdsa_sk(secret: &[u8]) -> p256::ecdsa::SigningKey {
    let mut hasher = sha2::Sha256::new();
    hasher.update(secret);
    let hash = hasher.finalize();
    p256::ecdsa::SigningKey::from_bytes(&hash).expect("failed to construct a Ecdsa key")
}
#[derive(Debug, Clone)]
enum Mode {
    Sign(Arc<ComputedAlgo>),
    #[cfg(any(feature = "rsa", feature = "ecdsa"))]
    Validate(Arc<ValidationAlgo>),
}
/// You can use multiple authentication setups on a single site, but make sure that the respective
/// [`Builder::with_cookie_path`]s do not overlap. You MUST set `with_cookie_path` to use more than
/// 1 auth setup.
#[derive(Debug, Default)]
pub struct Builder {
    auth_page_name: Option<String>,
    jwt_page_name_extension: String,
    samesite_strict: Option<bool>,
    httponly: Option<bool>,
    relogin_on_ip_change: Option<bool>,
    jwt_cookie_name: Option<String>,
    credentials_cookie_name: Option<String>,
    show_auth_page_when_unauthorized: Option<String>,
    jwt_cookie_validity: Option<Duration>,
    credentials_cookie_validity: Option<Duration>,
    cookie_path: Option<String>,
    read_x_real_ip_header: Option<bool>,
}
impl Builder {
    /// Create a new builder.
    /// Use [`Self::build`] or [`Self::build_validate`] to get a [`Config`].
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the URL endpoint where your frontend authenticates to.
    pub fn with_auth_page_name(mut self, auth_page_name: impl Into<String>) -> Self {
        let s = auth_page_name.into();
        let jwt_page_name_extension = s.replace(
            |c: char| {
                u8::try_from(c as u32).map_or(true, |b| {
                    !kvarn::prelude::utils::is_valid_header_value_byte(b)
                })
            },
            "-",
        );
        self.jwt_page_name_extension = jwt_page_name_extension;
        self.auth_page_name = Some(s);
        self
    }
    /// Decrease security and protection against CSRF but allow users to follow links to
    /// auth-protected pages from other sites.
    /// This sets the `SameSite` property of the cookie to `lax`.
    pub fn with_lax_samesite(mut self) -> Self {
        self.samesite_strict = Some(false);
        self
    }
    /// Decrease security and protection against XSS but allow the JavaScript to read the cookie,
    /// which allows the client to get the logged in status.
    /// **It's highly recommended to enable [`Builder::with_force_relog_on_ip_change`] when this is
    /// enabled, as that negates any credential theft, as the credentials are bound to an IP.**
    ///
    /// This disables the usual setting of the `HttpOnly` cookie property.
    /// This does not affect the credentials cookie. That will never be served without `HttpOnly`.
    pub fn with_relaxed_httponly(mut self) -> Self {
        self.httponly = Some(false);
        self
    }
    /// Forces relogging by the user when they change IPs. This can protect users from getting
    /// their cookies scraped by malware, as the authentication is IP dependant.
    pub fn with_force_relog_on_ip_change(mut self) -> Self {
        self.samesite_strict = Some(false);
        self
    }
    /// Sets the name of the JWT cookie. This is the cookie that authorizes the user.
    ///
    /// # Panics
    ///
    /// Panics if `jwt_cookie_name` contains illegal bytes for a header value.
    pub fn with_jwt_cookie_name(mut self, jwt_cookie_name: impl Into<String>) -> Self {
        let s = jwt_cookie_name.into();
        if !s
            .bytes()
            .all(kvarn::prelude::utils::is_valid_header_value_byte)
        {
            panic!("jwt_cookie_name contains illegal bytes")
        }
        self.jwt_cookie_name = Some(s);
        self
    }
    /// Sets the name of the credentials cookie. This is the cookie that stores the user's
    /// credentials to allow renewal of the JWT cookie without requiring the user to input
    /// credentials. It is encrypted with the server's PK.
    ///
    /// # Panics
    ///
    /// Panics if `credentials_cookie_name` contains illegal bytes for a header value.
    pub fn with_credentials_cookie_name(
        mut self,
        credentials_cookie_name: impl Into<String>,
    ) -> Self {
        let s = credentials_cookie_name.into();
        if !s
            .bytes()
            .all(kvarn::prelude::utils::is_valid_header_value_byte)
        {
            panic!("jwt_cookie_name contains illegal bytes")
        }
        self.credentials_cookie_name = Some(s);
        self
    }
    /// Sets the path of all the cookies. Set this to avoid slowing down other pages on your
    /// server, as Kvarn will try to renew the JWT on every page by default.
    /// By setting this to only your protected pages, the JWT cookie is only sent there.
    /// Kvarn thinks the user isn't logged in on other pages, reducing the work it has to do.
    ///
    /// This is also useful if you want to have multiple authentication systems on a single host.
    ///
    /// # Panics
    ///
    /// Panics if `cookie_path` contains illegal bytes for a header value.
    pub fn with_cookie_path(mut self, cookie_path: impl Into<String>) -> Self {
        let s = cookie_path.into();
        if !s
            .bytes()
            .all(kvarn::prelude::utils::is_valid_header_value_byte)
        {
            panic!("cookie_path contains illegal bytes")
        }
        self.cookie_path = Some(s);
        self
    }
    /// Show this page when the user isn't logged in.
    ///
    /// This guarantees nobody can view any pages which starts with [`Self::with_cookie_path`]
    /// without being logged in.
    ///
    /// Please also specify [`Self::with_cookie_path`], as else `auth_page` will be shown instead
    /// of every other page when not logged in.
    ///
    /// # Panics
    ///
    /// Panics if `show_auth_page_when_unauthorized` cannot be converted into a [`kvarn::prelude::HeaderValue`].
    /// [`kvarn::prelude::Uri`].
    pub fn with_show_auth_page_when_unauthorized(mut self, auth_page: impl Into<String>) -> Self {
        let s = auth_page.into();
        if kvarn::prelude::Uri::try_from(&s).is_err() {
            panic!("show_auth_page_when_unauthorized contains illegal bytes")
        }
        self.show_auth_page_when_unauthorized = Some(s);
        self
    }
    /// Makes all JWTs valid for the duration of `valid_for`.
    /// After that, the JWT is automatically refreshed from the securely stored credentials.
    pub fn with_jwt_validity(mut self, valid_for: Duration) -> Self {
        self.jwt_cookie_validity = Some(valid_for);
        self
    }
    /// Makes the credentials cookie valid for the duration of `valid_for`.
    /// If this is a year, the user doesn't have to relog in a year.
    pub fn with_credentials_cookie_validity(mut self, valid_for: Duration) -> Self {
        self.credentials_cookie_validity = Some(valid_for);
        self
    }
    /// Reads the IP from the header `x-real-ip` instead of the connection IP.
    /// This is useful if the authentication is behind a reverse proxy.
    pub fn with_ip_from_header(mut self) -> Self {
        self.read_x_real_ip_header = Some(true);
        self
    }

    fn _build<
        T: Serialize + DeserializeOwned + Send + Sync,
        F: Fn(&str, &str, SocketAddr, &kvarn::FatRequest) -> Fut + Send + Sync,
        Fut: Future<Output = Validation<T>> + Send + Sync,
    >(
        self,
        is_allowed: F,
        mode: Mode,
    ) -> Arc<Config<T, F, Fut>> {
        let httponly = self.httponly.unwrap_or(true);
        let relogin_on_ip_change = self.relogin_on_ip_change.unwrap_or(false);
        if !httponly && !relogin_on_ip_change {
            log::warn!("HttpOnly not set and relogin_on_ip_change not set. In case of XSS attacks, the credentials could be leaked");
        }
        let c = Config {
            mode,
            is_allowed: Arc::new(is_allowed),
            jwt_page_name_extension: self.jwt_page_name_extension,
            auth_page_name: self.auth_page_name.unwrap_or_else(|| "/auth".into()),
            samesite_strict: self.samesite_strict.unwrap_or(true),
            httponly,
            relogin_on_ip_change,
            jwt_cookie_name: self.jwt_cookie_name.unwrap_or_else(|| "auth-jwt".into()),
            credentials_cookie_name: self
                .credentials_cookie_name
                .unwrap_or_else(|| "auth-credentials".into()),
            show_auth_page_when_unauthorized: self.show_auth_page_when_unauthorized,
            jwt_validity: self
                .jwt_cookie_validity
                .unwrap_or_else(|| Duration::from_secs(60 * 60)),
            credentials_cookie_validity: self
                .credentials_cookie_validity
                .unwrap_or_else(|| Duration::from_secs(60 * 60 * 24 * 365)),
            cookie_path: self.cookie_path.unwrap_or_else(|| String::from("/")),
            read_x_real_ip_header: self.read_x_real_ip_header.unwrap_or(false),
        };
        Arc::new(c)
    }
    /// Build these settings into a [`Config`], which you then use for validation.
    pub fn build<
        T: Serialize + DeserializeOwned + Send + Sync,
        F: Fn(&str, &str, SocketAddr, &kvarn::FatRequest) -> Fut + Send + Sync,
        Fut: Future<Output = Validation<T>> + Send + Sync,
    >(
        self,
        is_allowed: F,
        pk: CryptoAlgo,
    ) -> Arc<Config<T, F, Fut>> {
        self._build(is_allowed, Mode::Sign(Arc::new(pk.into())))
    }
    /// Build these settings into a [`Config`] built for validation.
    /// See the [module-level documentation](self) for more info.
    #[allow(clippy::type_complexity)]
    #[cfg(any(feature = "rsa", feature = "ecdsa"))]
    pub fn build_validate(
        self,
        validation_key: ValidationAlgo,
    ) -> Arc<
        Config<
            (),
            fn(&str, &str, SocketAddr, &kvarn::FatRequest) -> core::future::Pending<Validation<()>>,
            core::future::Pending<Validation<()>>,
        >,
    > {
        fn _placeholder(
            _user: &str,
            _password: &str,
            _addr: SocketAddr,
            _req: &kvarn::FatRequest,
        ) -> core::future::Pending<Validation<()>> {
            core::future::pending()
        }
        let placeholder: fn(
            &str,
            &str,
            SocketAddr,
            &kvarn::FatRequest,
        ) -> core::future::Pending<Validation<()>> = _placeholder;
        self._build(placeholder, Mode::Validate(Arc::new(validation_key)))
    }
}
/// The type of [`Config::login_status`]. Use this in the type bounds of Kvarn's extensions.
pub type LoginStatusClosure<T> = Arc<
    dyn Fn(&kvarn::FatRequest, kvarn::prelude::SocketAddr) -> Validation<T> + Send + Sync + 'static,
>;
/// The configured authentication. This can be attached to a Kvarn host using the [`Self::mount`]
/// method. You can call [`Self::login_status`] to get a function to use in your extensions to
/// check for authentication status.
pub struct Config<
    T: Serialize + DeserializeOwned + Send + Sync,
    F: Fn(&str, &str, SocketAddr, &kvarn::FatRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Validation<T>> + Send + Sync,
> {
    mode: Mode,
    is_allowed: Arc<F>,
    auth_page_name: String,
    jwt_page_name_extension: String,
    samesite_strict: bool,
    httponly: bool,
    relogin_on_ip_change: bool,
    jwt_cookie_name: String,
    credentials_cookie_name: String,
    show_auth_page_when_unauthorized: Option<String>,
    jwt_validity: Duration,
    credentials_cookie_validity: Duration,
    cookie_path: String,
    read_x_real_ip_header: bool,
}
impl<
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: Fn(&str, &str, SocketAddr, &kvarn::FatRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Validation<T>> + Send + Sync + 'static,
    > Config<T, F, Fut>
{
    fn ip(&self, ip: IpAddr) -> Option<IpAddr> {
        if self.relogin_on_ip_change {
            Some(ip)
        } else {
            None
        }
    }
    /// Returns a closure that can be sent to a Kvarn extension to extract the data from the user's
    /// JWT and validating the authenticity of the client.
    ///
    /// This makes it easier to cross the boundary of the Kvarn extension (using the `move ||`
    /// semantics). See [`LoginStatusClosure`].
    ///
    /// If the closure returns [`Validation::Unauthorized`], redirect the user to your login page
    /// ([`Builder::with_auth_page_name`]).
    pub fn login_status(&self) -> LoginStatusClosure<T> {
        let jwt_cookie_name = self.jwt_cookie_name.clone();
        let mode = self.mode.clone();
        let relogin_on_ip_change = self.relogin_on_ip_change;
        Arc::new(
            move |req: &kvarn::FatRequest, addr: kvarn::prelude::SocketAddr| {
                let ip = if relogin_on_ip_change {
                    Some(addr.ip())
                } else {
                    None
                };
                let cookie = get_cookie(req, &jwt_cookie_name);
                let cookie = if let Some(d) = cookie {
                    extract_cookie_value(d)
                } else {
                    return Validation::Unauthorized;
                };
                Validation::from_jwt(cookie, &mode, ip)
            },
        )
    }
    /// Create an API route at [`Builder::with_auth_page_name`] and make the JWT token automatically
    /// refresh.
    ///
    /// To log in, use JavaScript's `fetch` with method POST or PUT to the `auth_page_name`,
    /// with the username length on the first lines, then on the second line,
    /// the username concatenated with the password without any space.
    /// The rest of the body (after username length) is considered to be the password (it can
    /// contains newlines).
    ///
    /// To log out, `fetch` DELETE to `auth_page_name`.
    ///
    /// # Panics
    ///
    /// Panics if this config was created using [`Builder::build_validate`].
    #[allow(clippy::match_result_ok)]
    pub fn mount(self: &Arc<Self>, extensions: &mut kvarn::Extensions) {
        use kvarn::prelude::*;

        #[derive(Debug, PartialEq, Eq)]
        enum AuthState {
            Authorized,
            /// Only the JWT cookie is definitely invalid. We will try to refresh the JWT
            Incorrect,
            /// Both the JWT cookie and the credentials cookie are invalid
            Missing,
        }
        type JwtCreation = Arc<
            dyn Fn(
                    &str,
                    &str,
                    SocketAddr,
                    &FatRequest,
                ) -> extensions::RetSyncFut<'static, Option<(String, String)>>
                + Send
                + Sync
                + 'static,
        >;

        let signing_algo = match &self.mode {
            Mode::Sign(s) => Arc::clone(s),
            #[cfg(any(feature = "rsa", feature = "ecdsa"))]
            Mode::Validate(_v) => panic!("Called mount on a config acting as a validator."),
        };

        let jwt_refresh_page =
            format!("/./jwt-auth-refresh-token/{}", self.jwt_page_name_extension);

        let config = self.clone();
        let show_auth_page_when_unauthorized = config.show_auth_page_when_unauthorized.clone();
        let auth_page_name = config.auth_page_name.clone();
        let cookie_path = config.cookie_path.clone();
        let prime_signing_algo = signing_algo.clone();
        let validate = move |req: &FatRequest, addr: SocketAddr| {
            let jwt_cookie = get_cookie(req, &config.jwt_cookie_name);
            let credentials_cookie = get_cookie(req, &config.credentials_cookie_name);
            match (jwt_cookie, credentials_cookie) {
                (None, None) => AuthState::Missing,
                (None, _) => AuthState::Incorrect,
                (Some(jwt), _) => {
                    let value = extract_cookie_value(jwt);
                    let validation = validate(value, &*prime_signing_algo, config.ip(addr.ip()));
                    if validation.is_some() {
                        AuthState::Authorized
                    } else {
                        AuthState::Incorrect
                    }
                }
            }
        };
        type Validate = Arc<dyn Fn(&FatRequest, SocketAddr) -> AuthState + Send + Sync>;
        let validate: Validate = Arc::new(validate);
        let prime_jwt_refresh_page = Uri::try_from(&jwt_refresh_page)
            .expect("we converted all non-header safe values to hyphens");
        let x_real_ip = self.read_x_real_ip_header;
        fn check_addr(
            req: &FatRequest,
            addr: SocketAddr,
            x_real_ip: bool,
        ) -> Result<SocketAddr, ()> {
            if x_real_ip {
                if let Some(addr) = req
                    .headers()
                    .get("x-real-ip")
                    .and_then(|header| header.to_str().ok())
                    .and_then(|header| header.parse::<IpAddr>().ok())
                    .map(|ip| SocketAddr::new(ip, 0))
                {
                    Ok(addr)
                } else {
                    Err(())
                }
            } else {
                Ok(addr)
            }
        }
        async fn resolve_addr(
            req: &FatRequest,
            addr: SocketAddr,
            x_real_ip: bool,
            host: &Host,
        ) -> Result<SocketAddr, FatResponse> {
            if let Ok(addr) = check_addr(req, addr, x_real_ip) {
                Ok(addr)
            } else {
                Err(default_error_response(StatusCode::BAD_REQUEST, host, Some("the authentication extected to be behind a reverse proxy and to get the `x-real-ip` header.")).await)
            }
        }

        if show_auth_page_when_unauthorized.is_some() {
            let cookie_path = cookie_path.clone();
            let validate = Arc::clone(&validate);
            extensions.add_package(
                package!(
                    response,
                    req,
                    _host,
                    addr,
                    move |cookie_path: String, validate: Validate, x_real_ip: bool| {
                        let addr = match check_addr(req, addr, *x_real_ip) {
                            Ok(a) => a,
                            Err(()) => {
                                // same as Incorrect
                                response
                                    .headers_mut()
                                    .insert("client-cache", HeaderValue::from_static("no-cache"));
                                return;
                            }
                        };
                        if req.uri().path().starts_with(cookie_path) {
                            let state: AuthState = validate(req, addr);
                            match state {
                                AuthState::Missing | AuthState::Incorrect => {
                                    response.headers_mut().insert(
                                        "client-cache",
                                        HeaderValue::from_static("no-cache"),
                                    );
                                }
                                AuthState::Authorized => {}
                            }
                        }
                    }
                ),
                Id::new(-7, "don't cache authentication website on client"),
            )
        }

        extensions.add_prime(
            prime!(
                req,
                _host,
                addr,
                move |validate: Validate,
                      show_auth_page_when_unauthorized: Option<String>,
                      auth_page_name: String,
                      cookie_path: String,
                      prime_jwt_refresh_page: Uri,
                      x_real_ip: bool| {
                    if !req.uri().path().starts_with(cookie_path)
                        || req.uri().path() == auth_page_name
                    {
                        return None;
                    }
                    let addr = match check_addr(req, addr, *x_real_ip) {
                        Ok(a) => a,
                        // same as Incorrect
                        Err(()) => return Some(prime_jwt_refresh_page.clone()),
                    };
                    let state: AuthState = validate(req, addr);
                    match state {
                        AuthState::Authorized => None,
                        AuthState::Missing
                            if req.uri().path().starts_with(cookie_path)
                                && req.uri().path() != auth_page_name =>
                        {
                            show_auth_page_when_unauthorized.as_ref().map(|path| {
                                let uri = req.uri();
                                {
                                    let scheme = uri.scheme().map_or("", uri::Scheme::as_str);
                                    let authority =
                                        uri.authority().map_or("", uri::Authority::as_str);
                                    let bytes = build_bytes!(
                                        scheme.as_bytes(),
                                        if uri.scheme().is_some() {
                                            &b"://"[..]
                                        } else {
                                            &[]
                                        },
                                        authority.as_bytes(),
                                        path.as_bytes()
                                    );
                                    Uri::from_maybe_shared(bytes)
                                        .expect("invalid bytes in auth path")
                                }
                            })
                        }
                        AuthState::Missing => None,
                        AuthState::Incorrect => Some(prime_jwt_refresh_page.clone()),
                    }
                }
            ),
            extensions::Id::new(8432, "auth JWT renewal").no_override(),
        );
        let refresh_signing_algo = signing_algo.clone();
        // `/./jwt-auth-refresh-token` to read credentials token and write jwt token (remove
        // credentials if invalid), then 303 to the current page
        let credentials_cookie_name = self.credentials_cookie_name.clone();
        let jwt_cookie_name = self.jwt_cookie_name.clone();
        let config = self.clone();
        let jwt_signing_algo = signing_algo.clone();
        let jwt_from_credentials: JwtCreation = Arc::new(
            move |username: &str, password: &str, addr: SocketAddr, req: &FatRequest| {
                let signing_algo = jwt_signing_algo.clone();
                let config = config.clone();
                let addr = match check_addr(req, addr, x_real_ip) {
                    Ok(a) => a,
                    // same as Incorrect
                    Err(()) => return Box::pin(async { None }),
                };
                let fut = (config.is_allowed)(username, password, addr, req).then(
                    move |data| async move {
                        match data {
                            Validation::Unauthorized => None,
                            Validation::Authorized(data) => {
                                let jwt = data.into_jwt_with_default_header(
                                    &signing_algo,
                                    config.jwt_validity.as_secs(),
                                    config.ip(addr.ip()),
                                );
                                let header_value = format!(
                                    "{}={}; Secure{}; SameSite={}; Max-Age={}; Path={}",
                                    config.jwt_cookie_name,
                                    jwt,
                                    if config.httponly { "; HttpOnly" } else { "" },
                                    if config.samesite_strict {
                                        "Strict"
                                    } else {
                                        "Lax"
                                    },
                                    config.jwt_validity.as_secs(),
                                    config.cookie_path,
                                );
                                Some((header_value, jwt))
                            }
                        }
                    },
                );
                Box::pin(fut)
            },
        );

        let auth_jwt_from_credentials = Arc::clone(&jwt_from_credentials);
        let cookie_path = self.cookie_path.clone();
        let prepare_extension = prepare!(
            req,
            host,
            _,
            addr,
            move |credentials_cookie_name: String,
                  jwt_cookie_name: String,
                  cookie_path: String,
                  refresh_signing_algo: Arc<ComputedAlgo>,
                  jwt_from_credentials: JwtCreation| {
                macro_rules! some_or_remove_cookie {
                    ($e: expr) => {
                        if let Some(v) = $e {
                            v
                        } else {
                            let do_remove_credentials = get_cookie(req, credentials_cookie_name)
                                .map(extract_cookie_value)
                                .map_or(false, |v| !v.is_empty());
                            let do_remove_jwt = get_cookie(req, jwt_cookie_name)
                                .map(extract_cookie_value)
                                .map_or(false, |v| !v.is_empty());
                            let encoding = req.headers_mut().remove("accept-encoding");
                            req.headers_mut()
                                .insert("accept-encoding", HeaderValue::from_static("identity"));

                            remove_cookie(req, credentials_cookie_name);
                            remove_cookie(req, jwt_cookie_name);

                            let mut response = kvarn::handle_cache(req, addr, host).await;

                            if do_remove_credentials {
                                remove_set_cookie(
                                    &mut response.response,
                                    credentials_cookie_name,
                                    cookie_path,
                                );
                            }
                            if do_remove_jwt {
                                remove_set_cookie(
                                    &mut response.response,
                                    jwt_cookie_name,
                                    cookie_path,
                                );
                            }
                            if let Some(encoding) = encoding {
                                req.headers_mut().insert("accept-encoding", encoding);
                            }

                            let mut fat_response = FatResponse::no_cache(response.response);
                            if let Some(f) = response.future {
                                fat_response = fat_response.with_future(f);
                            }
                            return fat_response;
                        }
                    };
                }

                let req: &mut FatRequest = req;

                let addr = match resolve_addr(req, addr, x_real_ip, host).await {
                    Ok(a) => a,
                    Err(resp) => return resp,
                };

                if let Some(header) = req.headers().get("x-kvarn-auth-processed") {
                    error!(
                        "This request has been processed by another auth instance or ourselves. \
                        If you are certain you specified different \
                        `cookie_path`s in the builder, please report this bug. \
                        If this message occurs more than once, it's a serious recursion bug."
                    );
                    if header == "true" {
                        req.headers_mut()
                            .insert("x-kvarn-auth-processed", HeaderValue::from_static("error"));
                        // try to get actual response
                        remove_cookie(req, credentials_cookie_name);
                        remove_cookie(req, jwt_cookie_name);

                        let response = kvarn::handle_cache(req, addr, host).await;
                        let mut fat_response = FatResponse::no_cache(response.response);
                        if let Some(f) = response.future {
                            fat_response = fat_response.with_future(f);
                        }
                        return fat_response;
                    } else {
                        // don't recursively call handle_cache, which could lead to this codepath
                        // again
                        return default_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            host,
                            Some("auth experienced an internal error"),
                        )
                        .await;
                    }
                }
                req.headers_mut()
                    .insert("x-kvarn-auth-processed", HeaderValue::from_static("true"));

                let credentials_cookie = get_cookie(req, credentials_cookie_name);
                let credentials =
                    some_or_remove_cookie!(credentials_cookie.map(extract_cookie_value));
                let mut rsa_credentials = Vec::new();
                some_or_remove_cookie!(base64::decode_engine_vec(
                    credentials,
                    &mut rsa_credentials,
                    &BASE64_ENGINE
                )
                .ok());
                let decrypted =
                    some_or_remove_cookie!(refresh_signing_algo.decrypt(&mut rsa_credentials));
                let (credentials, credentials_ip) =
                    some_or_remove_cookie!(CredentialsStore::from_bytes(&decrypted).ok());

                if let Some(ip) = credentials_ip {
                    // the IP addresses doesn't match
                    if ip != IpBytes::from(addr.ip()).as_ref() {
                        some_or_remove_cookie!(None);
                    }
                }

                let jwt =
                    jwt_from_credentials(credentials.username, credentials.password, addr, req)
                        .await;
                let (jwt, jwt_value) = some_or_remove_cookie!(jwt);

                if let Some((cookie, pos, header_pos)) =
                    get_cookie_with_header_pos(req, jwt_cookie_name)
                {
                    let new_cookie_header =
                        cookie.replace(extract_cookie_value((cookie, pos)), &jwt_value);
                    let header_to_change = req.headers_mut().entry("cookie");
                    if let header::Entry::Occupied(mut entry) = header_to_change {
                        let header_to_change = entry.iter_mut().nth(header_pos).unwrap();
                        *header_to_change = HeaderValue::from_str(&new_cookie_header)
                            .expect("JWT refresh contains illegal bytes in the header");
                    } else {
                        unreachable!(
                            "The header must be present, \
                            since we got the data from it in the previous call"
                        );
                    }
                } else if let Some(h) = req.headers_mut().get_mut("cookie") {
                    let mut new = BytesMut::with_capacity(
                        h.as_bytes().len() + 2 + jwt_cookie_name.len() + 1 + jwt_value.len(),
                    );
                    new.extend_from_slice(h.as_bytes());
                    new.extend_from_slice(b"; ");
                    new.extend_from_slice(jwt_cookie_name.as_bytes());
                    new.extend_from_slice(b"=");
                    new.extend_from_slice(jwt_value.as_bytes());
                    *h = HeaderValue::from_maybe_shared(new)
                        .expect("JWT refresh contains illegal bytes in the header");
                } else {
                    let mut new =
                        BytesMut::with_capacity(jwt_cookie_name.len() + 1 + jwt_value.len());
                    new.extend_from_slice(jwt_cookie_name.as_bytes());
                    new.extend_from_slice(b"=");
                    new.extend_from_slice(jwt_value.as_bytes());
                    req.headers_mut().insert(
                        "cookie",
                        HeaderValue::from_maybe_shared(new)
                            .expect("JWT refresh contains illegal bytes in the header"),
                    );
                }

                let encoding = req.headers_mut().remove("accept-encoding");
                req.headers_mut()
                    .insert("accept-encoding", HeaderValue::from_static("identity"));

                let mut response = kvarn::handle_cache(req, addr, host).await;
                response.response.headers_mut().append(
                    "set-cookie",
                    HeaderValue::from_str(&jwt)
                        .expect("JWT refresh contains illegal bytes in the header"),
                );

                if let Some(encoding) = encoding {
                    req.headers_mut().insert("accept-encoding", encoding);
                }

                let mut fat_response = FatResponse::no_cache(response.response);
                if let Some(f) = response.future {
                    fat_response = fat_response.with_future(f);
                }
                fat_response
            }
        );
        extensions.add_prepare_single(jwt_refresh_page, prepare_extension);

        // `/<auth-page-name>` to accept POST & PUT methods and the return a jwt and credentials
        // token. (use same jwt function as the other page)
        let config = self.clone();
        let new_credentials_cookie = Box::new(move |contents: &str| {
            format!(
                "{}={}; Secure; HttpOnly; SameSite={}; Max-Age={}; Path={}",
                config.credentials_cookie_name,
                contents,
                if config.samesite_strict {
                    "Strict"
                } else {
                    "Lax"
                },
                config.credentials_cookie_validity.as_secs(),
                config.cookie_path,
            )
        });
        let config = self.clone();
        let relogin_on_ip_change = config.relogin_on_ip_change;
        let jwt_cookie_name = config.jwt_cookie_name.clone();
        let credentials_cookie_name = config.credentials_cookie_name.clone();
        let cookie_path = config.cookie_path.clone();
        extensions.add_prepare_single(
            &config.auth_page_name,
            prepare!(
                req,
                host,
                _path,
                addr,
                move |auth_jwt_from_credentials: JwtCreation,
                      signing_algo: Arc<ComputedAlgo>,
                      new_credentials_cookie: Box<dyn Fn(&str) -> String + Send + Sync>,
                      relogin_on_ip_change: bool,
                      credentials_cookie_name: String,
                      jwt_cookie_name: String,
                      cookie_path: String| {
                    macro_rules! some_or_return {
                        ($e: expr, $status: expr) => {
                            if let Some(v) = $e {
                                v
                            } else {
                                return kvarn::default_error_response($status, host, None).await;
                            }
                        };
                        ($e: expr, $status: expr, $message: expr) => {
                            if let Some(v) = $e {
                                v
                            } else {
                                return kvarn::default_error_response(
                                    $status,
                                    host,
                                    Some($message),
                                )
                                .await;
                            }
                        };
                    }
                    let addr = match resolve_addr(req, addr, x_real_ip, host).await {
                        Ok(a) => a,
                        Err(resp) => return resp,
                    };

                    match *req.method() {
                        // continue with the normal control flow
                        Method::POST | Method::PUT => {}
                        Method::DELETE => {
                            let mut response = Response::new(Bytes::new());
                            remove_set_cookie(&mut response, jwt_cookie_name, cookie_path);
                            remove_set_cookie(&mut response, credentials_cookie_name, cookie_path);
                            return FatResponse::no_cache(response);
                        }
                        _ => {
                            return default_error_response(
                                StatusCode::METHOD_NOT_ALLOWED,
                                host,
                                Some("POST or PUT to log in, DELETE to log out"),
                            )
                            .await
                        }
                    }

                    let body = some_or_return!(
                        req.body_mut().read_to_bytes().await.ok(),
                        StatusCode::BAD_REQUEST
                    );
                    let body =
                        some_or_return!(std::str::from_utf8(&body).ok(), StatusCode::BAD_REQUEST);
                    let (username_length, credentials) = some_or_return!(
                        body.split_once('\n'),
                        StatusCode::BAD_REQUEST,
                        "the first line needs to be the username's length in bytes"
                    );
                    let username_length: usize = some_or_return!(
                        username_length.parse().ok(),
                        StatusCode::BAD_REQUEST,
                        "the first line needs to be the username's length in bytes"
                    );
                    let username = some_or_return!(
                        credentials.get(..username_length),
                        StatusCode::BAD_REQUEST,
                        "the username length was invalid"
                    );
                    let password = some_or_return!(
                        credentials.get(username_length..),
                        StatusCode::BAD_REQUEST,
                        "the username length was invalid; couldn't read password"
                    );
                    let (jwt_header, _jwt_value) = some_or_return!(
                        auth_jwt_from_credentials(username, password, addr, req).await,
                        StatusCode::UNAUTHORIZED,
                        "the credentials are invalid"
                    );
                    let credentials = CredentialsStore::new(username, password);
                    let credentials_bin = credentials.to_bytes(if *relogin_on_ip_change {
                        Some(addr.ip())
                    } else {
                        None
                    });
                    let encrypted = signing_algo.encrypt(&credentials_bin);
                    let mut credentials_header = String::new();
                    base64::encode_engine_string(
                        &encrypted,
                        &mut credentials_header,
                        &BASE64_ENGINE,
                    );
                    let credentials_header = new_credentials_cookie(&credentials_header);
                    FatResponse::no_cache(
                        Response::builder()
                            .header("set-cookie", jwt_header)
                            .header("set-cookie", credentials_header)
                            .body(Bytes::new())
                            .expect(
                                "JWT or credentials header contains invalid bytes for a header",
                            ),
                    )
                }
            ),
        );
    }
}

#[cfg(tests)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[cfg(feature = "ecdsa")]
    fn test_computed_algo(secret: &[u8]) -> ComputedAlgo {
        CryptoAlgo::EcdsaP256 {
            secret: secret.to_vec(),
        }
        .into()
    }

    #[test]
    #[cfg(feature = "structured")]
    fn serde() {
        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        let token = d.into_jwt_with_default_header(&test_computed_algo(b"secretkey"), 60, None);

        let v = Validation::<HashMap<String, String>>::from_jwt(&token, b"secretkey", None);
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
    #[cfg(all(feature = "ecdsa", feature = "structured"))]
    fn tampering_1() {
        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        // eyJhbGciOiJIUzI1NiJ9.eyJfX3ZhcmlhbnQiOiJzIiwiZXhwIjoxNjU5NDc3MjA4LCJpYXQiOjE2NTk0NzcxNDgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.p4V5nMMHYbri-na4aEPJzVIMb2U1XhEH9RmL8Hurra4
        let _token = d.into_jwt_with_default_header(&test_computed_algo(b"secretkey"), 60, None);

        // changed `loggedInAs` to `superuser`
        let tampered_token = "eyJhbGciOiJIUzI1NiJ9.eyJfX3ZhcmlhbnQiOiJzIiwiZXhwIjoxNjU5NDc3MjA4LCJpYXQiOjE2NTk0NzcxNDgsImxvZ2dlZEluQXMiOiJzdXBlcnVzZXIifQ.p4V5nMMHYbri-na4aEPJzVIMb2U1XhEH9RmL8Hurra4";

        let v = Validation::<HashMap<String, String>>::from_jwt(tampered_token, b"secretkey", None);
        match v {
            Validation::Authorized(_) => panic!("should be unauthorized"),
            Validation::Unauthorized => {}
        }
    }
    #[test]
    #[cfg(feature = "ecdsa")]
    fn tampering_2() {
        let d = AuthData::<()>::Text("user".to_owned());
        let _token = d.into_jwt_with_default_header(&test_computed_algo(b"secretkey"), 60, None);

        let d = AuthData::<()>::Text("admin".to_owned());
        let tampered_token =
            d.into_jwt_with_default_header(&test_computed_algo(b"the hacker's secret"), 60, None);

        let v =
            Validation::<HashMap<String, String>>::from_jwt(&tampered_token, b"secretkey", None);
        match v {
            Validation::Authorized(_) => panic!("should be unauthorized"),
            Validation::Unauthorized => {}
        }
    }
}
