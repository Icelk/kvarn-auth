#![allow(dead_code)]
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::FutureExt;
use hmac::{Hmac, Mac};
pub use rsa;
use rsa::PublicKey;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

fn seconds_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn get_cookie<'a, T>(req: &'a kvarn::prelude::Request<T>, name: &str) -> Option<(&'a str, usize)> {
    let mut cookie = None;
    let filter = format!("{}=", name);
    for header in req
        .headers()
        .get_all("cookie")
        .into_iter()
        .filter_map(|h| h.to_str().ok())
    {
        if let Some(pos) = header.find(&filter) {
            cookie = Some((header, pos + filter.len()));
            break;
        }
    }
    cookie
}
fn extract_cookie_value(d: (&str, usize)) -> &str {
    let s = &d.0[d.1..];
    s.split(';').next().unwrap_or(s)
}
pub enum AuthData<T: Serialize + DeserializeOwned = ()> {
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
    fn into_jwt(
        self,
        signing_algo: &ComputedAlgo,
        header: &[u8],
        seconds_before_expiry: u64,
        ip: Option<IpAddr>,
    ) -> String {
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

        match signing_algo {
            ComputedAlgo::HmacSha256 { secret, .. } => {
                // Hmac can take a key of any length
                let mut hmac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
                hmac.update(s.as_bytes());
                if let Some(ip) = ip {
                    hmac.update(IpBytes::from(ip).as_ref());
                }
                let sig = hmac.finalize().into_bytes();
                s.push('.');
                base64::encode_config_buf(sig, base64::URL_SAFE_NO_PAD, &mut s);
            }
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
                        rsa::PaddingScheme::PKCS1v15Sign {
                            hash: Some(rsa::Hash::SHA2_256),
                        },
                        &*hash,
                    )
                    .expect("failed to sign JWT with RSA key");
                s.push('.');
                base64::encode_config_buf(signature, base64::URL_SAFE_NO_PAD, &mut s);
            }
        }
        s
    }
    // static HEADER: &[u8] = r#"{"alg":"HS256"}"#.as_bytes();
    // static HEADER: &[u8] = r#"{"alg":"RS256"}"#.as_bytes();
    // fn into_jwt_with_default_header()
}
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
            Self::V4(addr) => &*addr,
            Self::V6(addr) => &*addr,
        }
    }
}

trait Validate {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()>;
}
impl Validate for ValidationAlgo {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        (&self).validate(data, signature, ip)
    }
}
impl<'a> Validate for &'a ValidationAlgo {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        match *self {
            ValidationAlgo::RSASha256 { public_key } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                if let Some(ip) = ip {
                    hasher.update(IpBytes::from(ip).as_ref());
                }
                let hash = hasher.finalize();
                public_key
                    .verify(
                        rsa::PaddingScheme::PKCS1v15Sign {
                            hash: Some(rsa::Hash::SHA2_256),
                        },
                        &hash,
                        signature,
                    )
                    .map_err(|_| ())
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
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        match *self {
            ComputedAlgo::RSASha256 { public_key, .. } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                if let Some(ip) = ip {
                    hasher.update(IpBytes::from(ip).as_ref());
                }
                let hash = hasher.finalize();
                public_key
                    .verify(
                        rsa::PaddingScheme::PKCS1v15Sign {
                            hash: Some(rsa::Hash::SHA2_256),
                        },
                        &hash,
                        signature,
                    )
                    .map_err(|_| ())
            }
            ComputedAlgo::HmacSha256 { secret, .. } => {
                // Hmac can take a key of any length
                let mut hmac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
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
            Mode::Validate(v) => v.validate(data, signature, ip),
        }
    }
}
impl<'a> Validate for &'a [u8] {
    fn validate(&self, data: &[u8], signature: &[u8], ip: Option<IpAddr>) -> Result<(), ()> {
        // Hmac can take a key of any length
        let mut hmac = Hmac::<Sha256>::new_from_slice(self).unwrap();
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
}
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
fn validate(s: &str, validate: impl Validate, ip: Option<IpAddr>) -> Option<serde_json::Value> {
    let parts = s.splitn(3, '.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let signature_input = &s[..parts[0].len() + parts[1].len() + 1];
    let remote_signature = base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD).ok()?;
    if validate
        .validate(signature_input.as_bytes(), &remote_signature, ip)
        .is_err()
    {
        return None;
    }
    let payload = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = (self.username.len() as u64).to_le_bytes();
        let mut v = Vec::with_capacity(8 + self.username.len() + self.password.len());
        v.extend_from_slice(&len);
        v.extend_from_slice(self.username.as_bytes());
        v.extend_from_slice(self.password.as_bytes());
        v
    }
    pub fn from_bytes(mut b: &'a [u8]) -> Result<Self, ()> {
        (|| {
            let mut take_n = |n: usize| {
                let v = b.get(..n)?;
                b = &b[n..];
                Some(v)
            };
            let len = take_n(8)?;
            let mut array = [0; 8];
            array.copy_from_slice(len);
            let len = u64::from_le_bytes(array);
            let username = std::str::from_utf8(take_n(len as usize)?).ok()?;
            let password = std::str::from_utf8(b).ok()?;
            Some(Self { username, password })
        })()
        .ok_or(())
    }
}

#[derive(Debug)]
pub enum ValidationAlgo {
    RSASha256 { public_key: rsa::RsaPublicKey },
}
#[derive(Debug)]
enum ComputedAlgo {
    HmacSha256 {
        secret: Vec<u8>,
        credentials_encryption_rsa_private_key: rsa::RsaPrivateKey,
        credentials_encryption_rsa_public_key: rsa::RsaPublicKey,
    },
    RSASha256 {
        private_key: rsa::RsaPrivateKey,
        public_key: rsa::RsaPublicKey,
    },
}
impl ComputedAlgo {
    fn public_key(&self) -> &rsa::RsaPublicKey {
        match self {
            Self::HmacSha256 {
                credentials_encryption_rsa_public_key,
                ..
            } => credentials_encryption_rsa_public_key,
            Self::RSASha256 {
                private_key: _,
                public_key,
            } => public_key,
        }
    }
    fn private_key(&self) -> &rsa::RsaPrivateKey {
        match self {
            Self::HmacSha256 {
                credentials_encryption_rsa_private_key,
                ..
            } => credentials_encryption_rsa_private_key,
            Self::RSASha256 {
                public_key: _,
                private_key,
            } => private_key,
        }
    }
}
impl From<CryptoAlgo> for ComputedAlgo {
    fn from(alg: CryptoAlgo) -> Self {
        match alg {
            CryptoAlgo::HmacSha256 {
                secret,
                credentials_encryption_rsa_private_key,
            } => Self::HmacSha256 {
                secret,
                credentials_encryption_rsa_public_key: rsa::RsaPublicKey::from(
                    &credentials_encryption_rsa_private_key,
                ),
                credentials_encryption_rsa_private_key,
            },
            CryptoAlgo::RSASha256 { private_key } => Self::RSASha256 {
                public_key: rsa::RsaPublicKey::from(&private_key),
                private_key,
            },
        }
    }
}
#[derive(Debug)]
pub enum CryptoAlgo {
    HmacSha256 {
        secret: Vec<u8>,
        credentials_encryption_rsa_private_key: rsa::RsaPrivateKey,
    },
    // https://docs.rs/rsa/latest/rsa/struct.RsaPrivateKey.html#method.sign
    // https://docs.rs/rsa/latest/rsa/trait.PublicKey.html#tymethod.verify
    RSASha256 {
        private_key: rsa::RsaPrivateKey,
    },
}
#[derive(Debug, Clone)]
enum Mode {
    Sign(Arc<ComputedAlgo>),
    Validate(Arc<ValidationAlgo>),
}
#[derive(Debug, Default)]
pub struct Builder {
    auth_page_name: Option<String>,
    jwt_page_name_extension: String,
    samesite_strict: Option<bool>,
    relogin_on_ip_change: Option<bool>,
    jwt_cookie_name: Option<String>,
    credentials_cookie_name: Option<String>,
}
impl Builder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the URL endpoint where your frontend authenticates to.
    pub fn with_auth_page_name(mut self, auth_page_name: impl Into<String>) -> Self {
        let s = auth_page_name.into();
        let jwt_page_name_extension = s.replace('/', "-");
        self.jwt_page_name_extension = jwt_page_name_extension;
        self.auth_page_name = Some(s);
        self
    }
    /// Decrease security for CSRF but allow users to follow links to auth-protected pages from
    /// other sites.
    /// This sets the `samsite` property of the cookie to `lax`.
    pub fn with_lax_samesite(mut self) -> Self {
        self.samesite_strict = Some(false);
        self
    }
    /// Forces relogging by the user when they change IPs. This can protect users from getting
    /// their cookies scraped by malware, as the authentication is IP dependant.
    pub fn with_force_relog_on_ip_change(mut self) -> Self {
        self.samesite_strict = Some(false);
        self
    }
    /// Sets the name of the JWT cookie. This is the cookie that authorizes the user.
    pub fn with_jwt_cookie_name(mut self, jwt_cookie_name: impl Into<String>) -> Self {
        self.jwt_cookie_name = Some(jwt_cookie_name.into());
        self
    }
    /// Sets the name of the credentials cookie. This is the cookie that stores the user's
    /// credentials to allow renewal of the JWT cookie without requiring the user to input
    /// credentials. It is encrypted with the server's PK.
    pub fn with_credentials_cookie_name(
        mut self,
        credentials_cookie_name: impl Into<String>,
    ) -> Self {
        self.credentials_cookie_name = Some(credentials_cookie_name.into());
        self
    }
    pub fn build<
        T: Serialize + DeserializeOwned + Send + Sync,
        F: Fn(&str, &str, SocketAddr, &kvarn::FatRequest) -> Fut + Send + Sync,
        Fut: Future<Output = Validation<T>> + Send + Sync,
    >(
        self,
        is_allowed: F,
        pk: CryptoAlgo,
    ) -> Arc<Config<T, F, Fut>> {
        let c = Config {
            mode: Mode::Sign(Arc::new(pk.into())),
            is_allowed: Arc::new(is_allowed),
            jwt_page_name_extension: self.jwt_page_name_extension,
            auth_page_name: self.auth_page_name.unwrap_or_else(|| "/auth".into()),
            samesite_strict: self.samesite_strict.unwrap_or(true),
            relogin_on_ip_change: self.relogin_on_ip_change.unwrap_or(false),
            jwt_cookie_name: self.jwt_cookie_name.unwrap_or_else(|| "auth-jwt".into()),
            credentials_cookie_name: self
                .credentials_cookie_name
                .unwrap_or_else(|| "auth-credentials".into()),
        };
        Arc::new(c)
    }
    #[allow(clippy::type_complexity)]
    pub fn build_validate(
        self,
        public_key: rsa::RsaPublicKey,
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
        let c = Config {
            mode: Mode::Validate(Arc::new(ValidationAlgo::RSASha256 { public_key })),
            is_allowed: Arc::new(placeholder),
            jwt_page_name_extension: self.jwt_page_name_extension,
            auth_page_name: self.auth_page_name.unwrap_or_else(|| "/auth".into()),
            samesite_strict: self.samesite_strict.unwrap_or(true),
            relogin_on_ip_change: self.relogin_on_ip_change.unwrap_or(false),
            jwt_cookie_name: self.jwt_cookie_name.unwrap_or_else(|| "auth-jwt".into()),
            credentials_cookie_name: self
                .credentials_cookie_name
                .unwrap_or_else(|| "auth-credentials".into()),
        };
        Arc::new(c)
    }
}
pub type LoginStatusClosure<T> = Arc<
    dyn Fn(&kvarn::FatRequest, kvarn::prelude::SocketAddr) -> Validation<T> + Send + Sync + 'static,
>;
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
    relogin_on_ip_change: bool,
    jwt_cookie_name: String,
    credentials_cookie_name: String,
    // `TODO`: add option to use a prime extension to show the auth page when needing to log in to
    // see a resource
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
    /// # Panics
    ///
    /// Panics if this config was created using [`Builder::build_validate`].
    #[allow(clippy::match_result_ok)]
    pub fn mount(self: &Arc<Self>, extensions: &mut kvarn::Extensions) {
        use kvarn::prelude::*;

        #[derive(Debug)]
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
                ) -> extensions::RetSyncFut<'static, Option<String>>
                + Send
                + Sync
                + 'static,
        >;

        let signing_algo = match &self.mode {
            Mode::Sign(s) => Arc::clone(s),
            Mode::Validate(_v) => panic!("Called mount on a config acting as a validator."),
        };

        let config = self.clone();
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
        let validate: Box<dyn Fn(&FatRequest, SocketAddr) -> AuthState + Send + Sync> =
            Box::new(validate);

        extensions.add_prime(
            prime!(req, _host, addr, move |validate: Box<
                dyn Fn(&FatRequest, SocketAddr) -> AuthState + Send + Sync,
            >| {
                let state: AuthState = validate(req, addr);
                match state {
                    AuthState::Authorized | AuthState::Missing => None,
                    AuthState::Incorrect => Some(Uri::from_static("/./jwt-auth-refresh-token")),
                }
            }),
            extensions::Id::new(8432, "auth JWT renewal").no_override(),
        );
        let refresh_signing_algo = signing_algo.clone();
        // `/./jwt-auth-refresh-token` to read credentials token and write jwt token (remove
        // credentials if invalid), then 303 to the current page
        let credentials_cookie_name = self.credentials_cookie_name.clone();
        let config = self.clone();
        let jwt_signing_algo = signing_algo.clone();
        let jwt_from_credentials: JwtCreation = Arc::new(
            move |username: &str, password: &str, addr: SocketAddr, req: &FatRequest| {
                let signing_algo = jwt_signing_algo.clone();
                let config = config.clone();
                let fut = (config.is_allowed)(username, password, addr, req).then(
                    move |data| async move {
                        // let seconds_before_expiry = config.
                        match data {
                            Validation::Unauthorized => None,
                            Validation::Authorized(data) => {
                                let jwt =
                                    data.into_jwt(&signing_algo, b"", 60, config.ip(addr.ip()));
                                let header_value = format!(
                                    "{}={}; Secure; HttpOnly; SameSite={}; Path=/",
                                    config.jwt_cookie_name,
                                    jwt,
                                    if config.samesite_strict {
                                        "Strict"
                                    } else {
                                        "Lax"
                                    }
                                );
                                Some(header_value)
                            }
                        }
                    },
                );
                Box::pin(fut)
            },
        );
        let auth_jwt_from_credentials = Arc::clone(&jwt_from_credentials);
        extensions.add_prepare_single(
            "/./jwt-auth-refresh-token",
            prepare!(
                req,
                _,
                _,
                addr,
                move |credentials_cookie_name: String,
                      refresh_signing_algo: Arc<ComputedAlgo>,
                      jwt_from_credentials: JwtCreation| {
                    macro_rules! remove_cookie_307 {
                        ($e: expr, $uri: expr, $body: expr) => {
                            if let Some(v) = $e {
                                v
                            } else {
                                return FatResponse::no_cache(
                                    Response::builder()
                                        .status(StatusCode::TEMPORARY_REDIRECT)
                                        .header("location", $uri)
                                        .header(
                                            "set-cookie",
                                            format!(r#"{credentials_cookie_name}=""; Expires=1"#),
                                        )
                                        .body($body)
                                        .unwrap(),
                                );
                            }
                        };
                    }

                    let uri = req
                        .uri()
                        .path_and_query()
                        .map(uri::PathAndQuery::as_str)
                        .unwrap_or("/");
                    let uri = HeaderValue::from_str(uri)
                        .unwrap_or_else(|_| HeaderValue::from_static("/"));
                    let body = Bytes::from_static(b"");
                    let credentials_cookie = get_cookie(req, credentials_cookie_name);
                    let credentials =
                        remove_cookie_307!(credentials_cookie.map(extract_cookie_value), uri, body);
                    let mut rsa_credentials = Vec::new();
                    remove_cookie_307!(
                        base64::decode_config_buf(
                            credentials,
                            base64::URL_SAFE_NO_PAD,
                            &mut rsa_credentials,
                        )
                        .ok(),
                        uri,
                        body
                    );
                    let key = refresh_signing_algo.private_key();
                    let decrypted = remove_cookie_307!(
                        key.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &rsa_credentials)
                            .ok(),
                        uri,
                        body
                    );
                    let credentials = remove_cookie_307!(
                        CredentialsStore::from_bytes(&decrypted).ok(),
                        uri,
                        body
                    );

                    let jwt =
                        jwt_from_credentials(credentials.username, credentials.password, addr, req)
                            .await;
                    let jwt = remove_cookie_307!(jwt, uri, body);

                    FatResponse::no_cache(
                        Response::builder()
                            .status(StatusCode::TEMPORARY_REDIRECT)
                            .header("location", uri)
                            .header("set-cookie", jwt)
                            .body(body)
                            .expect("JWT refresh contains illegal bytes in the header"),
                    )
                }
            ),
        );

        // `/<auth-page-name>` to accept POST & PUT methods and the return a jwt and credentials
        // token. (use same jwt function as the other page)
        let config = self.clone();
        let new_credentials_cookie = Box::new(move |contents: &str| {
            format!(
                "{}={}; Secure; HttpOnly; SameSite={}; Path=/",
                config.credentials_cookie_name,
                contents,
                if config.samesite_strict {
                    "Strict"
                } else {
                    "Lax"
                }
            )
        });
        let config = self.clone();
        extensions.add_prepare_single(
            &config.auth_page_name,
            prepare!(
                req,
                host,
                _path,
                addr,
                move |auth_jwt_from_credentials: JwtCreation,
                signing_algo: Arc<ComputedAlgo>,
                new_credentials_cookie: Box<dyn Fn(&str) -> String + Send + Sync>| {
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
                    let body = some_or_return!(
                        req.body_mut().read_to_bytes().await.ok(),
                        StatusCode::BAD_REQUEST
                    );
                    let body =
                        some_or_return!(std::str::from_utf8(&body).ok(), StatusCode::BAD_REQUEST);
                    let mut lines = body.lines();
                    let username = some_or_return!(
                        lines.next(),
                        StatusCode::BAD_REQUEST,
                        "the first line needs to be the username"
                    );
                    let password = some_or_return!(
                        lines.next(),
                        StatusCode::BAD_REQUEST,
                        "the second line needs to be the password"
                    );
                    let jwt_header =some_or_return!(
                        auth_jwt_from_credentials(username, password, addr, req).await,
                        StatusCode::UNAUTHORIZED, "the credentials are invalid"
                    );
                    let credentials = CredentialsStore::new(username, password);
                    let credentials_bin = credentials.to_bytes();
                    let encrypted = signing_algo
                        .public_key()
                        .encrypt(
                            &mut rand::thread_rng(),
                            rsa::PaddingScheme::PKCS1v15Encrypt,
                            &credentials_bin,
                        )
                        .expect("failed to encrypt credentials with RSA");
                    let mut credentials_header = String::new();
                    base64::encode_config_buf(&encrypted, base64::URL_SAFE_NO_PAD, &mut credentials_header);
                    let credentials_header = new_credentials_cookie(&credentials_header);
                    FatResponse::no_cache(
                        Response::builder().header("set-cookie", jwt_header)
                        .header("set-cookie", credentials_header)
                        .body(Bytes::new())
                        .expect("JWT or credentials header contains invalid bytes for a header"))
                }
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    static HEADER: &[u8] = r#"{"alg":"HS256"}"#.as_bytes();

    #[test]
    fn serde() {
        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        let token = d.into_jwt(b"secretkey", HEADER, 60, None);

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
    fn tampering_1() {
        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        // eyJhbGciOiJIUzI1NiJ9.eyJfX3ZhcmlhbnQiOiJzIiwiZXhwIjoxNjU5NDc3MjA4LCJpYXQiOjE2NTk0NzcxNDgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.p4V5nMMHYbri-na4aEPJzVIMb2U1XhEH9RmL8Hurra4
        let _token = d.into_jwt(b"secretkey", HEADER, 60, None);

        // changed `loggedInAs` to `superuser`
        let tampered_token = "eyJhbGciOiJIUzI1NiJ9.eyJfX3ZhcmlhbnQiOiJzIiwiZXhwIjoxNjU5NDc3MjA4LCJpYXQiOjE2NTk0NzcxNDgsImxvZ2dlZEluQXMiOiJzdXBlcnVzZXIifQ.p4V5nMMHYbri-na4aEPJzVIMb2U1XhEH9RmL8Hurra4";

        let v = Validation::<HashMap<String, String>>::from_jwt(tampered_token, b"secretkey", None);
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
        let _token = d.into_jwt(b"secretkey", HEADER, 60, None);

        let mut map = HashMap::new();
        map.insert("loggedInAs".to_owned(), "admin".to_owned());
        let d = AuthData::Structured(map);
        let tampered_token = d.into_jwt(b"the hacker's secret", HEADER, 60, None);

        let v =
            Validation::<HashMap<String, String>>::from_jwt(&tampered_token, b"secretkey", None);
        match v {
            Validation::Authorized(_) => panic!("should be unauthorized"),
            Validation::Unauthorized => {}
        }
    }
}
