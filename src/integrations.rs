//! Integrations with databases to get started more quickly.
//!
//! # Support
//!
//! - [x] Custom, built-in format
//! - [ ] SQL?
//! - [ ] Icelk's DB?

#![allow(missing_docs)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use kvarn::extensions::RetFut;
use kvarn::prelude::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};

use crate::{AuthData, Builder, CryptoAlgo, Validation};

pub enum UserValidation<T> {
    Unauthorized,
    Authorized(LoginData, T),
}
impl<T> UserValidation<T> {
    pub fn into_option(self) -> Option<(LoginData, T)> {
        match self {
            Self::Unauthorized => None,
            Self::Authorized(l, t) => Some((l, t)),
        }
    }
}
/// Gets the user from a request.
pub struct GetFsUser<T: Default + Send + Sync> {
    pub login: Login,
    data: Arc<FsUserCollection<T>>,
}
impl<T: Default + DeserializeOwned + Serialize + Send + Sync> GetFsUser<T> {
    /// Get the user and it's data.
    pub fn get_user(
        &self,
        request: &FatRequest,
        addr: SocketAddr,
    ) -> UserValidation<dashmap::mapref::one::Ref<CompactString, User<T>>> {
        let validation = (self.login)(request, addr);
        match validation {
            Validation::Unauthorized => UserValidation::Unauthorized,
            Validation::Authorized(AuthData::Structured(v)) => {
                let Some(user) = self.data.users.get(&v.username) else {
                    warn!("User {} is authorized but doesn't exist in the DB", v.username);
                    return UserValidation::Unauthorized;
                };

                UserValidation::Authorized(v, user)
            }
            _ => panic!("our AuthData is always Structured"),
        }
    }
}

/// Data used when logging in.
#[derive(Deserialize, Serialize)]
pub struct LoginData {
    pub username: CompactString,
    pub email: CompactString,
    pub admin: bool,
    pub ctime: DateTime,
}

pub type Login = crate::LoginStatusClosure<LoginData>;

/// JS's `+(new Date())`:
/// Milliseconds since epoch.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone, Debug)]
#[serde(transparent)]
pub struct DateTime(u64);

#[derive(Deserialize)]
struct CreationUser {
    username: CompactString,
    email: CompactString,
    password: CompactString,
}
#[derive(Deserialize, Serialize, Clone)]
pub struct User<T: Default + Send + Sync> {
    pub username: CompactString,
    pub email: CompactString,
    pub admin: bool,

    pub data: T,

    pub ctime: DateTime,

    hashed_password: u128,
    salt: [u8; 16],
}
#[derive(Deserialize, Serialize, Clone)]
struct QueriedUser {
    pub username: CompactString,
    pub email: CompactString,
    pub admin: bool,
}
#[derive(Serialize, Deserialize)]
pub struct FsUserCollection<T: Default + Send + Sync> {
    pub users: DashMap<CompactString, User<T>>,
    #[serde(skip)]
    pub path: CompactString,
}
impl<T: Default + DeserializeOwned + Serialize + Send + Sync> FsUserCollection<T> {
    pub fn empty_at(path: impl AsRef<str>) -> Self {
        Self {
            users: DashMap::new(),
            path: path.as_ref().to_compact_string(),
        }
    }
    pub async fn read(path: impl AsRef<str>) -> Option<Self> {
        let path = path.as_ref().to_compact_string();
        let file = kvarn::read_file(&path, None).await?;
        let mut me: Self = bincode::serde::decode_from_slice(&file, bincode::config::standard())
            .ok()
            .map(|(v, _)| v)?;
        me.path = path;
        Some(me)
    }
}
/// `async Fn(username, email) -> bool`
pub type CreationAllowed =
    Arc<dyn Fn(CompactString, CompactString) -> RetFut<'static, bool> + Send + Sync>;
pub fn mount_fs_integration<T: Default + DeserializeOwned + Serialize + Send + Sync + 'static>(
    path: impl AsRef<str>,
    extensions: &mut Extensions,
    creation_allowed: CreationAllowed,
    users: Arc<FsUserCollection<T>>,
    key: CryptoAlgo,
    always_admin: HashSet<CompactString>,
) -> GetFsUser<T> {
    let path = path.as_ref();
    let account_path = format_compact!("{path}account");
    let login_path = format_compact!("{path}login");

    let auth = {
        let users = users.clone();
        Builder::new()
            .with_cookie_path(path)
            .with_auth_page_name(login_path)
            .with_relaxed_httponly()
            .build(
                move |user, password, _addr, _req| {
                    let user = user.to_compact_string();
                    let password = password.to_compact_string();
                    let users = users.clone();
                    async move {
                        let Some(user) = ({
                            users.users.get(&user)
                        }) else {
                            return Validation::Unauthorized;
                        };

                        let mut pass = Vec::with_capacity(password.len() + 16);
                        pass.extend_from_slice(password.as_bytes());
                        pass.extend_from_slice(&user.salt);

                        let hash = xxhash_rust::xxh3::xxh3_128(&pass);

                        if user.hashed_password != hash {
                            return Validation::Unauthorized;
                        }

                        Validation::Authorized(AuthData::Structured(LoginData {
                            username: user.username.clone(),
                            email: user.email.clone(),
                            admin: user.admin,
                            ctime: user.ctime.clone(),
                        }))
                    }
                },
                key,
            )
    };

    let login = auth.login_status();
    struct Ext<T: Default + DeserializeOwned + Serialize + Send + Sync> {
        creation_allowed: CreationAllowed,
        users: Arc<FsUserCollection<T>>,
        always_admin: HashSet<CompactString>,
        login: Login,
    }
    impl<T: Default + DeserializeOwned + Serialize + Send + Sync> kvarn::extensions::PrepareCall
        for Ext<T>
    {
        fn call<'a>(
            &'a self,
            req: &'a mut FatRequest,
            host: &'a Host,
            _: Option<&'a Path>,
            addr: SocketAddr,
        ) -> RetFut<'a, FatResponse> {
            Box::pin(async move {
                let Self {
                    creation_allowed,
                    users,
                    always_admin,
                    login,
                } = self;
                match *req.method() {
                    Method::PUT => {
                        if matches!(login(req, addr), Validation::Authorized(_)) {
                            return default_error_response(
                                StatusCode::BAD_REQUEST,
                                host,
                                Some("You're already logged in!"),
                            )
                            .await;
                        }
                        let Ok(body) = req.body_mut().read_to_bytes(1024 * 8).await else {
                            return default_error_response(
                                StatusCode::BAD_REQUEST, host, Some("requires JSON body")
                            ).await;
                        };
                        let Ok(body): Result<CreationUser, _> = serde_json::from_slice(&body) else {
                            return default_error_response(
                                StatusCode::BAD_REQUEST, host, Some("missing parameters")
                            ).await;
                        };

                        let contains = { users.users.contains_key(&body.username) };
                        let allow = async {
                            (creation_allowed)(body.username.clone(), body.email.clone()).await
                        };
                        if contains || !(allow.await) {
                            return default_error_response(
                                StatusCode::FORBIDDEN,
                                host,
                                Some("you aren't allowed to create an account"),
                            )
                            .await;
                        }

                        let salt: [u8; 16] = rand::Rng::gen(&mut rand::thread_rng());

                        let mut pass = Vec::with_capacity(body.password.len() + 16);
                        pass.extend_from_slice(body.password.as_bytes());
                        pass.extend_from_slice(&salt);

                        let hash = xxhash_rust::xxh3::xxh3_128(&pass);

                        let user = User {
                            username: body.username.clone(),
                            email: body.email.clone(),
                            admin: always_admin.contains(&body.username),

                            data: T::default(),

                            ctime: DateTime(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or(Duration::ZERO)
                                    .as_millis() as u64,
                            ),

                            hashed_password: hash,
                            salt,
                        };
                        let (data, path) = {
                            if users.users.contains_key(&body.username) {
                                return default_error_response(
                                    StatusCode::FORBIDDEN,
                                    host,
                                    Some("you aren't allowed to create an account"),
                                )
                                .await;
                            }
                            users.users.insert(body.username.clone(), user);

                            (
                                bincode::serde::encode_to_vec(
                                    &**users,
                                    bincode::config::standard(),
                                )
                                .unwrap(),
                                users.path.clone(),
                            )
                        };

                        if let Err(err) = tokio::fs::write(path.as_str(), data).await {
                            error!("Failed to write user database to {path:?}: {err}");
                        }

                        FatResponse::no_cache(Response::new(Bytes::new()))
                    }
                    Method::GET => {
                        let login = login(req, addr);
                        if !matches!(
                            login,
                            Validation::Authorized(AuthData::Structured(LoginData {
                                username: _,
                                email: _,
                                admin: true,
                                ctime: _,
                            }))
                        ) {
                            return default_error_response(StatusCode::UNAUTHORIZED, host, None)
                                .await;
                        }
                        let users = users.users.iter().map(|user| QueriedUser {
                            username: user.value().username.clone(),
                            email: user.value().email.clone(),
                            admin: user.value().admin,
                        });
                        let bytes = WriteableBytes::new();
                        let mut ser = serde_json::Serializer::new(bytes);
                        ser.collect_seq(users).unwrap();
                        let bytes = ser.into_inner();

                        FatResponse::no_cache(Response::new(bytes.into_inner().freeze()))
                    }
                    Method::DELETE => {
                        let Validation::Authorized(AuthData::Structured(
                            LoginData {
                                username,
                                email: _,
                                admin,
                                ctime: _,
                            },
                        )) = login(req, addr) else {
                            return default_error_response(StatusCode::UNAUTHORIZED, host, None)
                                .await;
                        };

                        let header = req
                            .headers()
                            .get("x-account")
                            .map(HeaderValue::to_str)
                            .and_then(Result::ok);

                        let target;

                        if let Some(header) = header {
                            if !admin {
                                return default_error_response(
                                    StatusCode::UNAUTHORIZED,
                                    host,
                                    None,
                                )
                                .await;
                            } else {
                                target = header;
                            }
                        } else {
                            target = &username;
                        }

                        users.users.remove(target);

                        FatResponse::no_cache(Response::new(Bytes::new()))
                    }
                    _ => default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None).await,
                }
            })
        }
    }
    extensions.add_prepare_single(
        account_path,
        Box::new(Ext {
            always_admin,
            creation_allowed,
            login,
            users: users.clone(),
        }),
    );
    auth.mount(extensions);
    GetFsUser {
        login: auth.login_status(),
        data: users,
    }
}
