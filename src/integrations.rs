//! Integrations with databases to get started more quickly.
//!
//! # Support
//!
//! - [x] Custom, built-in format
//! - [ ] SQL?
//! - [ ] Icelk's DB?

#![allow(missing_docs)]

use std::collections::BTreeSet;
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
pub struct GetFsUser<T, U> {
    pub login: Login,
    data: Arc<FsUserCollection<T, U>>,
}
impl<T, U> Clone for GetFsUser<T, U> {
    fn clone(&self) -> Self {
        Self {
            login: self.login.clone(),
            data: self.data.clone(),
        }
    }
}
impl<
        T: DeserializeOwned + Serialize + Send + Sync,
        U: DeserializeOwned + Serialize + Send + Sync,
    > GetFsUser<T, U>
{
    /// Get the user and it's data.
    pub fn get_user(
        &self,
        request: &FatRequest,
        addr: SocketAddr,
    ) -> UserValidation<dashmap::mapref::one::Ref<'_, CompactString, User<T>>> {
        let validation = (self.login)(request, addr);
        match validation {
            Validation::Unauthorized => UserValidation::Unauthorized,
            Validation::Authorized(AuthData::Structured(v)) => {
                let Some(user) = self.data.users.get(&v.username) else {
                    warn!(
                        "User {} is authorized but doesn't exist in the DB",
                        v.username
                    );
                    return UserValidation::Unauthorized;
                };

                UserValidation::Authorized(v, user)
            }
            _ => panic!("our AuthData is always Structured"),
        }
    }
    /// Get the user and it's data as a mutable reference.
    pub fn get_user_mut(
        &self,
        request: &FatRequest,
        addr: SocketAddr,
    ) -> UserValidation<dashmap::mapref::one::RefMut<'_, CompactString, User<T>>> {
        let validation = (self.login)(request, addr);
        match validation {
            Validation::Unauthorized => UserValidation::Unauthorized,
            Validation::Authorized(AuthData::Structured(v)) => {
                let Some(user) = self.data.users.get_mut(&v.username) else {
                    warn!(
                        "User {} is authorized but doesn't exist in the DB",
                        v.username
                    );
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
    #[serde(flatten)]
    other: serde_json::Value,
}
#[derive(Deserialize, Serialize, Clone)]
pub struct User<T> {
    pub username: CompactString,
    pub email: CompactString,
    pub admin: bool,

    pub data: T,

    pub ctime: DateTime,

    hashed_password: u128,
    salt: [u8; 16],
}
impl<T> User<T> {
    pub fn new_password(&mut self, password: &[u8]) {
        let (hash, salt) = new_hash(password);
        self.hashed_password = hash;
        self.salt = salt;
    }
}
#[derive(Deserialize, Serialize, Clone)]
struct QueriedUser {
    pub username: CompactString,
    pub email: CompactString,
    pub admin: bool,
}
#[derive(Serialize, Deserialize)]
pub struct FsUserCollection<T, U> {
    pub users: DashMap<CompactString, User<T>>,
    pub email_to_user: DashMap<CompactString, CompactString>,
    pub other_data: U,
    #[serde(skip)]
    pub path: CompactString,
}
impl<
        T: DeserializeOwned + Serialize + Send + Sync,
        U: DeserializeOwned + Serialize + Send + Sync,
    > FsUserCollection<T, U>
{
    pub fn empty_at(path: impl AsRef<str>, other_data: U) -> Self {
        Self {
            users: DashMap::new(),
            email_to_user: DashMap::new(),
            other_data,

            path: path.as_ref().to_compact_string(),
        }
    }
    pub async fn read(path: impl AsRef<str>) -> Option<Result<Self, String>> {
        let path = path.as_ref().to_compact_string();
        // `tokio-uring` support
        let file = kvarn::read_file(&path, None).await?;
        let me: Result<Self, _> =
            bincode::serde::decode_from_slice(&file, bincode::config::standard()).map(|(v, _)| v);
        match me {
            Ok(mut me) => {
                me.path = path;
                Some(Ok(me))
            }
            Err(err) => Some(Err(format!("Failed to load the file at {path}: {err}"))),
        }
    }
    pub async fn write(&self) {
        let (data, path) = {
            (
                bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap(),
                self.path.clone(),
            )
        };

        if let Err(err) = tokio::fs::write(path.as_str(), data).await {
            error!("Failed to write user database to {path:?}: {err}");
        }
    }

    pub fn remove_user(&self, username: &str) -> bool {
        let user = self.users.remove(username);
        if let Some((_, user)) = user {
            self.email_to_user.remove(&user.email);
            true
        } else {
            false
        }
    }
    #[allow(clippy::result_unit_err)]
    pub fn change_user_password(&self, username: &str, password: &[u8]) -> Result<(), ()> {
        let mut u = self.users.get_mut(username).ok_or(())?;
        u.new_password(password);
        Ok(())
    }

    /// Change types of all data. Useful for "upgrading" the data scheme
    /// Please keep in mind that the `other_data` passwed to `map_user_data` is not upgraded
    pub fn map<
        NewT: DeserializeOwned + Serialize + Send + Sync,
        NewU: DeserializeOwned + Serialize + Send + Sync,
    >(
        self,
        map_other_data: impl FnOnce(U, &DashMap<CompactString, User<NewT>>) -> NewU,
        mut map_user_data: impl FnMut(T, &U) -> NewT,
    ) -> FsUserCollection<NewT, NewU> {
        let Self {
            users,
            email_to_user,
            other_data,
            path,
        } = self;

        let users = users
            .into_iter()
            .map(|(k, v)| {
                let User {
                    username,
                    email,
                    admin,
                    data,
                    ctime,
                    hashed_password,
                    salt,
                } = v;
                let data = map_user_data(data, &other_data);
                (
                    k,
                    User {
                        username,
                        email,
                        admin,
                        data,
                        ctime,
                        hashed_password,
                        salt,
                    },
                )
            })
            .collect();
        let other_data = map_other_data(other_data, &users);

        FsUserCollection {
            users,
            email_to_user,
            other_data,
            path,
        }
    }
}
/// `Arc<async Fn(username, email) -> Option<User data>>`, disallowed if `None`
pub type CreationAllowed<T> = Arc<
    dyn Fn(CompactString, CompactString, serde_json::Value) -> RetFut<'static, Option<T>>
        + Send
        + Sync,
>;
/// `Arc<async Fn(user, email, target_user_to_be_deleted, user_is_admin) -> delete?>`
///
/// Is only called if the deletion would normally be allowed (user tries to delete self, or user
/// is admin).
pub type AllowUserDeletion = Arc<
    dyn Fn(CompactString, CompactString, CompactString, bool) -> RetFut<'static, bool>
        + Send
        + Sync,
>;

#[derive(Default)]
pub struct FsIntegrationOptions {
    pub always_admin: BTreeSet<CompactString>,
    pub account_path: Option<CompactString>,
    pub login_path: Option<CompactString>,
    pub cookie_path: Option<CompactString>,
    pub allow_user_deletion: Option<AllowUserDeletion>,
}

pub fn mount_fs_integration<
    T: DeserializeOwned + Serialize + Send + Sync + 'static,
    U: Serialize + DeserializeOwned + Send + Sync + 'static,
>(
    path: impl AsRef<str>,
    extensions: &mut Extensions,
    creation_allowed: CreationAllowed<T>,
    users: Arc<FsUserCollection<T, U>>,
    key: CryptoAlgo,
    opts: FsIntegrationOptions,
) -> GetFsUser<T, U> {
    let path = path.as_ref();
    let account_path = format_compact!(
        "{path}{}",
        opts.account_path.as_ref().map_or("account", |s| s.as_ref())
    );
    let login_path = format_compact!(
        "{path}{}",
        opts.login_path.as_ref().map_or("login", |s| s.as_ref())
    );

    let auth = {
        let users = users.clone();
        Builder::new()
            .with_cookie_path(opts.cookie_path.as_ref().map_or(path, |s| s.as_ref()))
            .with_auth_page_name(login_path)
            .with_relaxed_httponly()
            .build(
                move |user, password, _addr, _req| {
                    let user = user.to_compact_string();
                    let password = password.to_compact_string();
                    let users = users.clone();
                    async move {
                        let user = users.users.get(&user).or_else(|| {
                            users
                                .email_to_user
                                .get(&user)
                                .and_then(|user| users.users.get(user.value()))
                        });
                        let Some(user) = user else {
                            return Validation::Unauthorized;
                        };

                        let hash = password_hash(password.as_bytes(), &user.salt);

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
    struct Ext<
        T: DeserializeOwned + Serialize + Send + Sync,
        U: DeserializeOwned + Serialize + Send + Sync,
    > {
        creation_allowed: CreationAllowed<T>,
        users: Arc<FsUserCollection<T, U>>,
        login: Login,
        deletion: Option<AllowUserDeletion>,
        always_admin: BTreeSet<CompactString>,
    }
    impl<
            T: DeserializeOwned + Serialize + Send + Sync,
            U: DeserializeOwned + Serialize + Send + Sync,
        > kvarn::extensions::PrepareCall for Ext<T, U>
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
                    login,
                    deletion,
                    always_admin,
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
                                StatusCode::BAD_REQUEST,
                                host,
                                Some("requires JSON body"),
                            )
                            .await;
                        };
                        let Ok(mut body): Result<CreationUser, _> = serde_json::from_slice(&body)
                        else {
                            return default_error_response(
                                StatusCode::BAD_REQUEST,
                                host,
                                Some("missing parameters"),
                            )
                            .await;
                        };

                        body.email = body.email.to_lowercase().to_compact_string();

                        let contains = {
                            users.users.contains_key(&body.username)
                                || users.email_to_user.contains_key(&body.email)
                        };
                        let allow = async {
                            (creation_allowed)(
                                body.username.clone(),
                                body.email.clone(),
                                body.other,
                            )
                            .await
                        };
                        let opt = if contains { None } else { allow.await };
                        let Some(data) = opt else {
                            return default_error_response(
                                StatusCode::FORBIDDEN,
                                host,
                                Some("you aren't allowed to create an account"),
                            )
                            .await;
                        };

                        let (hash, salt) = new_hash(body.password.as_bytes());

                        let user = User {
                            username: body.username.clone(),
                            email: body.email.clone(),
                            admin: always_admin.contains(&body.username),

                            data,

                            ctime: DateTime(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or(Duration::ZERO)
                                    .as_millis() as u64,
                            ),

                            hashed_password: hash,
                            salt,
                        };
                        if users.users.contains_key(&body.username)
                            || users.email_to_user.contains_key(&body.email)
                        {
                            return default_error_response(
                                StatusCode::FORBIDDEN,
                                host,
                                Some("you aren't allowed to create an account"),
                            )
                            .await;
                        }
                        users.users.insert(body.username.clone(), user);
                        users
                            .email_to_user
                            .insert(body.email.clone(), body.username.clone());

                        users.write().await;

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
                        let Validation::Authorized(AuthData::Structured(LoginData {
                            username,
                            email,
                            admin,
                            ctime: _,
                        })) = login(req, addr)
                        else {
                            return default_error_response(StatusCode::UNAUTHORIZED, host, None)
                                .await;
                        };

                        let header = req
                            .headers()
                            .get("x-account")
                            .map(HeaderValue::to_str)
                            .and_then(Result::ok);

                        let mut target;

                        if let Some(header) = header {
                            if !admin {
                                return default_error_response(
                                    StatusCode::UNAUTHORIZED,
                                    host,
                                    None,
                                )
                                .await;
                            }
                            target = header.to_compact_string();
                        } else {
                            if admin {
                                return default_error_response(
                                    StatusCode::UNAUTHORIZED,
                                    host,
                                    Some("you can't implicitly delete your account as admin"),
                                )
                                .await;
                            }
                            target = username.clone()
                        }

                        if !users.users.contains_key(&target) {
                            if let Some(u) = users.email_to_user.get(&target) {
                                target = u.value().to_compact_string();
                            }
                        }

                        let allow = if let Some(f) = deletion {
                            f(
                                username.to_compact_string(),
                                email,
                                target.to_compact_string(),
                                admin,
                            )
                            .await
                        } else {
                            true
                        };
                        let r = if allow {
                            if users.remove_user(&target) {
                                FatResponse::no_cache(Response::new(Bytes::new()))
                            } else {
                                default_error_response(
                                    StatusCode::NOT_FOUND,
                                    host,
                                    Some("account not found"),
                                )
                                .await
                            }
                        } else {
                            default_error_response(
                                StatusCode::UNAUTHORIZED,
                                host,
                                Some("you weren't allowed to remove your account"),
                            )
                            .await
                        };
                        users.write().await;
                        r
                    }
                    _ => default_error_response(StatusCode::METHOD_NOT_ALLOWED, host, None).await,
                }
            })
        }
    }
    extensions.add_prepare_single(
        account_path,
        Box::new(Ext {
            creation_allowed,
            login,
            users: users.clone(),
            deletion: opts.allow_user_deletion,
            always_admin: opts.always_admin,
        }),
    );
    auth.mount(extensions);
    GetFsUser {
        login: auth.login_status(),
        data: users,
    }
}

fn password_hash(password: &[u8], salt: &[u8]) -> u128 {
    let mut pass = Vec::with_capacity(password.len() + salt.len());
    pass.extend_from_slice(password);
    pass.extend_from_slice(salt);

    xxhash_rust::xxh3::xxh3_128(&pass)
}
fn new_hash(password: &[u8]) -> (u128, [u8; 16]) {
    let salt: [u8; 16] = rand::Rng::gen(&mut rand::thread_rng());

    let hash = password_hash(password, &salt);
    (hash, salt)
}
