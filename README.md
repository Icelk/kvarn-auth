# kvarn-auth

A fast, simple, and customizable authentication extension for use in [Kvarn](https://kvarn.org).
It's impossible to shot yourself in your foot!

Provides an easy-to-use [JWT](https://wikipedia.org/wiki/JSON_Web_Token)-based authentication helper with support for persistent logins and validation servers.

You provide an async callback which gives the user a level of authorization.
You can return any structured data based on serde.
The JWT is automatically renewed, as the server stores a credentials cookie (encrypted using the server's private key).
Everything is configurable.

**⚠️ Warning: This crate has not been audited. All dependencies I use have. Use at your own risk.**

> I do however personally use this for production systems.

# Front-end usage

A small [JS library](lib.mjs) is provided for logging in and out and to get the current status of the user.
See it and it's docs for more details.

# Validation servers

An important feature of this library is validation servers.
This enables a deployment of `kvarn-auth` to multiple different physicervers,
without sharing the private key which can sign anybody in.
This is achieved by using fast asymmetric cryptography.
See [`ecdsa_sk`] for more info.

# Persistent logins

Along with the usual JWT cookie, `kvarn-auth` sends a credentials cookie.
It contains the user's credentials encrypted using the secret/private key of the server.
This allows for automatic renewal (using Kvarn's excellent extension system) when the JWT has
expired. The credentials cookie is encrypted to avoid XSS attacks stealing the user's password,
which the user probably reused on other websites; this is an effort to help users.

You can enable [`Builder::with_force_relog_on_ip_change`] to make any cookie stealing useless.
We embed the user's IP in the JWT and credentials and only allow them if the IP is the same.
This may be annoying for the users (especially if your user-base is predominantly on mobile),
but greatly decreases the risk of account theft. So probably use it for banking :)

```rust
# use kvarn::prelude::*;
// please use a strong random secret (>1024bits of entropy to be safe)
let secret = b"this secret protects all the JWTs and the credentials".to_vec();
let mut accounts: HashMap<String, String> = HashMap::new();
accounts.insert("icelk".into(), "password".into());
let auth_config = kvarn_auth::Builder::new()
    // the authentication's scope is limited to routes starting with `/demo/`.
    .with_cookie_path("/demo/")
    .with_auth_page_name("/demo/auth")
    // according to Kvarn's internal redirects, `/demo/login.` is shorthand for `/demo/login.html`
    .with_show_auth_page_when_unauthorized("/demo/login.")
    .build::<(), _, _>(
        move |user, password, _addr, _req| {
            let v = if accounts.get(user).map_or(false, |pass| pass == password) {
                kvarn_auth::Validation::Authorized(kvarn_auth::AuthData::None)
            } else {
                kvarn_auth::Validation::Unauthorized
            };
            core::future::ready(v)
        },
        kvarn_auth::CryptoAlgo::EcdsaP256 { secret },
    );

let mut extensions = kvarn::Extensions::new();

auth_config.mount(&mut extensions);
let login_status = auth_config.login_status();

extensions.add_prepare_single(
    "/demo/api",
    prepare!(
    req,
    host,
    _path,
    addr,
    move |login_status: kvarn_auth::LoginStatusClosure<()>| {
        let auth_data =
            if let kvarn_auth::Validation::Authorized(ad) =
                login_status(req, addr)
        {
            ad
        } else {
            return default_error_response(
                StatusCode::UNAUTHORIZED,
                host,
                Some("log in at `/demo/login.html`"),
            )
            .await;
        };
        // continue with your API, with a guarantee
        FatResponse::no_cache(Response::new(Bytes::new()))
    }),
);
```
