# kvarn-auth

Provides an easy-to-use JWT-based authentication helper. You provide an async callback which gives the user a level of authorization.
You can return any structured data based on serde.
The JWT is automatically renewed, as the server stores a credentials cookie (encrypted using the server's private key).
Everything is configurable.

**⚠️ Warning: This crate has not been audited. All dependencies I use have. Use at your own risk.**

> I do however personally use this for production systems.
