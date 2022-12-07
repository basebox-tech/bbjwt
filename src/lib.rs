//!
//! JWT validation library for [basebox](https://basebox.tech) (and maybe others :-) )
//!
//! # Synopsis
//!
//! This lib was created to provide a straight forward, simple and reliable way to validate
//! JWTs against a set of public keys loaded from a URL.
//! We at [basebox](https://basebox.tech) use it to validate OpenID Connect ID Tokens (which are JWTs)
//! using the set of public keys published by the OpenID server (e.g. Keycloak).
//!
//! It provides the following features:
//!
//! * Download a set of public keys from a URL (a [JSON Web Key Set](https://connect2id.com/products/server/docs/config/jwk-set))
//! * Provide an entry point to update the keyset if necessary
//! * Parse JWTs and validate them using the key(s) in the downloaded keyset.
//!
//! And that's it.
//!
//! ## Building
//!
//! bbjwt uses the openssl crate, so OpenSSL development libraries are required to build bbjwt. See
//! the [openssl crate's](https://docs.rs/openssl/latest/openssl/) documentation for details.
//!
//! ## Why yet another Rust JWT validation lib?
//!
//! We tried various other Rust JWT libraries, but none worked for us. Problems were complicated
//! APIs, lacking documentation and/or functionality. This is our attempt at doing better :-)
//!
//! ## Usage
//!
//! See the following example:
//!
//! ```rust,no_run
//! use bbjwt::KeyStore;
//!
//! #[tokio::main]
//! async fn main() {
//!   // We need a public key to validate JWTs. These can usually be loaded from a URL provided
//!   // by the server that issues the JWT; In OpenID Connect, this URL is called
//!   // "discovery endpoint".
//!
//!   // If you are using Keycloak, you can use this convenience function to get the discovery
//!   // endpoint URL; all you need is the base URL and the realm name:
//!   let discovery_url = KeyStore::keycloak_discovery_url(
//!     "https://server.tld", "testing"
//!   ).unwrap();
//!
//!   // If you're not using Keycloak, the URL might be different.
//!   let discovery_url = "https://idp-host.tld/.well-known/discovery";
//!
//!   // Assuming an OpenID Connect server, we call its discovery endpoint to query the keyset URL
//!   let keyset_url = KeyStore::idp_certs_url(discovery_url).await.unwrap();
//!
//!   // Now we can load the keys:
//!   let keystore = KeyStore::new(Some(&keyset_url)).await.unwrap();
//!
//!   // You can also load public keys from memory like this:
//!   let mut keystore = KeyStore::new(None).await.unwrap();
//!
//!   // Read public keys from a buffer; this must be a JWK in JSON syntax; for example
//!   // https://openid.net/specs/draft-jones-json-web-key-03.html#ExampleJWK
//!   let key = r#"
//!   {
//!     "kty":"RSA",
//!     "use":"sig",
//!     ... abbreviated ...",
//!   }"#;
//!   // Add the key
//!   keystore.add_key(key);
//! }
//! ```
//!
//!
//! Copyright (c) 2022 basebox GmbH, all rights reserved.
//!
//! License: MIT
//!
//! Made with ❤️ and Emacs :-)
//!

/* --- uses ------------------------------------------------------------------------------------- */

#[macro_use]
extern crate serde_derive;

pub use keystore::KeyStore;


/* --- mods ------------------------------------------------------------------------------------- */

pub mod keystore;
pub mod errors;


/* --- types ------------------------------------------------------------------------------------ */




/* --- start of code ---------------------------------------------------------------------------- */


pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
