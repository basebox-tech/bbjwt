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
//! Basta (i.e. "that's it").
//!
//! **Note:** As stated above, this lib is part of an [OpenID Connect](https://openid.net/connect/)
//! based authentication system. JWTs created and used by OpenID Connect have slightly different
//! requirements and rules than other JWTs, and this library assumes OpenID Connect JWTs. More info
//! about ID Tokens can be found [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
//!
//! ## Building
//!
//! bbjwt uses the openssl crate, so OpenSSL development libraries are required to build bbjwt. See
//! the [openssl crate's](https://docs.rs/openssl/latest/openssl/) documentation for details.
//!
//! ## Why yet another Rust JWT lib?
//!
//! If you ever had tried to use one of the existing libraries to do JWT validation you probably would
//! not ask this question. In short, the other Rust libraries I have tried are cumbersome to use
//! and lack documentation.
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
