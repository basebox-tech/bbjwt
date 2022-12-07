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
//! Besides, we designed bbjwt to meet the following requirements:
//!
//! * No unsecure code
//! * Never panic
//! * No lifetime specifiers in the API
//! * Asynchronous
//! * Thread safe
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
//! To validate JWTs, you have to have the issuer's public keys available. Using bbjwt, you can
//! get them either by downloading them from a URL provided by the issuer, or you load them from
//! a local buffer/file.
//!
//! ### Download public keys from a URL
//!
//! See the following example:
//!
//! ```rust,no_run
//! use bbjwt::KeyStore;
//!
//! #[tokio::main]
//! async fn main() {
//!
//!   // bbjwt provides a function to determine the public keyset URL by loading discovery
//!   // info from the issuer; this is common for OpenID Connect servers.
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
//!   // Now we can load the keys into a new KeyStore:
//!   let keystore = KeyStore::new_from_url(&keyset_url).await.unwrap();
//! }
//! ```
//!
//! ### Using public keys from memory
//!
//! This example loads the keys from a local buffer.
//!
//! ```rust,no_run
//! use bbjwt::KeyStore;
//!
//! #[tokio::main]
//! async fn main() {
//!   // Create an empty keystore
//!   let mut keystore = KeyStore::new().await.unwrap();
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
//!
//!   // You can add more keys; in this case, the keys should have an ID and the JWT to be
//!   // validated should have a "kid" claim. Otherwise, bbjwt uses the first key in the set.
//! }
//! ```
//!
//! ### Validating JWTs
//!
//! JWTs are passed as Base64 encoded strings; for details about this format, see e.g. <https://jwt.io>.
//!
//! ```rust,no_run
//! use bbjwt::KeyStore;
//!
//! #[tokio::main]
//! async fn main() {
//!   // Create a keystore; see examples above
//!   let keystore = KeyStore::new_from_url("https://server.tld/keyset").await.unwrap();
//!
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
use errors::{BBResult, BBError};


/* --- mods ------------------------------------------------------------------------------------- */

pub mod keystore;
pub mod errors;


/* --- types ------------------------------------------------------------------------------------ */

///
/// Enumeration of validation steps that are checked during validation.
///
/// A validation step basically means that a specific claim has to be present and, optionally,
/// has to have a certain value.
///
/// For a list of claims see <https://www.iana.org/assignments/jwt/jwt.xhtml#claims>.
///
pub enum ValidationStep {
  /// The signature must be valid.
  Signature,
  /// "iss" claim must have certain String value.
  Issuer(String),
  /// "aud" claim must have certain String value.
  Audience(String),
  /// "nonce" claim must have certain String value.
  Nonce(String),
  /// "exp" claim must contain a time stamp in the future.
  NotExpired,
  /// "sub" claim must be present and non-empty.
  HasSubject,
  /// "roles" claim must be present and non-empty.
  HasRoles,
  /// "groups" claim must be present and non-empty.
  HasGroups,
  /// "entitlements" claim must be present and non-empty.
  HasEntitlements,
  /// "email" claim must be present and non-empty.
  HasEmail
}

///
/// All claims defined in a JWT.
///
/// This is created and returned to the caller upon successful validation.
///
pub struct TokenClaims {

}



/* --- start of code ---------------------------------------------------------------------------- */

///
/// Return a default set of validation steps.
///
/// The validation steps returned by this function match the recommendations for OpenID Connect
/// ID tokens, as outlined in the
/// [OpenID Connect spec](https://openid.net/specs/openid-connect-core-1_0.html).
///
/// If using the Implicit Flow, verifying the Nonce value is mandatory. For Authorization code flow,
/// the list is very [long](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
///
/// # Arguments
///
/// `issuer` - the contents the "iss" claim must have
/// `audience` - if Some, the value the "aud" claim must have
/// `nonce` - if Some, the value the "nonce" claim must have
///
/// # Returns
///
/// A vector of ValidationStep variants that can be passed into the [`validate_jwt`] function.
///
pub fn default_validations(
  issuer: &str,
  audience: Option<&str>,
  nonce: Option<&str>
) -> Vec<ValidationStep> {
  /* Create vector of bare minimum validations */
  let mut validations = vec![
    ValidationStep::Signature,
    ValidationStep::Issuer(issuer.to_string()),
    ValidationStep::NotExpired,
  ];

  if audience.is_some() {
    validations.push(ValidationStep::Audience(audience.unwrap().to_string()));
  }
  if nonce.is_some() {
    validations.push(ValidationStep::Nonce(nonce.unwrap().to_string()));
  }

  validations
}

///
/// Validate a JWT.
///
/// # Arguments
///
/// * `jwt` - Base64 encoded JWT to validate
/// * `validation_steps` - what to validate
/// * `keystore` - the keystore containing public keys to verify the JWT's signature.
///
/// # Returns
///
/// All claims found in the JWT on success.
///
pub async fn validate_jwt(
  jwt: &str,
  validation_steps: &Vec<ValidationStep>,
  keystore: &KeyStore) -> BBResult<TokenClaims> {

  Err(BBError::Other("Not implemented yet :-)".to_string()))
}
