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

use std::collections::HashMap;

use serde::de::{DeserializeOwned};
use base64;
use keystore::base64_config;

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
/// Note that this enum does not contain a `Signature` variant as the signature is always verified.
///
pub enum ValidationStep {
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
pub struct JWTClaims {
  /// JOSE header fields of the JWTs, see [RFC7519](https://www.rfc-editor.org/rfc/rfc7519#section-5)
  headers: HashMap<String, String>,
  /// Claims (fields) found in the JWT. What fields are present depends on the purpose of
  /// the JWT. For OpenID Connect ID tokens see
  /// [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
  claims: HashMap<String, String>
}


///
/// JOSE header struct with all fields relevant to us.
///
/// This is the first of 3 parts of a JWT, the others being claims and signature.
/// See <https://www.rfc-editor.org/rfc/rfc7515#section-4>.
///
/// **Important**: For now, bbjwt ignores the `jku` and `jwk` parameters since in my opinion,
/// signing a data structure and including the public key to verify it in the same data structure
/// is completely pointless.
/// Instead, the public keys have to come from a trusted, different source. The trust comes from
/// verifying the `iss` field of the header.
/// I have no idea if `jku` and/or `jwk` fields are actually being used...
///
#[derive(Deserialize)]
struct JOSEHeader {
  /// Algorithm
  alg: String,
  /// ID of the public key used to sign this JWT
  kid: Option<String>,
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
pub fn default_validations(issuer: &str,
                           audience: Option<&str>,
                           nonce: Option<&str>) -> Vec<ValidationStep> {

  /* Create vector of bare minimum validations */
  let mut validations = vec![
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
/// This function decodes the token string (base64), decrypts it (if applicable) and
/// then validates it.
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
pub async fn validate_jwt(jwt: &str,
                          validation_steps: &Vec<ValidationStep>,
                          keystore: &KeyStore) -> BBResult<JWTClaims> {

  /* A JWT is a Base64 encoded string with 3 parts separated by dots:
   * HEADER.CLAIMS.SIGNATURE */
  let parts: Vec<&str> = jwt.splitn(3, '.').collect();
  if parts.len() != 3 {
    return Err(BBError::TokenInvalid("Could not split token in 3 parts.".to_string()));
  }

  /* Get the JOSE header */
  let kid_hdr: JOSEHeader = deserialize_b64(parts[0])?;

  /* get public key for signature validation */
  let pubkey = keystore.key_by_id(kid_hdr.kid.as_deref())?;

  /* First, we verify the signature. */

  for step in validation_steps {
    match step {
      ValidationStep::Audience(aud) => {

      },

      ValidationStep::HasEmail => {

      }
      ValidationStep::Issuer(iss) => todo!(),
      ValidationStep::Nonce(nonce) => todo!(),
      ValidationStep::NotExpired => todo!(),
      ValidationStep::HasSubject => todo!(),
      ValidationStep::HasRoles => todo!(),
      ValidationStep::HasGroups => todo!(),
      ValidationStep::HasEntitlements => todo!(),
    }
  }

  Err(BBError::Other("Not implemented yet :-)".to_string()))
}

///
/// Base64 decode a string and deserialize it using serde_json.
///
/// # Arguments
///
/// `b64` - base64 encoded JSON string; a JOSE header maybe.
///
fn deserialize_b64<T: DeserializeOwned>(b64: &str) -> BBResult<T> {
  /* decode base64 */
  let json = base64::decode_config(b64, base64_config())
    .map_err(|e| BBError::DecodeError(format!("Failed to decode JWT: {:?}", e)))?;
  /* deserialize JSON string */
  serde_json::from_slice(&json)
    .map_err(|e| BBError::JSONError(format!("{:?}", e)))
}
