//!
//! Keystore implementation for bbjwt.
//!
//! This file implements handling of Json Web Keys (JWK) and Json Web Keysets (JWKS).
//! It is named *keystore* since on top of JWKS functionality it also provides loading keys
//! from a URL.
//!
//! Keys might have an expiration time; while this implementation supports updating
//! expired keys by reloading them from the original URL, it does not provide cron-like
//! functionality, so the user is responsible to call this update entry point at certain
//! intervals.
//!
//! Author: Markus Thielen <markus.thielen@basebox.tech>
//!
//! Copyright (c) 2022 basebox GmbH, all rights reserved.
//!
//! License: MIT
//!

/* --- uses ------------------------------------------------------------------------------------- */

use std::time::{Duration, SystemTime};
use crate::errors::*;

extern crate base64;
extern crate openssl;
extern crate serde;
extern crate serde_json;


/* --- types ------------------------------------------------------------------------------------ */

///
/// JWK key type enum
///
pub enum KeyType {
  RSA,
}

///
/// Key algorithms
///
pub enum KeyAlgorithm {
  RSA256,
}

///
/// JSON web key
///
/// For a description of the members, see [RFC7517](https://www.rfc-editor.org/rfc/rfc7517).
///
#[derive(Clone, Debug, Deserialize)]
pub struct JWK {
  kty: KeyType,
  alg: Option<KeyAlgorithm>,
  kid: Option<String>,
  n: String,
  e: String,
}

///
/// JWK key store.
///
/// This is basically a thin wrapper around JSON web key sets that adds loading/updating
/// functionality.
///
pub struct KeyStore {
  /// List of keys in this store.
  /// Because the the `kid` field of JWKs is optional, this is a vector rather than a map.
  /// I naively assume that we do not need an index, since I do not expect many keys in the store.
  keys: Vec<JWK>,
  /// The URL the key set is loaded from.
  url: String,
  /// The time the keys were last loaded from `url`.
  load_time: Option<SystemTime>,
  /// Refresh interval factor; if .7, keys are considered expired if 70% of their lifetime is over
  refresh_interval: f64,
  /// Expiration time.
  expire_time: Option<SystemTime>,
}


impl Keystore {

  ///
  /// Return current keyset.
  ///
  pub fn keyset(&self) -> &Vec<JWK> {
    return &self.keys;
  }

  ///
  /// Load/update keys from the keystore URL.
  ///
  pub async fn load_keys(&mut self) -> BBResult<()> {
    let mut response = reqwest::get(&self.url)
      .await
      .map_err(|e| {
        BBError::Other(format!("Failed to load IdP keyset: {:?}", e))
      })?;

    let load_time = SystemTime::now();
    let mut expire_time: Option<SystemTime> = None;

    /* get expiration time from cache-control HTTP header field */
    if let Ok(value) = KeyStore::cache_max_age(&mut response) {
      expire_time = Some(load_time + Duration::new(value, 0));
    }

    let json = response
      .text()
      .await?;

    self.keyset = JwkSet::from_bytes(
      response
        .bytes()
        .await
        .map_err(|e| BBError::Other(format!("Failed to read keyset response: {}", e)))?
    )
      .map_err(|e| BBError::Other(format!("Failed to read IdP keyset: {:?}", e)))?;

    Ok(())

  }

}
