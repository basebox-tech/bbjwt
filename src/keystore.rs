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
#[derive(Clone, Debug, Deserialize)]
pub enum KeyType {
  RSA,
}

///
/// Key algorithms
///
#[derive(Clone, Debug, Deserialize)]
pub enum KeyAlgorithm {
  RSA256,
}

///
/// JSON web key
///
/// For a description of the members, see [RFC7517](https://www.rfc-editor.org/rfc/rfc7517).
///
#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct JWK {
  kty: KeyType,
  alg: Option<KeyAlgorithm>,
  kid: Option<String>,
  n: String,
  e: String,
}

///
/// JSON Web Key Set
///
#[derive(Clone, Debug, Deserialize)]
pub struct JWKS {
  keys: Vec<JWK>
}

///
/// JWK key store.
///
/// This is basically a thin wrapper around JSON web key sets that adds loading/updating
/// functionality.
///
pub struct KeyStore {
  /// List of keys in this store.
  keys: JWKS,
  /// The URL the key set is loaded from.
  url: String,
  /// The time the keys were last loaded from `url`.
  load_time: Option<SystemTime>,
  /// Refresh interval factor; if .7, keys are considered expired if 70% of their lifetime is over
  refresh_interval: f64,
  /// Expiration time.
  expire_time: Option<SystemTime>,
}

#[allow(dead_code)]
impl KeyStore {

  ///
  /// Return current keyset.
  ///
  pub fn keyset(&self) -> &JWKS {
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
    if let Ok(value) = KeyStore::get_key_expiration_time(&mut response) {
      expire_time = Some(load_time + Duration::new(value, 0));
    }

    /* load JWKS from URL */
    let json = response
      .text()
      .await
      .map_err(|e| BBError::NetworkError(format!("Failed to load public key set: {:?}", e)))?;

    /* deserialize JSON into our JWKS struct */
    let jwks: JWKS = serde_json::from_str(&json)
      .map_err(|e| BBError::Other(format!("Failed to parse IdP public key set: {:?}", e)))?;




    Ok(())

  }

  ///
  /// Get key expiration time from the cache-control HTTP header.
  ///
  /// # Arguments
  ///
  /// `response` - response to read the cache-control HTTP header from
  ///
  fn get_key_expiration_time(response: &mut reqwest::Response) -> Result<u64, ()> {
    let header = response.headers().get("cache-control").ok_or(())?;
    let cache_control = header.to_str().map_err(|_| ())?.to_lowercase();
    assigned_header_value(&cache_control, "max-age")
  }

  ///
  /// Determine the URL where public keys can be loaded.
  ///
  /// OpenID Connect IdPs provide an info endpoint called OpenID Connect Discovery that
  /// returns, among other info, the URL where the IdP's public keys (JWKS) are downloadable.
  /// These public keys are used to validate ID Tokens (i.e. JWTs) issued by this IdP.
  ///
  /// This function returns the public keys URL read from the discovery endpoint.
  ///
  /// OpenID Connect providers might use different schemas for this URL; for Keycloak, the URL
  /// is built like this:
  ///
  /// `https://host.tld/realms/<realm_name>/.well-known/openid-configuration`
  ///
  /// # Arguments
  /// `idp_discovery_url` - the URL to load the discovery info from.
  ///
  ///
  pub async fn idp_certs_url(idp_discovery_url: &str) -> BBResult<String> {
    let info_json = reqwest::get(idp_discovery_url)
      .await
      .map_err(|e| BBError::NetworkError(
        format!("Failed to load IdP discovery info JSON from {}: {:?}",
                idp_discovery_url, e)
      ))?
      .text()
      .await
      .map_err(|e| BBError::NetworkError(format!("Failed to get IdP discovery info JSON: {:?}", e)))?;

    let info: serde_json::Value = serde_json::from_str(&info_json)
      .map_err(|e| {
        BBError::Other(
          format!("Invalid JSON from IdP discovery info url '{}': {:?}", idp_discovery_url, e)
        )
      })?;

    if let serde_json::Value::String(jwks_uri) = &info["jwks_uri"] {
      Ok(jwks_uri.to_string())
    } else {
      Err(BBError::Other("No jwks_uri in IdP discovery info found".to_string()))
    }
  }

}


///
/// Return a numeric value from a HTTP header field with assigned name.
///
/// Example:
///
/// Assuming a `hdr_value` of 'Cache-Control: max-age = 45678,never-die' and `name` = 'max-age',
/// this function returns 45678.
///
/// # Arguments
/// `hdr_value` - the header value (or string) to search for an assigned value
/// `name` - the name to look for before the assignment '='
///
fn assigned_header_value(hdr_value: &str, name: &str) -> Result<u64, ()> {
  /* search name */
  let mut p = hdr_value.find(name).ok_or(())?;
  p += name.len();
  let mut num = String::with_capacity(22); // max byte length of a 64bit number
  let mut got_ass = false;
  let mut chars = hdr_value.get(p..).unwrap().chars();

  while let Some(c) = chars.next() {
    match c {
      '=' => {
        got_ass = true;
      },

      c => {
        if !got_ass {
          continue;
        }

        if c.is_numeric() {
          num.push(c);
        } else {
          if !num.is_empty() {
            /* No digit, but already saw a digit, stop here */
            break;
          }
        }
      }
    }
  }

  if num.is_empty() {
    return Err(())
  }

  let value: u64 = num.parse().map_err(|_| ())?;
  Ok(value)

}



#[cfg(test)]

mod tests {

  use super::*;

  #[test]
  fn test_header_value_parser() {
    let test_strings = vec![
      "oriuehgueohgeor depp = 3485975dd",
      "depp=1,fellow",
      "depp = 22-dude",
      "r depp=12345678",
      "xu depp=666"
    ];
    let results: Vec<u64> = vec![
      3485975,
      1,
      22,
      12345678,
      666
    ];

    /* check a couple of strings */
    for i in 0..test_strings.len() {
      assert!(assigned_header_value(test_strings[i], "depp").unwrap() == results[i]);
    }

    /* nonsense string must return error */
    assert!(assigned_header_value("orihgeorgohoho", "name").is_err());

  }



}
