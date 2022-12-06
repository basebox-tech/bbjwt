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
//! Some parts of this code inspired/taken from [jwksclient2](https://github.com/ammarzuberi/jwksclient2).
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
use url::Url;

extern crate base64;
extern crate openssl;
extern crate serde;
extern crate serde_json;

/* --- constants -------------------------------------------------------------------------------- */

/// Refresh interval factor; the lifetime of keys etc. is multiplied with this factor
/// to determine the point in time after which the information is considered outdated.
pub const REFRESH_INTERVAL_FACTOR: f64 = 0.75;


/* --- types ------------------------------------------------------------------b------------------ */

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
  /// Key type; see [here](https://www.rfc-editor.org/rfc/rfc7517#section-4.1)
  pub kty: KeyType,
  /// Algorithm; see [here](https://www.rfc-editor.org/rfc/rfc7517#section-4.4)
  pub alg: Option<KeyAlgorithm>,
  /// Key id; see [here](https://www.rfc-editor.org/rfc/rfc7517#section-4.5)
  pub kid: Option<String>,
  /// RSA modules; see [here](https://www.rfc-editor.org/rfc/rfc7517#section-9.3)
  pub n: String,
  /// RSA exponent
  pub e: String,
}

///
/// JSON Web Key Set
///
#[derive(Clone, Debug, Deserialize)]
pub struct JWKS {
  pub keys: Vec<JWK>
}

///
/// JWK key store.
///
/// This is basically a thin wrapper around JSON web key sets that adds loading/updating
/// functionality.
///
#[derive(Debug)]
pub struct KeyStore {
  /// List of keys in this store.
  keyset: JWKS,
  /// The URL the key set is loaded from.
  url: Option<String>,
  /// The time the keys were last loaded from `url`.
  load_time: Option<SystemTime>,
  /// Refresh interval factor; if .7, keys are considered expired if 70% of their lifetime is over
  refresh_interval: f64,
  /// Expiration time.
  expire_time: Option<SystemTime>,
}


impl JWKS {

  ///
  /// Create new empty keyset.
  ///
  pub fn new() -> Self {
    return JWKS {
      keys: vec![]
    }
  }

}


#[allow(dead_code)]
impl KeyStore {

  ///
  /// Create new keyset.
  ///
  /// If `url` is some, keys will be loaded from this URL; otherwise, the returned
  /// keystore will have an empty keyset.
  ///
  /// # Arguments
  ///
  /// `url`: optional URL to load the keys from.
  ///
  pub async fn new(url: Option<&str>) -> BBResult<Self> {
    let mut ks = KeyStore {
      keyset: JWKS::new(),
      url: url.map(String::from),
      load_time: None,
      refresh_interval: REFRESH_INTERVAL_FACTOR,
      expire_time: None,
    };

    /* load keys from URL if applicable */
    if url.is_some() {
      ks.load_keys().await?;
    }

   Ok(ks)
  }

  ///
  /// Return current keyset.
  ///
  pub fn keyset(&self) -> &JWKS {
    return &self.keyset;
  }

  ///
  /// Number of keys in keystore.
  ///
  pub fn keys_len(&self) -> usize {
    self.keyset.keys.len()
  }

  ///
  /// Manually add a key to the keystore.
  ///
  /// # Arguments
  /// `key_json` - JWT string; a JSON string containing a key.
  ///
  pub fn add_key(&mut self, key_json: &str) -> BBResult<()> {
    let key = serde_json::from_str(key_json)
      .map_err(|e| {
        BBError::Other(format!("Failed to parse key JSON: {:?}", e))
      })?;
    self.keyset.keys.push(key);
    Ok(())
  }

  ///
  /// Retrieve a key by id.
  ///
  /// The `kid` claim is optional, so the keyset may contain keys without id.
  /// This is why the `kid` argument to this function is optional, too. If it is
  /// None, we use the first key, assuming that there is only one. This
  /// complies to the rules set by the OpenID Connect spec, defined
  /// [here](https://openid.net/specs/openid-connect-core-1_0.html#SigEnc)
  ///
  /// # Arguments
  /// `kid` - the ID of the key. If None, the first key is returned.
  ///
  pub fn key_by_id(&self, kid: Option<&str>) -> BBResult<JWK> {

    let key = if kid.is_none() {
      /* return first key in set */
      self.keyset.keys.first().ok_or_else(|| {
        BBError::Other("No keys in keyset".to_string())
      })?
    } else {
      /* return key with specific ID */
      let kid = kid.unwrap();
      let key = self.keyset.keys.iter().find(|k: &&JWK| {
        if let Some(this_kid) = &k.kid {
          return this_kid.eq(kid);
        } else {
          return false;
        }
      });
      key.ok_or_else(|| BBError::Other(format!("Could not find kid '{}' in keyset.", kid)))?
    };

    Ok(key.clone())
  }

  ///
  /// Specify the interval (as a fraction) when the key store should refresh it's key.
  ///
  /// The default is 0.75, meaning that keys should be refreshed when we are 3/4 through
  /// the expiration time (similar to DHCP).
  ///
  /// This method does **not** update the refresh time. Call `load_keys` to force an update on
  /// the refresh time property.
  pub fn set_refresh_interval(&mut self, interval: f64) {
    self.refresh_interval = interval;
  }

  ///
  /// Get the current fraction time to check for token refresh time.
  ///
  pub fn refresh_interval(&self) -> f64 {
    self.refresh_interval
  }


  ///
  /// Load/update keys from the keystore URL.
  ///
  pub async fn load_keys(&mut self) -> BBResult<()> {
    let url = self.url
      .clone()
      .ok_or_else(|| BBError::Other("No load URL for keyset provided.".to_string()))?;
    let mut response = reqwest::get(&url)
      .await
      .map_err(|e| {
        BBError::Other(format!("Failed to load IdP keyset: {:?}", e))
      })?;

    /* get expiration/life time from cache-control HTTP header field */
    let lifetime = KeyStore::get_key_expiration_time(&mut response);

    /* load JWKS from URL */
    let json = response
      .text()
      .await
      .map_err(|e| BBError::NetworkError(format!("Failed to load public key set: {:?}", e)))?;

    /* deserialize JSON into our JWKS struct */
    self.keyset = serde_json::from_str(&json)
      .map_err(|e| BBError::Other(format!("Failed to parse IdP public key set: {:?}", e)))?;

    /* update load time and expiration time */
    let load_time = SystemTime::now();
    if let Ok(value) = lifetime {
      let seconds: u64 = (value as f64 * self.refresh_interval) as u64;
      self.expire_time = Some(load_time + Duration::new(seconds, 0));
    }

    if self.load_time.is_none() {
      self.load_time = Some(load_time);
    }

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


  ///
  /// Construct Keycloak specific discovery URL from a host and realm name.
  ///
  /// Provided for convenience :-)
  ///
  /// # Arguments
  ///
  /// `host` - protocol and host name of the Keycloak server, e.g. "https://idp.domain.tld"
  /// `realm` - the realm name
  ///
  /// # Returns
  ///
  /// URL of discovery endpoint.
  ///
  pub fn keycloak_discovery_url(host: &str, realm: &str) -> BBResult<String> {
    let mut info_url = Url::parse(host).map_err(|e| {
      BBError::Other(format!("Invalid base URL for Keycloak discovery endpoint: {:?}", e))
    })?;

    /* Discovery info URL is built like this:
     * https://<host>/realms/<realm_name>/.well-known/openid-configuration
     */
    info_url
      .path_segments_mut()
      .map_err(|_| {
        BBError::Other(format!("Invalid IdP URL '{}'", host))
      })?
      .push("realms")
      .push(realm)
      .push(".well-known")
      .push("openid-configuration");

    Ok(info_url.to_string())

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
  use std::env;
  use std::path::Path;
  use rand::seq::SliceRandom;
  use std::fs::File;
  use std::io::Read;


  /// Seconds since UNIX_EPOCH in the very far future (~1000 years)
  const NEVER_SECONDS: u64 = 33206263475;

  ///
  /// Utility function that returns the absolute path and file name to a file in the /tests/assets folder.
  ///
  /// This is copied from tests::bb_common; unfortunately, I do not know how to import/use code from there.
  ///
  /// # Arguments
  ///
  /// `asset_name` - path and file name of the file, relative to the "assets" folder.
  ///
  /// # Returns
  ///
  /// Absolute path to the asset file.
  ///
  pub fn path_to_asset_file(asset_name: &str) -> String {
    let path = Path::new(env::var("CARGO_MANIFEST_DIR")
      .expect("CARGO_MANIFEST_DIR not set").as_str()
    ).join(format!("tests/assets/{}", asset_name));

    String::from(path.to_str().unwrap())
  }


  #[test]
  ///
  /// Test for `keycloak_discovery_url`
  ///
  fn test_keycloak_discovery_url() {
    /* Very simple, if not pathetic, test. Runs without accessing any keycloak instance :-) */
    let url = KeyStore::keycloak_discovery_url("https://host.tld", "testing");
    assert_eq!(url.unwrap(), "https://host.tld/realms/testing/.well-known/openid-configuration")
  }

  ///
  /// Test for `assigned_header_value` function
  ///
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

  ///
  /// Test keystore without loading from URL.
  ///
  #[tokio::test]
  async fn test_keystore_local() {
    /* create empty keystore */
    let mut ks = KeyStore::new(None).await.expect("Failed to create empty keystore");

    /* load a key from a local JSON file */
    let key_json_file = path_to_asset_file("pubkey.json");
    let mut file = File::open(key_json_file).expect("Failed to open pubkey.json");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    /* add key to store 20 times */
    for i in 1..21 {
      /* add keys with patched kid */
      ks.add_key(
        &data.replace("nOo3ZDrODXEK1jKWhXslHR_KXEg",
                      format!("bbjwt-test-{}", i).as_str()))
        .expect("Failed to add key to keystore");
    }

    assert_eq!(ks.keys_len(), 20);

    /* get first key */
    let key1 = ks.key_by_id(None).expect("Failed to get key just added");
    assert!(key1.kid.unwrap() == "bbjwt-test-1");

    /* get some other key */
    let k = ks.key_by_id(Some("bbjwt-test-17")).expect("Failed to get key by ID");
    assert_eq!(k.kid.unwrap(), "bbjwt-test-17");

  }


  ///
  /// Test loading keys from a URL.
  ///
  #[tokio::test]
  async fn test_load_keys() {
    /* ask Microsoft for the location of their public key store :-) */
    let url = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
    let ks_url = KeyStore::idp_certs_url(url).await.expect("Failed to get keyset URL");

    /* Test load keyset from URL */
    let ks = KeyStore::new(Some(&ks_url)).await.expect("Failed to load keystore");

    /* test for expiration time */
    assert!(ks.load_time.is_some());
    assert!(ks.expire_time.is_some());
    assert!(ks.expire_time.unwrap() > ks.load_time.unwrap());

    println!("KeyStore: {:?}", ks);

    /* Test keys length; should be > 0 */
    assert!(ks.keys_len() > 0);

    /* get a random key from the keyset */
    let key = ks.keyset().keys.choose(&mut rand::thread_rng()).expect("Failed to get random key from keyset");
    /* get its key id and try to get it from the store by key id */
    let kid = key.kid.clone().expect("No kid in key; not an error, but spoils this test...");
    let k = ks.key_by_id(Some(&kid)).expect("Failed to get key by id");
    assert_eq!(k.kid.expect("Missing kid"), kid);

    /* get the first key */
    let k1 = ks.keyset().keys.first().expect("Failed to get first key").clone();

    /* get key without id; must return the first/something */
    let k = ks.key_by_id(None).expect("No key returned without kid");
    /* kid must match the kid of the first key */
    assert_eq!(k.kid.unwrap().as_str(), k1.kid.unwrap().as_str());
  }

}
