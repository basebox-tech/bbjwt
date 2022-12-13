///
/// Integration tests for bbjwt.
///
/// Uses `env_logger` to dump information. To see it, you could start tests like this:
///
/// ```sh
/// RUST_LOG=INFO cargo test -- --nocapture
/// ```
///
/// (c) Copyright 2022 by basebox GmbH. All rights reserved.
///

/* --- uses ------------------------------------------------------------------------------------- */

#[macro_use]
pub mod bb_common;

use bb_common::*;
use bbjwt::{KeyStore, validate_jwt, default_validations};
use bbjwt::keystore::KeyAlgorithm;
use std::fs::File;
use std::io::Read;


///
/// Load an asset from a file by its asset name (relative to test/assets/)
///
fn load_asset(name: &str) -> String {
  let pfn = path_to_asset_file(name);
  let mut file = File::open(&pfn).expect(&format!("Failed to open asset {}", &pfn));
  let mut data = String::new();
  file.read_to_string(&mut data).unwrap();
  data
}

///
/// Validate valid RSA256 JWT.
///
#[tokio::test]
async fn rsa256_valid_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(
    &load_asset("rsa256.pub.key"),
    Some("key-rsa256-1"),
    KeyAlgorithm::RS256)
    .expect("Failed to add RSA256 key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_rsa256.txt");
  validate_jwt(
    &jwt,
    &default_validations("https://kcdev.basebox.health:8443/realms/testing", None, None),
    &ks
  )
  .await
  .expect("Valid JWT did not validate");
}


///
/// Validate expired RSA256 JWT with wrong issuer; all errors must be reported.
///
#[tokio::test]
async fn rsa256_invalid_claims_expired_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(
    &load_asset("rsa256.pub.key"),
    Some("key-rsa256-1"),
    KeyAlgorithm::RS256)
    .expect("Failed to add RSA256 key");
  assert_eq!(ks.keys_len(), 1);

  /* verify expired token, must fail */
  let jwt = load_asset("id_token_rsa256_expired.txt");
  let ret = validate_jwt(
    &jwt,
    &default_validations("https://kcdev.basebox.health:8443/realms/WRONG", None, None),
    &ks
  )
  .await;

  if let Err(err) = ret {
    /* all errors must be in the error string */
    let msg = err.to_string();
    assert!(msg.contains("iss"), "iss error not reported");
    assert!(msg.contains("expired"), "expiration not reported");
  } else {
    /* no error */
    panic!("Invalid JWT validated ok!");
  }
}


///
/// Validate expired RSA256 JWT.
///
#[tokio::test]
#[should_panic(expected = "expired")]
async fn rsa256_valid_claims_expired_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(
    &load_asset("rsa256.pub.key"),
    Some("key-rsa256-1"),
    KeyAlgorithm::RS256)
    .expect("Failed to add RSA256 key");
  assert_eq!(ks.keys_len(), 1);

  /* verify expired token, must fail */
  let jwt = load_asset("id_token_rsa256_expired.txt");
  validate_jwt(
    &jwt,
    &default_validations("https://kcdev.basebox.health:8443/realms/testing", None, None),
    &ks
  )
  .await
  .unwrap();

}
