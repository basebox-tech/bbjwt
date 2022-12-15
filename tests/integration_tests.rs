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
use bbjwt::keystore::{KeyAlgorithm, EcCurve};
use std::fs::File;
use std::io::Read;

const ISS: &str = "https://kc.basebox.health/realms/testing";

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
    &load_asset("rsa.pub.key"),
    Some("key-1"),
    KeyAlgorithm::RS256)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_rsa256.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .expect("Valid JWT did not validate");
}


///
/// Validate RSA256 JWT with wrong key, must panic.
///
#[tokio::test]
#[should_panic(expected = "SignatureInvalid")]
async fn rsa256_invalid_key() {
  let wrong_key = "-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBpqqxgRe8ugvp6+LsNMood
VX7c+hb58VG23Q7pZMhhoMTU4fE/sgCCE361GuH4xbfkg2/nf2LiMD5qaq6L5U5I
O4ycVtFTYSXMDHQVKB8BB8ZZpL7tx1S4kzaycClmDzSmTibIpNVdQmxNTrH2GHak
jk9+z6rSusYbYPOd3MSP1SakWcN6wv2j1hNMPrp7SZ98ST0CTuRCx01e9fSW5jP9
XJrW2WwcQAk9XkTDG0/hZ6Owxt4lMaXfXvVflvSeWhR/ucuZd5HomvI+taxg1OvA
MN6hu6FOYmhMPDLa9pv4MacbIxAnYyHcKnQPC6xvIWcEemZm9uZDEtqk7QigKd7r
AgMBAAE=
-----END PUBLIC KEY-----";

  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(
    wrong_key,
    Some("key-1"),
    KeyAlgorithm::RS256)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_rsa256.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
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
    &load_asset("rsa.pub.key"),
    Some("key-1"),
    KeyAlgorithm::RS256)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify expired token, must fail */
  let jwt = load_asset("id_token_rsa256_expired.txt");
  let ret = validate_jwt(
    &jwt,
    &default_validations("https://kc.basebox.health/realms/WRONG", None, None),
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
    &load_asset("rsa.pub.key"),
    Some("key-1"),
    KeyAlgorithm::RS256)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify expired token, must fail */
  let jwt = load_asset("id_token_rsa256_expired.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .unwrap();

}

///
/// Validate valid RSA384 JWT.
///
#[tokio::test]
async fn rsa384_valid_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(
    &load_asset("rsa.pub.key"),
    Some("key-1"),
    KeyAlgorithm::RS384)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_rsa384.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .expect("Valid JWT did not validate");
}

///
/// Validate valid RSA512 JWT.
///
#[tokio::test]
async fn rsa512_valid_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(
    &load_asset("rsa.pub.key"),
    Some("key-1"),
    KeyAlgorithm::RS512)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_rsa512.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .expect("Valid JWT did not validate");
}


///
/// Validate valid ES256 JWT.
///
#[tokio::test]
async fn es256_valid_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec256.pub.key"),
    Some("key-1"),
    EcCurve::P256)
    .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es256.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .expect("Valid JWT did not validate");
}


///
/// Validate expired ES256 JWT; must panic
///
#[tokio::test]
#[should_panic(expected = "expired")]
async fn es256_expired_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec256.pub.key"),
    Some("key-1"),
    EcCurve::P256)
    .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es256_expired.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .unwrap();
}

///
/// Validate expired ES256 JWT; must panic
///
#[tokio::test]
#[should_panic(expected = "SignatureInvalid")]
async fn es256_signature_invalid_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec256.pub.key"),
    Some("key-1"),
    EcCurve::P256)
    .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es256_signature_invalid.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .unwrap();
}


///
/// Validate ES384
///
#[tokio::test]
async fn es384_valid_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec384.pub.key"),
    Some("key-1"),
    EcCurve::P384)
    .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es384.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .expect("Valid ES384 JWT did not validate");
}

///
/// Validate ES384 with wrong ISS; must panic
///
#[tokio::test]
#[should_panic(expected = "iss")]
async fn es384_iss_wrong() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec384.pub.key"),
    Some("key-1"),
    EcCurve::P384)
    .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es384.txt");
  validate_jwt(
    &jwt,
    &default_validations("wrong_iss", None, None),
    &ks
  )
  .await
  .unwrap();
}

///
/// Validate ES512
///
#[tokio::test]
async fn es512_valid_jwt() {

  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec384.pub.key"),
    Some("key-1"),
    EcCurve::P521)
    .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es512.txt");
  validate_jwt(
    &jwt,
    &default_validations(ISS, None, None),
    &ks
  )
  .await
  .expect("Valid ES512 JWT did not validate");
}

