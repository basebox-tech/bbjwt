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

/* --- uses ------------------------------------------------------------------------------------- */

#[macro_use]
pub mod bb_common;

use std::fs::File;
use std::io::Read;

use bb_common::*;
use bbjwt::keystore::{EcCurve, KeyAlgorithm};
use bbjwt::{default_validations, validate_jwt, KeyStore};

const ISS: &str = "https://kc.basebox.health/realms/testing";

///
/// Load an asset from a file by its asset name (relative to test/assets/)
fn load_asset(name: &str) -> String {
  let pfn = path_to_asset_file(name);
  let mut file = File::open(&pfn).expect(&format!("Failed to open asset {}", &pfn));
  let mut data = String::new();
  file.read_to_string(&mut data).unwrap();
  data
}

///
/// Validate a JWT with a correct and a wrong key. Naturally, the latter must fail.
async fn validate_jwt_with_keystores(
  jwt_name: &str,
  keystore_good: &KeyStore,
  keystore_bad: &KeyStore,
) {
  let jwt = load_asset(jwt_name);

  let jwt_decoded = validate_jwt(&jwt, &default_validations(ISS, None, None), keystore_good)
    .await
    .expect("Valid JWT did not validate");

  /* check some claims */
  assert_eq!(jwt_decoded.claims["nonce"].as_str().unwrap(), "UZ1BSZFvy7jKkj1o9p3r7w");
  assert_eq!(jwt_decoded.claims["sub"].as_str().unwrap(), "13529346-91b6-4268-aae1-f5ad8f44cf4d");
  assert_eq!(
    jwt_decoded.claims["iss"].as_str().unwrap(),
    "https://kc.basebox.health/realms/testing"
  );

  /* wrong keystore: must fail */
  let ret = validate_jwt(&jwt, &default_validations(ISS, None, None), keystore_bad).await;
  let err_msg = ret.unwrap_err().to_string();
  assert!(
    err_msg.contains("Invalid signature"),
    "Invalid key check did not fail with signature error."
  );
}

///
/// Validate unsupported algorithm; must panic.
#[tokio::test]
#[should_panic(expected = "Unsupported alg")]
async fn unsupported_alg_jwt() {
  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(&load_asset("rsa.pub.key"), Some("key-1"), KeyAlgorithm::RS256)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_unsupported_alg.txt");
  validate_jwt(&jwt, &default_validations(ISS, None, None), &ks).await.unwrap();
}

///
/// Validate valid RSA256 JWT.
#[tokio::test]
async fn rsa256_valid_jwt() {
  let ks_good = KeyStore::new().await.unwrap();
  ks_good
    .add_rsa_pem_key(&load_asset("rsa.pub.key"), Some("key-1"), KeyAlgorithm::RS256)
    .expect("Failed to add RSA384 key");

  let ks_bad = KeyStore::new().await.unwrap();
  ks_bad
    .add_rsa_pem_key(&load_asset("rsa.wrong.pub.key"), Some("key-1"), KeyAlgorithm::RS256)
    .expect("Failed to add RSA384 key");

  validate_jwt_with_keystores("id_token_rsa256.txt", &ks_good, &ks_bad).await;
}

///
/// Validate expired RSA256 JWT with wrong issuer; all errors must be reported.
#[tokio::test]
async fn rsa256_invalid_claims_expired_jwt() {
  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(&load_asset("rsa.pub.key"), Some("key-1"), KeyAlgorithm::RS256)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify expired token, must fail */
  let jwt = load_asset("id_token_rsa256_expired.txt");
  let ret = validate_jwt(
    &jwt,
    &default_validations("https://kc.basebox.health/realms/WRONG", None, None),
    &ks,
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
#[tokio::test]
#[should_panic(expected = "expired")]
async fn rsa256_valid_claims_expired_jwt() {
  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(&load_asset("rsa.pub.key"), Some("key-1"), KeyAlgorithm::RS256)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify expired token, must fail */
  let jwt = load_asset("id_token_rsa256_expired.txt");
  validate_jwt(&jwt, &default_validations(ISS, None, None), &ks).await.unwrap();
}

///
/// Validate valid RSA384 JWT.
#[tokio::test]
async fn rsa384_valid_jwt() {
  let ks_good = KeyStore::new().await.unwrap();
  ks_good
    .add_rsa_pem_key(&load_asset("rsa.pub.key"), Some("key-1"), KeyAlgorithm::RS384)
    .expect("Failed to add RSA384 key");

  let ks_bad = KeyStore::new().await.unwrap();
  ks_bad
    .add_rsa_pem_key(&load_asset("rsa.wrong.pub.key"), Some("key-1"), KeyAlgorithm::RS384)
    .expect("Failed to add RSA384 key");

  validate_jwt_with_keystores("id_token_rsa384.txt", &ks_good, &ks_bad).await;
}

///
/// Validate valid RSA512 JWT.
#[tokio::test]
async fn rsa512_valid_jwt() {
  let ks = KeyStore::new().await.unwrap();
  ks.add_rsa_pem_key(&load_asset("rsa.pub.key"), Some("key-1"), KeyAlgorithm::RS512)
    .expect("Failed to add RSA key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_rsa512.txt");
  validate_jwt(&jwt, &default_validations(ISS, None, None), &ks)
    .await
    .expect("Valid JWT did not validate");
}

///
/// Validate valid ES256 JWT.
#[tokio::test]
async fn es256_valid_jwt() {
  let ks_good = KeyStore::new().await.unwrap();
  ks_good
    .add_ec_pem_key(&load_asset("ec256.pub.key"), Some("key-1"), EcCurve::P256, KeyAlgorithm::ES256)
    .expect("Failed to add ec256 key");

  let ks_bad = KeyStore::new().await.unwrap();
  ks_bad
    .add_ec_pem_key(
      &load_asset("ec256.wrong.pub.key"),
      Some("key-1"),
      EcCurve::P256,
      KeyAlgorithm::ES256,
    )
    .expect("Failed to add EC256 key");

  validate_jwt_with_keystores("id_token_es256.txt", &ks_good, &ks_bad).await;
}

///
/// Validate expired ES256 JWT; must panic
#[tokio::test]
#[should_panic(expected = "expired")]
async fn es256_expired_jwt() {
  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec256.pub.key"),
    Some("key-1"),
    EcCurve::P256,
    KeyAlgorithm::ES256,
  )
  .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es256_expired.txt");
  validate_jwt(&jwt, &default_validations(ISS, None, None), &ks).await.unwrap();
}

///
/// Validate expired ES256 JWT; must panic
#[tokio::test]
#[should_panic(expected = "SignatureInvalid")]
async fn es256_signature_invalid_jwt() {
  let ks = KeyStore::new().await.unwrap();
  ks.add_ec_pem_key(
    &load_asset("ec256.pub.key"),
    Some("key-1"),
    EcCurve::P256,
    KeyAlgorithm::ES256,
  )
  .expect("Failed to add EC key");
  assert_eq!(ks.keys_len(), 1);

  /* verify valid token */
  let jwt = load_asset("id_token_es256_signature_invalid.txt");
  validate_jwt(&jwt, &default_validations(ISS, None, None), &ks).await.unwrap();
}

///
/// Validate ES384
#[tokio::test]
async fn es384_valid_jwt() {
  let ks_good = KeyStore::new().await.unwrap();
  ks_good
    .add_ec_pem_key(&load_asset("ec384.pub.key"), Some("key-1"), EcCurve::P384, KeyAlgorithm::ES384)
    .expect("Failed to add ec384 key");

  let ks_bad = KeyStore::new().await.unwrap();
  ks_bad
    .add_ec_pem_key(
      &load_asset("ec384.wrong.pub.key"),
      Some("key-1"),
      EcCurve::P384,
      KeyAlgorithm::ES384,
    )
    .expect("Failed to add EC384 key");

  validate_jwt_with_keystores("id_token_es384.txt", &ks_good, &ks_bad).await;
}

///
/// Validate ES512
#[tokio::test]
async fn es512_valid_jwt() {
  let ks_good = KeyStore::new().await.unwrap();
  ks_good
    .add_ec_pem_key(&load_asset("ec512.pub.key"), Some("key-1"), EcCurve::P521, KeyAlgorithm::ES512)
    .expect("Failed to add ec512 key");

  let ks_bad = KeyStore::new().await.unwrap();
  ks_bad
    .add_ec_pem_key(
      &load_asset("ec512.wrong.pub.key"),
      Some("key-1"),
      EcCurve::P521,
      KeyAlgorithm::ES512,
    )
    .expect("Failed to add EC512 key");

  validate_jwt_with_keystores("id_token_es512.txt", &ks_good, &ks_bad).await;
}

///
/// Validate Ed25519
#[tokio::test]
async fn ed25519_valid_jwt() {
  let ks_good = KeyStore::new().await.unwrap();
  ks_good
    .add_ec_pem_key(
      &load_asset("ed25519.pub.key"),
      Some("key-1"),
      EcCurve::Ed25519,
      KeyAlgorithm::EdDSA,
    )
    .expect("Failed to add Ed25519 key");

  let ks_bad = KeyStore::new().await.unwrap();
  ks_bad
    .add_ec_pem_key(
      &load_asset("ed25519.wrong.pub.key"),
      Some("key-1"),
      EcCurve::Ed25519,
      KeyAlgorithm::EdDSA,
    )
    .expect("Failed to add Ed448 key");

  validate_jwt_with_keystores("id_token_ed25519.txt", &ks_good, &ks_bad).await;
}

///
/// Validate Ed448
#[tokio::test]
async fn ed448_valid_jwt() {
  let ks_good = KeyStore::new().await.unwrap();
  ks_good
    .add_ec_pem_key(
      &load_asset("ed448.pub.key"),
      Some("key-1"),
      EcCurve::Ed448,
      KeyAlgorithm::EdDSA,
    )
    .expect("Failed to add Ed448 key");

  let ks_bad = KeyStore::new().await.unwrap();
  ks_bad
    .add_ec_pem_key(
      &load_asset("ed448.wrong.pub.key"),
      Some("key-1"),
      EcCurve::Ed448,
      KeyAlgorithm::EdDSA,
    )
    .expect("Failed to add Ed448 key");

  validate_jwt_with_keystores("id_token_ed448.txt", &ks_good, &ks_bad).await;
}

///
/// Test loading OKP/Ed25519 key from JWK JSON.
#[tokio::test]
async fn load_ed25519_jwk() {
  let mut ks = KeyStore::new().await.unwrap();
  let jwk_json = load_asset("ed25519.pub.jwk.json");
  ks.add_key(&jwk_json).unwrap();

  assert_eq!(ks.keys_len(), 1);

  /* get the key by name */
  ks.key_by_id(Some("key-1")).unwrap();

  /* get key with wrong name, must fail */
  assert!(ks.key_by_id(Some("No-key-with-that-name")).is_err());
}

///
/// Test loading elliptic curve key from JWK JSON.
#[tokio::test]
async fn load_ec_jwk() {
  let mut ks = KeyStore::new().await.unwrap();
  let jwk_json = load_asset("ec256.pub.jwk.json");
  ks.add_key(&jwk_json).unwrap();

  assert_eq!(ks.keys_len(), 1);

  /* get the key by name */
  ks.key_by_id(Some("ec2561")).unwrap();

  /* get key with wrong name, must fail */
  assert!(ks.key_by_id(Some("No-key-with-that-name")).is_err());
}
