//!
//! Keystore and key handling for bbjwt.
//!
//! This file implements handling of Json Web Keys (JWK) and Json Web Keysets (JWKS).
//!
//! Keys might have an expiration time; while this implementation supports updating
//! expired keys by reloading them from the original URL, it does not provide cron-like
//! functionality, so the user is responsible to call this update entry point at certain
//! intervals.
//!
//! Some parts of this code inspired/taken from [jwksclient2](https://github.com/ammarzuberi/jwksclient2).
//!
//! Copyright (c) 2022 basebox GmbH, all rights reserved.
//!
//! License: MIT
//!

/* --- uses ------------------------------------------------------------------------------------- */

use crate::errors::*;
use crate::pem::decoder::PemEncodedKey;
use base64::Engine;
use der::Encode;
use num_bigint::BigInt;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::FromEncodedPoint as _;
use ring::digest;
use ring::signature::VerificationAlgorithm;
use serde::Deserialize;
use std::fmt::{self};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use url::Url;

/* --- constants -------------------------------------------------------------------------------- */

/// The lifetime of keys etc. is multiplied with this factor to determine the point in time
/// after which the information is considered outdated.
/// See [`KeyStore::set_reload_factor`] for more info.
pub const RELOAD_INTERVAL_FACTOR: f64 = 0.75;

pub const BASE64_ENGINE: base64::engine::general_purpose::GeneralPurpose =
  base64::engine::general_purpose::URL_SAFE_NO_PAD;

/* --- types ------------------------------------------------------------------------------------ */

///
/// A key as we store it in the key store, modeled after JWK.
///
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BBKey {
  /// Optional key ID from the JWK
  kid: Option<String>,
  /// Key type
  kty: KeyType,
  /// DER encoded key data
  key: PublicKey,

  /// Curve for elliptic curve algorithms
  crv: Option<EcCurve>,
  /// Hash algorithm
  alg: KeyAlgorithm,
}

use derive_more::{AsRef, From, Into};
#[derive(Debug, Clone, From, Into, AsRef)]
pub struct PublicKey(Vec<u8>);

///
/// JWK key type enum
///
/// * <https://www.rfc-editor.org/rfc/rfc7517#section-4.1>
/// * <https://www.rfc-editor.org/rfc/rfc7518#page-28>
///
#[derive(Clone, Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub enum KeyType {
  /// RSA
  RSA,
  /// Elliptic Curve
  EC,
  /// Octet key pair according to [this doc](https://curity.io/resources/learn/jwt-signatures/)
  OKP,
  /// Other types are not supported
  #[serde(other)]
  Unsupported,
}

///
/// Key algorithms.
///
/// A list of values allowed in a JOSE header is here:
/// <https://www.rfc-editor.org/rfc/rfc7518#section-3.1>
///
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum KeyAlgorithm {
  /// RSASSA-PKCS-v1_5 using SHA-256 hash algorithm (recommended).
  RS256,
  /// RSASSA-PKCS-v1_5 using SHA-384 hash algorithm (optional).
  RS384,
  /// RSASSA-PKCS-v1_5 using SHA-512 hash algorithm (optional).
  RS512,
  /// ECDSA using P-256 (secp256r1) curve and SHA-256 hash algorithm (recommended).
  ES256,
  /// ECDSA using P-384 curve and SHA-384 hash algorithm (optional).
  ES384,
  /// ECDSA using P-521 (no typo) curve and SHA-512 hash algorithm (optional).
  ES512,
  /// Edwards Curve DSA
  EdDSA,
  /// Other algorithms are not supported; this include "none", which turns off validation.
  /// This is a security issue, see [here](https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1)
  #[serde(other)]
  Other,
}

///
/// Elliptic Curves for EC and Ed/OKP keys
///
/// <https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1>
///
#[derive(Clone, Debug, Deserialize)]
pub enum EcCurve {
  /// secp256r1
  /// <https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/6.0/com/nimbusds/jose/JWSAlgorithm.html#ES256>
  #[serde(rename = "P-256")]
  P256,
  #[serde(rename = "secp256k1")]
  SECP256K1,
  #[serde(rename = "P-384")]
  P384,
  #[serde(rename = "P-521")]
  P521,
  Ed25519,
  Ed448,
}

///
/// JSON web key
///
/// This lib supports EC and RSA keys as required by the OpenID Connect spec, see
/// <https://openid.net/specs/draft-jones-json-web-key-03.html#anchor6>.
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
  /// RSA modulus; see [here](https://www.rfc-editor.org/rfc/rfc7517#section-9.3)
  pub n: Option<String>,
  /// RSA exponent
  pub e: Option<String>,
  /// EC curve, only for kty="EC"
  pub crv: Option<EcCurve>,
  /// EC x coordinate, only for kty="EC"
  pub x: Option<String>,
  /// EC y coordinate, only for kty="EC"
  pub y: Option<String>,
}

///
/// JSON Web Key Set
///
#[derive(Clone, Debug, Deserialize)]
pub struct JWKS {
  pub keys: Vec<JWK>,
}

///
/// JWK key store.
///
/// This is basically a thin wrapper around JSON web key sets that adds loading/updating
/// functionality.
///
#[derive(Debug)]
pub struct KeyStore {
  /// List of keys in this store
  keyset: RwLock<Vec<BBKey>>,
  /// The URL the key set is loaded from.
  url: Option<String>,
  /// The time the keys were last loaded from `url`.
  load_time: Option<SystemTime>,
  /// Reload interval factor; if .7, keys are considered expired if 70% of their lifetime is over.
  /// See [`KeyStore::set_reload_factor`] for more info.
  reload_factor: f64,
  /// Time at which keys should be reloaded.
  reload_time: Option<SystemTime>,
}

impl JWKS {
  ///
  /// Create new empty keyset.
  ///
  pub fn new() -> Self {
    JWKS { keys: vec![] }
  }
}

impl Default for JWKS {
  fn default() -> Self {
    Self::new()
  }
}

impl KeyAlgorithm {
  ///
  /// Return message digest for an algorithm.
  ///
  pub fn message_digest(&self) -> Option<&'static digest::Algorithm> {
    match self {
      KeyAlgorithm::RS256 | KeyAlgorithm::ES256 => Some(&digest::SHA256),
      KeyAlgorithm::RS384 | KeyAlgorithm::ES384 => Some(&digest::SHA384),
      KeyAlgorithm::RS512 | KeyAlgorithm::ES512 => Some(&digest::SHA512),
      _ => None,
    }
  }

  ///
  /// Return verification implementation
  ///
  pub(crate) fn verification(&self) -> &'static dyn VerificationAlgorithm {
    match self {
      KeyAlgorithm::RS256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
      KeyAlgorithm::RS384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
      KeyAlgorithm::RS512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
      KeyAlgorithm::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED,
      KeyAlgorithm::ES384 => &ring::signature::ECDSA_P384_SHA384_FIXED,
      KeyAlgorithm::ES512 => todo!(),
      KeyAlgorithm::EdDSA => &ring::signature::ED25519,
      // hitting this is a programming error
      KeyAlgorithm::Other => unimplemented!(),
    }
  }
}

impl Default for KeyAlgorithm {
  ///
  /// Return default algorithm - should none be specified.
  ///
  fn default() -> Self {
    KeyAlgorithm::RS256
  }
}

impl EcCurve {
  ///
  /// Return message digest algorithm for a curve.
  ///
  pub fn message_digest(&self) -> Option<&'static digest::Algorithm> {
    match self {
      EcCurve::P256 => Some(&digest::SHA256),
      EcCurve::P384 => Some(&digest::SHA384),
      EcCurve::P521 => Some(&digest::SHA512),
      _ => None,
    }
  }
}

impl fmt::Display for BBKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    /* Use kid for keys that have it, otherwise no_kid */
    let kid = self.kid.as_deref().unwrap_or("<no_kid>").to_string();
    write!(f, "{}", kid)
  }
}

impl BBKey {
  ///
  /// Verify a signature.
  ///
  /// # Arguments
  ///
  /// * `payload` - the signed data
  /// * `signature` - the signature to verify
  ///
  pub fn verify_signature(&self, payload: &[u8], signature: &[u8]) -> BBResult<()> {
    match self.alg {
      KeyAlgorithm::RS256
      | KeyAlgorithm::RS384
      | KeyAlgorithm::RS512
      | KeyAlgorithm::ES256
      | KeyAlgorithm::ES384
      | KeyAlgorithm::EdDSA => {
        // TODO hacky, AND it does not work
        if matches!(self.crv, Some(EcCurve::Ed448)) {
          let key: ed448_rust::PublicKey =
            BigInt::from_bytes_be(num_bigint::Sign::Plus, self.key.as_ref()).into();
          let res = key
            .verify(payload, signature, None)
            .map_err(|_| BBError::SignatureInvalid);
          res
        } else {
          let key =
            ring::signature::UnparsedPublicKey::new(self.alg.verification(), self.key.as_ref());
          let res = key
            .verify(payload, signature)
            .map_err(|_| BBError::SignatureInvalid);
          return res;
        }
      }

      _ => Err(BBError::Other(format!(
        "Unsupported key algorithm for key '{}'",
        *self
      ))),
    }
  }
}

///
/// Create a [`BBKey`] from a JWK.
///
/// # Arguments
///
/// * `jwk` - the JWK to convert.
///
/// # Returns
///
/// A PublicKey instance.
///
fn pubkey_from_jwk(jwk: &JWK) -> BBResult<BBKey> {
  let kid = jwk.kid.as_deref().unwrap_or("<no_kid>").to_string();

  let key = match jwk.kty {
    // TODO tests that cover more than loading?
    KeyType::EC => {
      /* ensure crv field */
      if jwk.crv.is_none() {
        return Err(BBError::JWKInvalid(format!(
          "Missing 'crv' field for EC key '{kid}'"
        )));
      }

      /* ensure point coordinates */
      if jwk.x.is_none() || jwk.y.is_none() {
        return Err(BBError::JWKInvalid(format!(
          "Missing x or y for EC key '{kid}'"
        )));
      }

      let x = BASE64_ENGINE.decode(jwk.x.as_ref().unwrap())?;
      let y = BASE64_ENGINE.decode(jwk.y.as_ref().unwrap())?;

      let res = match jwk.crv.as_ref().unwrap() {
        EcCurve::P256 => p256::EncodedPoint::from_affine_coordinates(
          GenericArray::from_slice(&x),
          GenericArray::from_slice(&y),
          false,
        )
        .to_bytes()
        .into(),
        EcCurve::SECP256K1 => todo!(),
        EcCurve::P384 => p384::EncodedPoint::from_affine_coordinates(
          GenericArray::from_slice(&x),
          GenericArray::from_slice(&y),
          false,
        )
        .to_bytes()
        .into(),
        EcCurve::P521 => todo!(),
        // TODO is this a possible code path?
        EcCurve::Ed25519 => x,
        // TODO is this a possible code path?
        EcCurve::Ed448 => x,
      };

      res
    }

    KeyType::RSA => {
      if jwk.n.is_none() || jwk.e.is_none() {
        return Err(BBError::JWKInvalid(format!(
          "Missing n or e for RSA key '{kid}'"
        )));
      }

      let n = BASE64_ENGINE.decode(jwk.n.as_ref().unwrap())?;
      let e = BASE64_ENGINE.decode(jwk.e.as_ref().unwrap())?;

      let n = der::asn1::UintRef::new(&n)
        .map_err(|e| BBError::JWKInvalid(format!("Invalid n for RSA key '{kid}'")))?;
      let e = der::asn1::UintRef::new(&e)
        .map_err(|e| BBError::JWKInvalid(format!("Invalid e for RSA key '{kid}'")))?;
      let key = pkcs1::RsaPublicKey {
        modulus: n,
        public_exponent: e,
      };
      key.to_der().unwrap()
    }

    KeyType::OKP => {
      /* OKP is Ed25519 or Ed448. Names, names, lots of names.
       * This public key type uses only the x coordinate on the elliptic curve */
      if jwk.x.is_none() {
        return Err(BBError::JWKInvalid(format!(
          "Missing x for OKP key '{kid}'"
        )));
      }
      let bytes = BASE64_ENGINE
        .decode(jwk.x.as_ref().unwrap())
        .map_err(|e| BBError::DecodeError(format!("Failed to decode x for {kid}: {}", e)))?;
      match jwk.crv {
        // `None` assumes `Ed25519`
        Some(EcCurve::Ed25519) | Some(EcCurve::Ed448) | None => bytes,
        _ => {
          return Err(BBError::JWKInvalid(format!(
            "Invalid curve for OKP key {kid}"
          )));
        }
      }
    }

    _ => {
      return Err(BBError::JWKInvalid(format!(
        "Unsupported keytype for {kid}"
      )));
    }
  };

  Ok(BBKey {
    kid: jwk.kid.clone(),
    key: key.into(),
    kty: jwk.kty.clone(),
    crv: jwk.crv.clone(),
    alg: jwk.alg.clone().unwrap_or_default(),
  })
}

#[allow(dead_code)]
impl KeyStore {
  ///
  /// Create a new, empty keyset.
  ///
  pub async fn new() -> BBResult<Self> {
    Ok(KeyStore {
      keyset: RwLock::new(Vec::new()),
      url: None,
      load_time: None,
      reload_factor: RELOAD_INTERVAL_FACTOR,
      reload_time: None,
    })
  }

  ///
  /// Create new keyset and load keys from a URL
  ///
  /// # Arguments
  ///
  /// * `surl`: URL to load the keys from.
  ///
  pub async fn new_from_url(surl: &str) -> BBResult<Self> {
    /* make sure the URL is safe (https) */
    let url = Url::parse(surl)
      .map_err(|e| BBError::URLInvalid(format!("Invalid keyset URL '{surl}: {:?}", e)))?;
    let host = url
      .host_str()
      .ok_or_else(|| BBError::URLInvalid(format!("No host in keyset URL '{surl}")))?;
    /* if the URL is not local, it must use TLS */
    if !["localhost", "127.0.0.1"].contains(&host) && url.scheme() != "https" {
      return Err(BBError::URLInvalid(
        "Public keysets must be loaded via https.".to_string(),
      ));
    }

    let mut ks = KeyStore {
      keyset: RwLock::new(Vec::new()),
      url: Some(url.to_string()),
      load_time: None,
      reload_factor: RELOAD_INTERVAL_FACTOR,
      reload_time: None,
    };

    /* load keys from URL if applicable */
    ks.load_keys().await?;

    Ok(ks)
  }

  ///
  /// Return the keys in the keystore.
  ///
  /// This function is cloning all keys, since otherwise the read lock would have to be
  /// held after this function returns. Thus, use this sparingly :-)
  ///
  /// # Returns
  ///
  /// The cloned keyset or None if something goes wrong.
  ///
  pub fn keyset(&self) -> BBResult<Vec<BBKey>> {
    if let Ok(keyset) = self.keyset.read() {
      Ok(keyset.clone())
    } else {
      Err(BBError::Fatal("Keyset lock is poisoned".to_string()))
    }
  }

  ///
  /// Number of keys in keystore.
  ///
  /// If the keyset lock is poisoned (should never happen), this function returns 0.
  ///
  pub fn keys_len(&self) -> usize {
    if let Ok(keyset) = self.keyset.read() {
      keyset.len()
    } else {
      0
    }
  }

  ///
  /// Manually add a key to the keystore.
  ///
  /// # Arguments
  ///
  /// * `key_json` - JSON string containing a [`JWK`].
  ///
  pub fn add_key(&mut self, key_json: &str) -> BBResult<()> {
    let key: JWK = serde_json::from_str(key_json)
      .map_err(|e| BBError::Other(format!("Failed to parse key JSON: {:?}", e)))?;

    let mut keyset = self
      .keyset
      .write()
      .map_err(|e| BBError::Other(format!("Failed to get write lock on keyset: {:?}", e)))?;
    keyset.push(pubkey_from_jwk(&key)?);
    Ok(())
  }

  ///
  /// Add a public RSA key from a PEM string.
  ///
  /// # Arguments
  ///
  /// * `pem` - PEM encoded public RSA key
  /// * `kid` - optional key id
  /// * `alg` - algorithm, e.g. [`KeyAlgorithm::RS256`]
  ///
  pub fn add_rsa_pem_key(&self, pem: &str, kid: Option<&str>, alg: KeyAlgorithm) -> BBResult<()> {
    if !matches!(
      alg,
      KeyAlgorithm::RS256 | KeyAlgorithm::RS384 | KeyAlgorithm::RS512
    ) {
      return Err(BBError::Other("Invalid algorithm for rsa key".to_string()));
    }
    let pem_key = PemEncodedKey::new(pem.as_bytes())
      .map_err(|e| BBError::Other(format!("Could not read RSA pem: {:?}", e)))?;

    let key = pem_key
      .as_rsa_key()
      .map_err(|e| BBError::Other(format!("Failed to create RSA key from PEM: {:?}", e)))?
      .to_owned();

    let bbkey = BBKey {
      kid: kid.map(|v| v.to_string()),
      key: key.into(),
      kty: KeyType::RSA,
      crv: None,
      alg,
    };

    let mut keyset = self
      .keyset
      .write()
      .map_err(|e| BBError::Other(format!("Failed to get write lock on keyset: {:?}", e)))?;
    keyset.push(bbkey);
    Ok(())
  }

  ///
  /// Add a public elliptic curve key from a PEM string.
  ///
  /// Supports both EdDSA and EC keys.
  ///
  /// # Arguments
  ///
  /// * `pem` - public key in PEM encoding
  /// * `kid` - optional key id
  /// * `curve` - the Ed curve (Ed448 or Ed25519) or EC curve (P256, P384, P521)
  /// * `alg` - the algorithm, e.g. ES384
  ///
  pub fn add_ec_pem_key(
    &self,
    pem: &str,
    kid: Option<&str>,
    curve: EcCurve,
    alg: KeyAlgorithm,
  ) -> BBResult<()> {
    /* determine key type */
    let kty = match alg {
      KeyAlgorithm::ES256 | KeyAlgorithm::ES384 | KeyAlgorithm::ES512 => KeyType::EC,
      KeyAlgorithm::EdDSA => KeyType::OKP,
      _ => {
        return Err(BBError::Other(
          "Invalid algorithm for EdDSA/EC key".to_string(),
        ));
      }
    };

    let pem_key = PemEncodedKey::new(pem.as_bytes())
      .map_err(|e| BBError::Other(format!("Could not read PEM EdDSA/EC pub key: {:?}", e)))?;

    let mut key_data = match alg {
      KeyAlgorithm::ES256 | KeyAlgorithm::ES384 | KeyAlgorithm::ES512 => pem_key
        .as_ec_public_key()
        .map_err(|e| BBError::Other(format!("PEM does not contain an EC public key: {:?}", e)))?,
      _ => pem_key
        .as_ed_public_key()
        .map_err(|e| BBError::Other(format!("PEM does not contain an Ed public key: {:?}", e)))?,
    };

    // TODO (DER vs bigint repr?)
    if matches!(curve, EcCurve::Ed448) {
      key_data = pem_key
        .as_ed_public_key()
        .map_err(|e| BBError::Other(format!("PEM does not contain an Ed public key: {:?}", e)))?;
    }

    let bbkey = BBKey {
      kid: kid.map(|v| v.to_string()),
      key: PublicKey(key_data.to_owned()),
      kty,
      alg,
      crv: Some(curve),
    };

    let mut keyset = self
      .keyset
      .write()
      .map_err(|e| BBError::Other(format!("Failed to get write lock on keyset: {:?}", e)))?;
    keyset.push(bbkey);
    Ok(())
  }

  ///
  /// Retrieve a key by id.
  ///
  /// The `kid` claim is optional, so the keyset may contain keys without id.
  /// This is why the `kid` argument to this function is optional, too. If it is
  /// None, we use the first key, assuming that there is only one. This
  /// complies to the rules set by the OpenID Connect spec, defined
  /// [here](https://openid.net/specs/openid-connect-core-1_0.html#SigEnc).
  ///
  /// # Arguments
  /// * `kid` - the ID of the key. If None, the first key is returned.
  ///
  pub fn key_by_id(&self, kid: Option<&str>) -> BBResult<BBKey> {
    let keyset = self
      .keyset
      .read()
      .map_err(|_e| BBError::Fatal("The keyset lock is poisoned".to_string()))?;

    let key = if let Some(kid) = kid {
      /* `kid` is Some; return key with specific ID */
      let key = keyset.iter().find(|k: &&BBKey| {
        if let Some(this_kid) = &k.kid {
          this_kid.eq(kid)
        } else {
          false
        }
      });
      key.ok_or_else(|| BBError::Other(format!("Could not find kid '{kid}' in keyset.")))?
    } else {
      /* `kid` is None; return first key in set */
      keyset
        .first()
        .ok_or_else(|| BBError::Other("No keys in keyset".to_string()))?
    };

    Ok(key.clone())
  }

  ///
  /// Specify the interval factor to determine when the key store should reload its keys.
  ///
  /// The default is 0.75, meaning that keys should be reloaded when we are 3/4 through
  /// the expiration time (similar to DHCP). For example if the server tells us that the
  /// keys expire in 10 minutes, setting the reload interval to 0.75 will consider the keys
  /// to be expired after 7.5 minutes and the [`KeyStore::should_reload`] function returns true.
  ///
  /// This method does **not** update the reload time. Call [`KeyStore::load_keys`] to force an update.
  ///
  pub fn set_reload_factor(&mut self, interval: f64) {
    self.reload_factor = interval;
  }

  ///
  /// Get the current fraction time to check for token reload time.
  ///
  pub fn reload_factor(&self) -> f64 {
    self.reload_factor
  }

  ///
  /// Get the time at which the keys were initially loaded.
  ///
  /// # Returns
  ///
  /// Time of initial load or None if the keys were never loaded.
  ///
  pub fn load_time(&self) -> Option<SystemTime> {
    self.load_time
  }

  ///
  /// Get the time at which the keys should be reloaded.
  ///
  /// See [`KeyStore::set_reload_factor`] for more info.
  ///
  pub fn reload_time(&self) -> Option<SystemTime> {
    self.reload_time
  }

  ///
  /// Check if keys are expired based on the given `time`.
  ///
  /// # Returns
  /// * Some(true) if keys should be reloaded.
  /// * Some(false) if keys need not to be reloaded
  /// * None if the key store does not have a reload time available. For example, the
  ///    [`KeyStore::load_keys`] function was not called or the HTTP server did not provide a
  ///    cache-control HTTP header.
  ///
  pub fn should_reload_time(&self, time: SystemTime) -> Option<bool> {
    self.reload_time.map(|reload_time| reload_time <= time)
  }

  ///
  /// Check if keys are expired based on the current system time.
  ///
  /// # Returns
  /// * Some(true) if keys should be reloaded.
  /// * Some(false) if keys need not to be reloaded
  /// * None if the key store does not have a reload time available. For example, the
  ///   [`KeyStore::load_keys`] function was not called or the HTTP server did not provide a
  ///   cache-control HTTP header.
  ///
  pub fn should_reload(&self) -> Option<bool> {
    self.should_reload_time(SystemTime::now())
  }

  ///
  /// Load/update keys from the keystore URL.
  ///
  /// Clients should call this function when [`KeyStore::should_reload`] returns true.
  ///
  #[allow(clippy::await_holding_lock)]
  pub async fn load_keys(&mut self) -> BBResult<()> {
    let url = self
      .url
      .clone()
      .ok_or_else(|| BBError::Other("No load URL for keyset provided.".to_string()))?;

    /* No keys are better than expired keys: clear keys first. */
    let mut keys = self
      .keyset
      .write()
      .map_err(|e| BBError::Fatal(format!("Keyset write lock is poisoned: {}", e)))?;
    keys.clear();
    /* drop the cache write lock so we do not hold it during the refresh request.
     * Note: Clippy emits a false positive about a lock being held while an async
     * function is being awaited. The lock is dropped explicitly here.
     * See here https://github.com/rust-lang/rust-clippy/issues/9208
     */
    drop(keys);

    let mut response = reqwest::get(&url)
      .await
      .map_err(|e| BBError::Other(format!("Failed to load IdP keyset: {:?}", e)))?;

    /* get expiration/life time from cache-control HTTP header field */
    let lifetime = KeyStore::get_key_expiration_time(&mut response);

    /* load JWKS from URL */
    let json = response
      .text()
      .await
      .map_err(|e| BBError::NetworkError(format!("Failed to load public key set: {:?}", e)))?;

    /* deserialize JSON into our JWKS struct */
    let keyset: JWKS = serde_json::from_str(&json)
      .map_err(|e| BBError::Other(format!("Failed to parse IdP public key set: {:?}", e)))?;

    let mut keys = self
      .keyset
      .write()
      .map_err(|e| BBError::Fatal(format!("Keyset write lock is poisoned: {}", e)))?;

    /* convert all keys to internal type and add them to the store */
    for key in keyset.keys {
      keys.push(pubkey_from_jwk(&key)?);
    }

    /* update load time and expiration time */
    let load_time = SystemTime::now();
    if let Ok(value) = lifetime {
      let seconds: u64 = (value as f64 * self.reload_factor) as u64;
      self.reload_time = Some(load_time + Duration::new(seconds, 0));
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
  /// * `response` - response to read the cache-control HTTP header from
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
  /// * `idp_discovery_url` - the URL to load the discovery info from.
  ///
  pub async fn idp_certs_url(idp_discovery_url: &str) -> BBResult<String> {
    let info_json = reqwest::get(idp_discovery_url)
      .await
      .map_err(|e| {
        BBError::NetworkError(format!(
          "Failed to load IdP discovery info JSON from {idp_discovery_url}: {:?}",
          e
        ))
      })?
      .text()
      .await
      .map_err(|e| {
        BBError::NetworkError(format!("Failed to get IdP discovery info JSON: {:?}", e))
      })?;

    let info: serde_json::Value = serde_json::from_str(&info_json).map_err(|e| {
      BBError::Other(format!(
        "Invalid JSON from IdP discovery info url '{idp_discovery_url}': {:?}",
        e
      ))
    })?;

    if let serde_json::Value::String(jwks_uri) = &info["jwks_uri"] {
      Ok(jwks_uri.to_string())
    } else {
      Err(BBError::Other(
        "No jwks_uri in IdP discovery info found".to_string(),
      ))
    }
  }

  ///
  /// Construct Keycloak specific discovery URL from a host and realm name.
  ///
  /// Provided for convenience :-)
  ///
  /// # Arguments
  ///
  /// * `host` - protocol and host name of the Keycloak server, e.g. <https://idp.domain.tld>
  /// * `realm` - the realm name
  ///
  /// # Returns
  ///
  /// URL of discovery endpoint.
  ///
  pub fn keycloak_discovery_url(host: &str, realm: &str) -> BBResult<String> {
    let mut info_url = Url::parse(host).map_err(|e| {
      BBError::Other(format!(
        "Invalid base URL for Keycloak discovery endpoint: {:?}",
        e
      ))
    })?;

    /* Discovery info URL is built like this:
     * https://<host>/realms/<realm_name>/.well-known/openid-configuration
     */
    info_url
      .path_segments_mut()
      .map_err(|_| BBError::Other(format!("Invalid IdP URL '{host}'")))?
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
///
/// * `hdr_value` - the header value (or string) to search for an assigned value
/// * `name` - the name to look for before the assignment '='
///
fn assigned_header_value(hdr_value: &str, name: &str) -> Result<u64, ()> {
  /* search name */
  let mut p = hdr_value.find(name).ok_or(())?;
  p += name.len();
  let mut num = String::with_capacity(22); // max byte length of a 64bit number
  let mut got_ass = false;
  let chars = hdr_value.get(p..).unwrap().chars();

  for c in chars {
    match c {
      '=' => {
        got_ass = true;
      }

      c => {
        if !got_ass {
          continue;
        }

        if c.is_numeric() {
          num.push(c);
        } else if !num.is_empty() {
          /* No digit, but already saw a digit, stop here */
          break;
        }
      }
    }
  }

  if num.is_empty() {
    return Err(());
  }

  let value: u64 = num.parse().map_err(|_| ())?;
  Ok(value)
}

#[cfg(test)]

mod tests {

  use super::*;
  use rand::seq::SliceRandom;
  use std::env;
  use std::fs::File;
  use std::io::Read;
  use std::path::Path;

  ///
  /// Utility function that returns the absolute path and file name to a file in the /tests/assets folder.
  ///
  /// This is copied from tests::bb_common; unfortunately, I do not know how to import/use code from there.
  ///
  /// # Arguments
  ///
  /// * `asset_name` - path and file name of the file, relative to the "assets" folder.
  ///
  /// # Returns
  ///
  /// Absolute path to the asset file.
  ///
  pub fn path_to_asset_file(asset_name: &str) -> String {
    let path = Path::new(
      env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set")
        .as_str(),
    )
    .join(format!("tests/assets/{asset_name}"));

    String::from(path.to_str().unwrap())
  }

  #[test]
  ///
  /// Test for `keycloak_discovery_url`
  ///
  fn test_keycloak_discovery_url() {
    /* Very simple, if not pathetic, test. Runs without accessing any keycloak instance :-) */
    let url = KeyStore::keycloak_discovery_url("https://host.tld", "testing");
    assert_eq!(
      url.unwrap(),
      "https://host.tld/realms/testing/.well-known/openid-configuration"
    )
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
      "xu depp=666",
    ];
    let results: Vec<u64> = vec![3485975, 1, 22, 12345678, 666];

    /* check a couple of strings */
    for i in 0..test_strings.len() {
      assert!(assigned_header_value(test_strings[i], "depp").unwrap() == results[i]);
    }

    /* nonsense string must return error */
    assert!(assigned_header_value("orihgeorgohoho", "name").is_err());
  }

  ///
  /// Test keystore with local pub keys.
  ///
  #[tokio::test]
  async fn test_keystore_local() {
    /* create empty keystore */
    let mut ks = KeyStore::new()
      .await
      .expect("Failed to create empty keystore");

    /* load a key from a local JSON file */
    let key_json_file = path_to_asset_file("pubkey.json");
    let mut file = File::open(key_json_file).expect("Failed to open pubkey.json");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    /* add key to store 20 times */
    for i in 1..21 {
      /* add keys with patched kid */
      ks.add_key(&data.replace(
        "nOo3ZDrODXEK1jKWhXslHR_KXEg",
        format!("bbjwt-test-{i}").as_str(),
      ))
      .expect("Failed to add key to keystore");
    }

    assert_eq!(ks.keys_len(), 20);

    /* get first key */
    let key1 = ks.key_by_id(None).expect("Failed to get key just added");
    assert!(key1.kid.unwrap() == "bbjwt-test-1");

    /* get some other key */
    let k = ks
      .key_by_id(Some("bbjwt-test-17"))
      .expect("Failed to get key by ID");
    assert_eq!(k.kid.unwrap(), "bbjwt-test-17");
  }

  ///
  /// Test loading from an insecure URL.
  ///
  #[tokio::test]
  async fn insecure_keyset_load() {
    /* Loading from non-https URL must be refused/fail */
    let ret = KeyStore::new_from_url(
      "http://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    )
    .await;
    assert!(format!("{:?}", ret).contains("https"));
  }

  ///
  /// Test loading keys from a URL.
  ///
  #[tokio::test]
  async fn test_load_keys() {
    /* ask Seattle for the location of their public key store :-) */
    let url = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
    let ks_url = KeyStore::idp_certs_url(url)
      .await
      .expect("Failed to get keyset URL");

    /* Test load keyset from URL */
    let ks = KeyStore::new_from_url(&ks_url)
      .await
      .expect("Failed to load keystore");

    /* test for expiration time */
    assert!(ks.load_time.is_some());
    assert!(ks.reload_time.is_some());
    assert!(ks.reload_time.unwrap() > ks.load_time.unwrap());

    println!("KeyStore: {:?}", ks);

    /* Test keys length; should be > 0 */
    assert!(ks.keys_len() > 0);

    let keyset = ks.keyset().unwrap();

    /* get a random key from the keyset */
    let key = keyset
      .choose(&mut rand::thread_rng())
      .expect("Failed to get random key from keyset");

    /* get its key id and try to get it from the store by key id */
    let kid = key
      .kid
      .clone()
      .expect("No kid in key; not an error, but spoils this test...");
    let k = ks.key_by_id(Some(&kid)).expect("Failed to get key by id");
    assert_eq!(k.kid.expect("Missing kid"), kid);

    /* get the first key */
    let k1 = ks
      .keyset()
      .unwrap()
      .first()
      .expect("Failed to get first key")
      .clone();

    /* get key without id; must return the first/something */
    let k = ks.key_by_id(None).expect("No key returned without kid");
    /* kid must match the kid of the first key */
    assert_eq!(k.kid.unwrap().as_str(), k1.kid.unwrap().as_str());
  }
}
