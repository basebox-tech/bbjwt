//!
//! Keystore and key handling for bbjwt.
//!
//! This file implements handling of Json Web Keys (JWK) and Json Web Keysets (JWKS) as well as
//! OpenSSL related functionality, e.g. converting JWKs into something OpenSSL can work with.
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
use base64::Engine;
use openssl::ecdsa::EcdsaSig;
use std::fmt::{self};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use url::Url;

extern crate base64;
extern crate openssl;
extern crate serde;
extern crate serde_json;

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;

/* --- constants -------------------------------------------------------------------------------- */

/// The lifetime of keys etc. is multiplied with this factor to determine the point in time
/// after which the information is considered outdated.
/// See [`KeyStore::set_reload_factor`] for more info.
pub const RELOAD_INTERVAL_FACTOR: f64 = 0.75;

pub const BASE64_ENGINE: base64::engine::general_purpose::GeneralPurpose =
  base64::engine::general_purpose::URL_SAFE_NO_PAD;

/* --- types ------------------------------------------------------------------------------------ */


///
/// A key as we store it in the key store.
///
/// This is basically an OpenSSL [`PKey<Public>`] with required fields from the original JWK.
///
///
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BBKey {
  /// OpenSSL public key
  key: PKey<Public>,
  /// Optional key ID from the JWK
  kid: Option<String>,
  /// Key type
  kty: KeyType,
  /// Curve for elliptic curve algorithms
  crv: Option<EcCurve>,
  /// Hash algorithm
  alg: KeyAlgorithm,
}

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
  pub fn message_digest(&self) -> Option<MessageDigest> {
    match *self {
      KeyAlgorithm::RS256 | KeyAlgorithm::ES256 => Some(MessageDigest::sha256()),
      KeyAlgorithm::RS384 | KeyAlgorithm::ES384 => Some(MessageDigest::sha384()),
      KeyAlgorithm::RS512 | KeyAlgorithm::ES512 => Some(MessageDigest::sha512()),
      _ => None,
    }
  }

  ///
  /// Return signature length.
  ///
  /// Only applies to elliptic curve algorithms.
  ///
  pub fn signature_length(&self) -> usize {
    match *self {
      KeyAlgorithm::ES256 => 64,
      KeyAlgorithm::ES384 => 96,
      KeyAlgorithm::ES512 => 132,
      _ => 0,
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
  /// Return message digest for a curve.
  ///
  /// See <https://docs.rs/openssl/latest/openssl/nid/struct.Nid.html>
  ///
  pub fn message_digest(&self) -> Option<MessageDigest> {
    match *self {
      EcCurve::P256 => Some(MessageDigest::sha256()),
      EcCurve::P384 => Some(MessageDigest::sha384()),
      EcCurve::P521 => Some(MessageDigest::sha512()),
      _ => None,
    }
  }

  ///
  /// Map elliptic curve variant to its matching OpenSSL NID.
  ///
  /// See <https://docs.rs/openssl/latest/openssl/nid/struct.Nid.html>
  ///
  pub fn nid(&self) -> Option<Nid> {
    match *self {
      EcCurve::SECP256K1 => Some(Nid::SECP256K1),
      EcCurve::P256 => Some(Nid::X9_62_PRIME256V1),
      EcCurve::P384 => Some(Nid::SECP384R1),
      EcCurve::P521 => Some(Nid::SECP521R1),
      _ => None,
    }
  }
}

impl fmt::Display for BBKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    /* Use kid for keys that have it, otherwise no_kid */
    let kid = self.kid.clone().unwrap_or_else(|| "<no_kid>".to_string());
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
  pub fn verify_signature(&self, payload: &[u8], signature: &[u8]) -> BBResult<bool> {
    match self.alg {
      KeyAlgorithm::RS256 | KeyAlgorithm::RS384 | KeyAlgorithm::RS512 => {
        let mut verifier = self.verifier()?;
        verifier
          .update(payload)
          .map_err(|e| BBError::DecodeError(format!("{:?}", e)))?;

        match verifier
          .verify(signature)
          .map_err(|e| BBError::Other(format!("Failed to check RSA signature: {:?}", e)))?
        {
          true => Ok(true),
          false => Err(BBError::SignatureInvalid()),
        }
      }

      KeyAlgorithm::ES256 | KeyAlgorithm::ES384 | KeyAlgorithm::ES512 => {
        let ec_key = self.key.ec_key().map_err(|e| {
          BBError::Other(format!("Failed to extract EC key from public key: {:?}", e))
        })?;

        let sig_len = signature.len();
        if sig_len != self.alg.signature_length() {
          return Err(BBError::SignatureInvalid());
        }

        /* Create Ecdsa signature from signature bytes */
        let m = signature.len() / 2;

        let r = BigNum::from_slice(&signature[..m])
          .map_err(|e| BBError::Other(format!("Bignum error: {}", e)))?;
        let s = BigNum::from_slice(&signature[m..sig_len])
          .map_err(|e| BBError::Other(format!("Bignum error: {}", e)))?;
        let sig = EcdsaSig::from_private_components(r, s)
          .map_err(|e| BBError::Other(format!("Could not create Ecdsa Signature: {}", e)))?;

        /* calculate signature from payload */
        let digest = self
          .alg
          .message_digest()
          .ok_or_else(|| BBError::Other("Unknown algorithm digest".to_string()))?;
        let hash = hash(digest, payload)
          .map_err(|e| BBError::Other(format!("Failed to hash payload: {}", e)))?;

        Ok(
          sig
            .verify(&hash, &ec_key)
            .map_err(|e| BBError::Other(format!("Failed to verify EC signature: {}", e)))?,
        )
      }

      KeyAlgorithm::EdDSA => {
        let mut verifier = Verifier::new_without_digest(&self.key)
          .map_err(|e| BBError::Other(format!("Cannot get verifier for EdDSA: {}", e)))?;
        Ok(
          verifier
            .verify_oneshot(signature, payload)
            .map_err(|e| BBError::Other(format!("Failed to verify EdDSA signature: {}", e)))?,
        )
      }

      _ => Err(BBError::Other(format!(
        "Unsupported key algorithm for key '{}'",
        *self
      ))),
    }
  }

  ///
  /// Return an OpenSSL verifier using this key.
  ///
  pub fn verifier(&self) -> BBResult<Verifier> {
    let verifier = match self.kty {
      KeyType::RSA => {
        /* Get message digest for the algorithm used */
        let message_digest = self.alg.message_digest().ok_or_else(|| {
          BBError::Other(format!("Failed to get message digest for key '{}'.", &self))
        })?;
        /* create verifier */
        Verifier::new(message_digest, &self.key).map_err(|e| {
          BBError::Other(format!(
            "Failed to create verifier for RSA key '{}': {:?}",
            &self, e
          ))
        })?
      }

      KeyType::EC => {
        /* EC keys do not use a verifier */
        return Err(BBError::Other("EC key has no verifier".to_string()));
      }

      KeyType::OKP => {
        /* Ed does not use a message digest */
        Verifier::new_without_digest(&self.key).map_err(|e| {
          BBError::Other(format!(
            "Failed to create verifier for Ed key '{}': {:?}",
            &self, e
          ))
        })?
      }

      KeyType::Unsupported => {
        return Err(BBError::Other(format!(
          "Unsupported key type for key '{}'",
          &self
        )));
      }
    };

    Ok(verifier)
  }
}

///
/// Return config instance for base64 decoding of JWTs.
///
// pub fn base64_config() -> base64::Config {
//   base64::URL_SAFE_NO_PAD.decode_allow_trailing_bits(true)
// }

///
/// Create a BigNum from a base64 encoded string.
///
/// # Arguments
///
/// * `b64` - base64 encoded binary value; if None, an error is returned
/// * `error_context` - a string to include in error messages
///
fn bignum_from_base64(b64: &str, error_context: &str) -> BBResult<BigNum> {
  let bytes = BASE64_ENGINE.decode(b64)
    .map_err(|e| BBError::DecodeError(format!("{error_context}: '{:?}'", e)))?;

  BigNum::from_slice(&bytes).map_err(|e| {
    BBError::DecodeError(format!(
      "Failed to create number from b64 string ({error_context}): {}",
      e
    ))
  })
}

///
/// Create an OpenSSL-backed public key from a JWK.
///
/// This basically converts a JWK to a openssl::Pkey<Public>, wrapper in a [`BBKey`] struct.
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
  let kid = if jwk.kid.is_some() {
    jwk.kid.as_ref().unwrap()
  } else {
    "<no_kid>"
  };

  let key = match jwk.kty {
    KeyType::EC => {
      /* get the curve name/id */
      let nid = if jwk.crv.is_some() {
        jwk.crv.as_ref().unwrap().nid()
      } else {
        None
      }
      .ok_or_else(|| {
        BBError::JWKInvalid(format!(
          "Missing or unsupported 'crv' field for EC key '{kid}'"
        ))
      })?;
      let group = EcGroup::from_curve_name(nid).map_err(|e| {
        BBError::JWKInvalid(format!(
          "Cannot create EcGroup from nid {:?} for key {kid}: {}",
          nid, e
        ))
      })?;

      /* get point coordinates */
      if jwk.x.is_none() || jwk.y.is_none() {
        return Err(BBError::JWKInvalid(format!(
          "Missing x or y for EC key '{kid}'"
        )));
      }
      let x = bignum_from_base64(jwk.x.as_ref().unwrap(), "EC x")?;
      let y = bignum_from_base64(jwk.y.as_ref().unwrap(), "EC y")?;

      let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .map_err(|e| BBError::JWKInvalid(format!("Failed to create EcKey for {kid}': {}", e)))?;
      PKey::from_ec_key(ec_key)
        .map_err(|e| BBError::JWKInvalid(format!("Failed to create PKey/EC for {kid}': {}", e)))?
    }

    KeyType::RSA => {
      if jwk.n.is_none() || jwk.e.is_none() {
        return Err(BBError::JWKInvalid(format!(
          "Missing n or e for RSA key '{kid}'"
        )));
      }
      let n = bignum_from_base64(jwk.n.as_ref().unwrap(), "RSA n")?;
      let e = bignum_from_base64(jwk.e.as_ref().unwrap(), "RSA e")?;
      let rsa_key = Rsa::from_public_components(n, e)
        .map_err(|e| BBError::JWKInvalid(format!("Failed to create RSA key from {kid}: {}", e)))?;
      PKey::from_rsa(rsa_key)
        .map_err(|e| BBError::JWKInvalid(format!("Failed to create PKey/RSA from {kid}: {}", e)))?
    }

    KeyType::OKP => {
      /* OKP is Ed25519 or Ed448. Names, names, lots of names.
       * This public key type uses only the x coordinate on the elliptic curve */
      if jwk.x.is_none() {
        return Err(BBError::JWKInvalid(format!(
          "Missing x for OKP key '{kid}'"
        )));
      }
      let bytes = BASE64_ENGINE.decode(jwk.x.as_ref().unwrap())
        .map_err(|e| BBError::DecodeError(format!("Failed to decode x for {kid}: {}", e)))?;
      let curve_id = match jwk.crv {
        Some(EcCurve::Ed25519) => Id::ED25519,
        Some(EcCurve::Ed448) => Id::ED448,
        None => Id::ED25519,
        _ => {
          return Err(BBError::JWKInvalid(format!(
            "Invalid curve for OKP key {kid}"
          )));
        }
      };

      PKey::public_key_from_raw_bytes(&bytes, curve_id)
        .map_err(|e| BBError::JWKInvalid(format!("Failed to read EdDSA key for {kid}: {}", e)))?
    }

    _ => {
      return Err(BBError::JWKInvalid(format!(
        "Unsupported keytype for {kid}"
      )));
    }
  };

  Ok(BBKey {
    kid: jwk.kid.clone(),
    key,
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
    let rsa = openssl::rsa::Rsa::public_key_from_pem(pem.as_bytes())
      .map_err(|e| BBError::Other(format!("Could not read RSA pem: {:?}", e)))?;

    let bbkey = BBKey {
      kid: kid.map(|v| v.to_string()),
      key: PKey::from_rsa(rsa)
        .map_err(|e| BBError::JWKInvalid(format!("Failed to create PKey/RSA from PEM: {}", e)))?,
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
    let key = PKey::public_key_from_pem(pem.as_bytes())
      .map_err(|e| BBError::Other(format!("Failed to read PEM EdDSA pub key: {}", e)))?;

    /* determine key type */
    let kty = match alg {
      KeyAlgorithm::ES256 | KeyAlgorithm::ES384 | KeyAlgorithm::ES512 => KeyType::EC,
      KeyAlgorithm::EdDSA => KeyType::OKP,
      _ => {
        return Err(BBError::Other("Invalid algorithm for ec key".to_string()));
      }
    };

    let bbkey = BBKey {
      kid: kid.map(|v| v.to_string()),
      key,
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

    /* convert all keys to OpenSSL types */
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
