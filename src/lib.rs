//
// bbjwt main source file, see ../README.md for details.
//
// Copyright (c) 2022 basebox GmbH, all rights reserved.
//
// License: MIT
//
#![doc = include_str!("../README.md")]

/* --- uses ------------------------------------------------------------------------------------- */

use base64::Engine;
pub use errors::{BBError, BBResult};
pub use keystore::KeyStore;
pub use keystore::{EcCurve, KeyAlgorithm};

use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keystore::BBKey;
use keystore::BASE64_ENGINE;

/* --- mods ------------------------------------------------------------------------------------- */

pub mod errors;
pub mod keystore;
mod pem;

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
  /// "groups" claim must be present and non-empty.
  HasGroups,
}

///
/// All claims defined in a JWT.
///
/// This is created and returned to the caller upon successful validation. The claims present do vary,
/// and the caller knows best what fields to expect, so this struct simply contains a copy of the parsed
/// JSON fields.
///
#[derive(Debug)]
#[allow(dead_code)]
pub struct JWTClaims {
  /// JOSE header fields of the JWTs, see [RFC7519](https://www.rfc-editor.org/rfc/rfc7519#section-5)
  pub headers: serde_json::Value,
  /// Claims (fields) found in the JWT. What fields are present depends on the purpose of
  /// the JWT. For OpenID Connect ID tokens see
  /// [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
  pub claims: serde_json::Value,
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
  alg: KeyAlgorithm,
  /// ID of the public key used to sign this JWT
  kid: Option<String>,
}

///
/// Audience enum; supports a single or multiple audiences.
///
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
  Single(String),
  Multi(Vec<String>),
}

///
/// Claims that can be subject to validation.
///
#[derive(Deserialize)]
struct ValidationClaims {
  iss: Option<String>,
  sub: Option<String>,
  exp: Option<u64>,
  aud: Option<Audience>,
  nonce: Option<String>,
  groups: Option<Vec<String>>,
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
/// * `issuer` - the contents the "iss" claim must have
/// * `audience` - if Some, the value the "aud" claim must have
/// * `nonce` - if Some, the value the "nonce" claim must have
///
/// # Returns
///
/// A vector of ValidationStep variants that can be passed into the [`validate_jwt`] function.
///
pub fn default_validations(
  issuer: &str,
  audience: Option<&str>,
  nonce: Option<&str>,
) -> Vec<ValidationStep> {
  /* Create vector of bare minimum validations */
  let mut validations = vec![
    ValidationStep::Issuer(issuer.to_string()),
    ValidationStep::NotExpired,
  ];

  if let Some(audience) = audience {
    validations.push(ValidationStep::Audience(audience.to_string()));
  }
  if let Some(nonce) = nonce {
    validations.push(ValidationStep::Nonce(nonce.to_string()));
  }

  validations
}

///
/// Validate a JWT.
///
/// This function decodes the token string (base64) and then validates it. Encrypted JWTs are
/// not supported (yet?).
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
  keystore: &KeyStore,
) -> BBResult<JWTClaims> {
  /* A JWT is a Base64 encoded string with 3 parts separated by dots:
   * HEADER.CLAIMS.SIGNATURE */
  let parts: Vec<&str> = jwt.splitn(3, '.').collect();
  if parts.len() != 3 {
    return Err(BBError::TokenInvalid(
      "Could not split token in 3 parts.".to_string(),
    ));
  }

  /* Get the JOSE header */
  let hdr_json = BASE64_ENGINE.decode(parts[0])?;
  let kid_hdr: JOSEHeader =
    serde_json::from_slice(&hdr_json).map_err(|e| BBError::JSONError(format!("{:?}", e)))?;

  /* Deny JWTs with no algorithm; see [here](https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1) */
  if kid_hdr.alg == KeyAlgorithm::Other {
    return Err(BBError::TokenInvalid("Unsupported algorithm".to_string()));
  }

  /* get public key for signature validation */
  let pubkey = keystore.key_by_id(kid_hdr.kid.as_deref())?;

  /* First, we verify the signature. */
  // TODO this swallows the base64 decode error
  check_jwt_signature(&parts, &pubkey).map_err(|_| BBError::SignatureInvalid)?;

  /* decode the payload so we can verify its contents */
  let payload_json = BASE64_ENGINE.decode(parts[1])?;
  let claims: ValidationClaims =
    serde_json::from_slice(&payload_json).map_err(|e| BBError::JSONError(format!("{:?}", e)))?;

  /* Be nice: return all validation errors at once */
  let mut validation_errors = Vec::<String>::new();

  for step in validation_steps {
    if let Some(error) = validate_claim(&claims, step) {
      validation_errors.push(error);
    }
  }

  if !validation_errors.is_empty() {
    let mut err = "One or more claims failed to validate:\n".to_string();
    err.push_str(&validation_errors.join("\n"));
    return Err(BBError::ClaimInvalid(err));
  }

  /* Success! */
  Ok(JWTClaims {
    headers: serde_json::from_slice(&hdr_json)?,
    claims: serde_json::from_slice(&payload_json)?,
  })
}

///
/// Validate a single claim.
///
/// If a claim is None, this is treated as a validation error.
///
/// # Arguments
///
/// * `claims` - claims extracted from the JWT
/// * `step` - the validation step to perform
///
/// # Returns
///
/// None on success or an error string on validation error.
///
fn validate_claim(claims: &ValidationClaims, step: &ValidationStep) -> Option<String> {
  match step {
    ValidationStep::Audience(aud) => {
      if let Some(claims_aud) = &claims.aud {
        match claims_aud {
          Audience::Single(single) => {
            if single != aud {
              return Some(format!(
                "'aud' does not match; expected '{}', got '{}'",
                aud, single
              ));
            }
          }
          Audience::Multi(multi) => {
            if !multi.contains(aud) {
              return Some(format!(
                "'aud' claims don't match: '{}' not found in '{:?}'",
                aud, multi
              ));
            }
          }
        }
      } else {
        return Some("'aud' not set".to_string());
      }
    }

    ValidationStep::Issuer(iss) => {
      if let Some(claims_iss) = &claims.iss {
        if claims_iss != iss {
          return Some(format!(
            "'iss' does not match; expected '{}', got '{}'",
            iss, claims_iss
          ));
        }
      } else {
        return Some("'iss' is missing".to_string());
      }
    }

    ValidationStep::Nonce(nonce) => {
      if let Some(claims_nonce) = &claims.nonce {
        if claims_nonce != nonce {
          return Some("'nonce' does not match".to_string());
        }
      } else {
        return Some("'nonce' is missing".to_string());
      }
    }

    ValidationStep::NotExpired => {
      if let Some(exp) = &claims.exp {
        /* get current time; if this fails, we can assume a wrong time setting and panic */
        let now = SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .expect("System time is wrong.");
        if Duration::from_secs(*exp) < now {
          return Some("Token has expired.".to_string());
        }
      }
    }

    ValidationStep::HasSubject => {
      if claims.sub.is_none() {
        return Some("'sub' is missing".to_string());
      }
    }

    ValidationStep::HasGroups => {
      if claims.groups.is_none() {
        return Some("'groups' is missing".to_string());
      }
    }
  }

  None
}

///
/// Check if a JWT's signature is correct.
///
/// # Arguments
///
/// * `jwt_parts` - JWT split by '.'; must be a vector of 3 strings
/// * `verifier` - The OpenSSL verifier to use
///
fn check_jwt_signature(jwt_parts: &[&str], pubkey: &BBKey) -> BBResult<()> {
  /* first 2 parts are JWT data */
  let jwt_data = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
  /* signature is the 3rd part */
  let sig = BASE64_ENGINE
    .decode(jwt_parts[2])
    .map_err(|e| BBError::DecodeError(format!("{:?}", e)))?;

  pubkey.verify_signature(jwt_data.as_bytes(), &sig)
}

#[cfg(test)]

mod tests {

  use core::panic;

  use super::*;

  ///
  /// Return empty validations.
  ///
  fn empty_validations() -> ValidationClaims {
    ValidationClaims {
      aud: None,
      iss: None,
      nonce: None,
      exp: None,
      sub: None,
      groups: None,
    }
  }

  #[test]
  fn validate_aud_claim() {
    let claims = ValidationClaims {
      aud: Some(Audience::Single("test".to_string())),
      ..empty_validations()
    };

    let step = ValidationStep::Audience("test".to_string());
    assert!(validate_claim(&claims, &step).is_none());

    let step = ValidationStep::Audience("test2".to_string());
    if let Some(err_str) = validate_claim(&claims, &step) {
      /* assert we get a detailed error string */
      assert_eq!(
        err_str,
        "'aud' does not match; expected 'test2', got 'test'"
      );
    } else {
      panic!("Invalid aud did not fail validation");
    }
  }

  #[test]
  fn validate_iss_claim() {
    let claims = ValidationClaims {
      iss: Some("test".to_string()),
      ..empty_validations()
    };

    let step = ValidationStep::Issuer("test".to_string());
    assert!(validate_claim(&claims, &step).is_none());

    let step = ValidationStep::Issuer("test2".to_string());
    if let Some(err_str) = validate_claim(&claims, &step) {
      /* assert we get a detailed error string */
      assert_eq!(
        err_str,
        "'iss' does not match; expected 'test2', got 'test'"
      );
    } else {
      panic!("Invalid iss did not fail validation");
    }
  }
}
