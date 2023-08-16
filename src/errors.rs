//!
//! Error definitions for bbjwt.
//!
//! Copyright (c) 2022 basebox GmbH
//!

/* --- uses ------------------------------------------------------------------------------------- */

use thiserror::Error;

/* --- public types ----------------------------------------------------------------------------- */

pub type BBResult<T> = Result<T, BBError>;

///
/// Errors used in bbjwt
///
#[allow(dead_code)]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BBError {
  #[error("Network/load error: {0}")]
  /// Some network communication failed.
  NetworkError(String),

  #[error("Token could not be parsed: {0}")]
  /// Token has invalid format.
  TokenInvalid(String),

  #[error("Invalid URL: {0}")]
  /// URL is invalid.
  URLInvalid(String),

  #[error("Fatal error: {0}")]
  /// A fatal error, we cannot continue.
  Fatal(String),

  #[error("JSON error: {0}")]
  /// JSON related error.
  JSONError(String),

  #[error("JWK data is invalid: {0}")]
  /// JWK contains invalid data
  JWKInvalid(String),

  #[error("Decoding error: {0}")]
  /// Decoding (base64) failed.
  DecodeError(String),

  #[error("Invalid claim value: {0}")]
  /// A claim did not validate/contained the wrong value.
  ClaimInvalid(String),

  #[error("Invalid signature")]
  /// The signature could not be verified.
  SignatureInvalid,

  #[error("Error: {0}")]
  /// Some other error.
  Other(String),

  #[error("Unknown/unspecified error")]
  /// Something went wrong for an unknown reason; should never be used :-)
  Unknown,
}

impl BBError {
  ///
  /// Return name for each error variant.
  ///
  pub fn name(&self) -> String {
    match self {
      Self::NetworkError(_) => "NetworkError".to_string(),
      Self::TokenInvalid(_) => "TokenInvalid".to_string(),
      Self::URLInvalid(_) => "URLInvalid".to_string(),
      Self::JWKInvalid(_) => "JWKInvalid".to_string(),
      Self::Fatal(_) => "Fatal".to_string(),
      Self::DecodeError(_) => "DecodeError".to_string(),
      Self::JSONError(_) => "JSONError".to_string(),
      Self::ClaimInvalid(_) => "ClaimInvalid".to_string(),
      Self::SignatureInvalid => "SignatureInvalid".to_string(),
      Self::Other(_) => "Other".to_string(),
      Self::Unknown => "Unknown".to_string(),
    }
  }
}

impl From<base64::DecodeError> for BBError {
  fn from(err: base64::DecodeError) -> Self {
    BBError::DecodeError(err.to_string())
  }
}

impl From<serde_json::Error> for BBError {
  fn from(err: serde_json::Error) -> Self {
    BBError::JSONError(err.to_string())
  }
}
