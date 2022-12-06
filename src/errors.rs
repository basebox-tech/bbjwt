//!
//! Error definitions for bbjwt.
//!
//! Author: Markus Thielen <markus.thielen@basebox.tech>
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

  #[error("Token validation failed: {0}")]
  /// Token validation failed.
  TokenInvalid(String),

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
      Self::NetworkError(..) => "NetworkError".to_string(),
      Self::TokenInvalid(..) => "TokenInvalid".to_string(),
      Self::Other(..) => "Other".to_string(),
      Self::Unknown => "Unknown".to_string(),
    }
  }
}
