use std::fmt;

/// Error types for session token operations
#[derive(Debug)]
pub enum DpsAuthSessionError {
  /// Token encoding failed
  EncodingError(String),
  /// Token decoding failed
  DecodingError(String),
  /// Token has expired
  TokenExpired,
  /// Invalid token format
  InvalidToken(String),
  /// JSON serialization/deserialization error
  JsonError(String),
}

impl fmt::Display for DpsAuthSessionError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      DpsAuthSessionError::EncodingError(msg) => write!(f, "Token encoding error: {msg}"),
      DpsAuthSessionError::DecodingError(msg) => write!(f, "Token decoding error: {msg}"),
      DpsAuthSessionError::TokenExpired => write!(f, "Token has expired"),
      DpsAuthSessionError::InvalidToken(msg) => write!(f, "Invalid token: {msg}"),
      DpsAuthSessionError::JsonError(msg) => write!(f, "JSON error: {msg}"),
    }
  }
}

impl std::error::Error for DpsAuthSessionError {}
