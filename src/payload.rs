use serde::{Deserialize, Serialize};

/// Session payload structure containing user session information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DpsAuthSessionPayload {
  /// Subject - user ID
  pub sub: i64,
  /// Issued at timestamp (seconds since epoch)
  pub iat: i64,
  /// Expiration timestamp (seconds since epoch)
  pub exp: i64,
}
