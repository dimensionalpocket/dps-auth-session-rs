//! # dps-auth-session
//!
//! A standalone authentication utility struct providing secure token encoding and decoding
//! functionality using AES-256-GCM encryption.
//!
//! ## Features
//!
//! - Secure token encoding/decoding with AES-256-GCM encryption
//! - Session payload management with expiration handling
//! - Comprehensive error handling
//! - No external dependencies on databases or user management
//!
//! ## Usage
//!
//! ```rust
//! use dps_auth_session::{DpsAuthSession, DpsAuthSessionPayload};
//!
//! // Create a session payload
//! let payload = DpsAuthSession::create_payload(123, None);
//!
//! // Encode to token
//! let secret = &[0u8; 32]; // Use a proper 32-byte secret in production
//! let token = DpsAuthSession::encode_token(&payload, secret)?;
//!
//! // Decode token back to payload
//! let decoded = DpsAuthSession::decode_token(&token, secret)?;
//! assert_eq!(payload.sub, decoded.sub);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod error;
pub mod payload;
pub mod session;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::DpsAuthSessionError;
pub use payload::DpsAuthSessionPayload;
pub use session::DpsAuthSession;
