# @dimensionalpocket/dps-auth-session

[![Rust Tests](https://github.com/dimensionalpocket/dps-auth-session-rs/actions/workflows/test.yml/badge.svg)](https://github.com/dimensionalpocket/dps-auth-session-rs/actions/workflows/test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A standalone Rust crate for secure session token management using AES-256-GCM encryption.

## Features

- **Secure Token Encoding/Decoding**: Uses AES-256-GCM encryption with random nonces
- **Session Payload Management**: Handles user ID and timestamp information
- **Expiration Validation**: Automatically validates token expiration
- **Comprehensive Error Handling**: Detailed error types for different failure scenarios
- **Zero External Dependencies**: No database or user management dependencies

## Usage

Add this to your `Cargo.toml`:

<!-- x-release-please-start-version -->
```toml
[dependencies]
dps-auth-session = { git = "https://github.com/dimensionalpocket/dps-auth-session-rs", tag = "0.1.0" }
```
<!-- x-release-please-end -->

### Basic Example

```rust
use dps_auth_session::{DpsAuthSession, DpsAuthSessionPayload, DpsAuthSessionError};

fn main() -> Result<(), DpsAuthSessionError> {
    // Use a proper 32-byte secret key in production
    let secret = &[0u8; 32];
    
    // Create a session payload for user ID 123
    let payload = DpsAuthSession::create_payload(123, None);
    println!("Created session for user: {}", payload.sub);
    
    // Encode the payload into a secure token
    let token = DpsAuthSession::encode_token(&payload, secret)?;
    println!("Generated token: {}", token);
    
    // Decode the token back to payload
    let decoded_payload = DpsAuthSession::decode_token(&token, secret)?;
    println!("Decoded user ID: {}", decoded_payload.sub);
    
    assert_eq!(payload.sub, decoded_payload.sub);
    Ok(())
}
```

### Error Handling

```rust
use dps_auth_session::{DpsAuthSession, DpsAuthSessionError};

let secret = &[0u8; 32];
let invalid_token = "invalid-token";

match DpsAuthSession::decode_token(invalid_token, secret) {
    Ok(payload) => println!("Valid token for user: {}", payload.sub),
    Err(DpsAuthSessionError::TokenExpired) => println!("Token has expired"),
    Err(DpsAuthSessionError::InvalidToken(msg)) => println!("Invalid token: {}", msg),
    Err(DpsAuthSessionError::DecodingError(msg)) => println!("Decoding failed: {}", msg),
    Err(e) => println!("Other error: {}", e),
}
```

## API Reference

### `DpsAuthSession`

The main struct providing static methods for token operations.

#### Methods

- `create_payload(user_id: i64, expiration_seconds: Option<i64>) -> DpsAuthSessionPayload`
  - Creates a new session payload with current timestamp. If `expiration_seconds` is `None`, the default of 3 days is used. If `Some(n)` and `n > 0`, the token expires `n` seconds after issuance.
  
- `encode_token(payload: &DpsAuthSessionPayload, secret: &[u8]) -> Result<String, DpsAuthSessionError>`
  - Encrypts a session payload into a base64-encoded token
  - Requires a 32-byte secret key for AES-256-GCM encryption
  
- `decode_token(token: &str, secret: &[u8]) -> Result<DpsAuthSessionPayload, DpsAuthSessionError>`
  - Decrypts and validates a token, returning the session payload
  - Automatically checks for token expiration

### `DpsAuthSessionPayload`

Session information structure.

#### Fields

- `sub: i64` - Subject (user ID)
- `iat: i64` - Issued at timestamp (seconds since Unix epoch)
- `exp: i64` - Expiration timestamp (seconds since Unix epoch)

### `DpsAuthSessionError`

Error types for session operations.

#### Variants

- `EncodingError(String)` - Token encoding failed
- `DecodingError(String)` - Token decoding failed  
- `TokenExpired` - Token has expired
- `InvalidToken(String)` - Invalid token format
- `JsonError(String)` - JSON serialization/deserialization error

## Security Considerations

- **Secret Key**: Use a cryptographically secure 32-byte secret key
- **Key Rotation**: Consider implementing key rotation for long-running applications
- **Token Storage**: Store tokens securely (HTTPS only cookies, secure headers)
- **Expiration**: Default 3-day expiration can be customized by creating payloads manually

## Testing

Run the test suite:

```bash
cargo test
```

The crate includes comprehensive unit and integration tests covering:
- Token encoding/decoding roundtrips
- Expiration validation
- Error conditions
- Edge cases (large user IDs, invalid tokens, etc.)

## License

MIT License - see [LICENSE](./LICENSE) file for details.
