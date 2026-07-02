//! Errors for CAP operation encoding/decoding.

/// An error encoding or decoding a CAP operation.
#[derive(Debug, thiserror::Error)]
pub enum CapError {
    /// BER encoding failed.
    #[error("CAP encode error: {0}")]
    Encode(String),
    /// BER decoding failed.
    #[error("CAP decode error: {0}")]
    Decode(String),
    /// The operation code is not a known CAP operation.
    #[error("unknown CAP operation code: {0}")]
    UnknownOperation(i64),
}
