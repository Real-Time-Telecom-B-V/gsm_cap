//! # cap
//!
//! **CAMEL Application Part (CAP)** operation codec — 3GPP TS 29.078. BER
//! encode/decode of the gsmSSF ↔ gsmSCF operations that drive CAMEL Intelligent
//! Network services (prepaid call control, service triggering, charging, and
//! CAMEL-for-SMS).
//!
//! CAP rides on TCAP over SCCP; this crate is the **operation layer** — the
//! argument/result types (via [`rasn`] ASN.1 BER) and the
//! [operation codes](op_codes). A consumer wraps a CAP argument in a TCAP Invoke
//! with the matching operation code; the surrounding dialogue (application
//! context, transaction IDs) is the TCAP layer's job.
//!
//! ```
//! use gsm_cap::operations::ReleaseCallArg;
//!
//! // gsmSCF → gsmSSF: release the call with a Q.850 cause (synthetic bytes).
//! let rel = ReleaseCallArg(vec![0x90, 0x03].into());
//! let ber = gsm_cap::encode(&rel).unwrap();
//! let back: ReleaseCallArg = gsm_cap::decode(&ber).unwrap();
//! assert_eq!(rel, back);
//! ```
//!
//! (See [`operations`] for the full set and [`op_codes`] for the codes.)

pub mod application_context;
pub mod error;
pub mod op_codes;
pub mod operations;
pub mod types;

#[cfg(feature = "python")]
pub mod python;

pub use error::CapError;
pub use op_codes::operation_name;

#[cfg(feature = "python")]
pub use python::register;

/// Encode a CAP operation argument/result to BER.
pub fn encode<T: rasn::Encode>(value: &T) -> Result<Vec<u8>, CapError> {
    rasn::ber::encode(value).map_err(|e| CapError::Encode(e.to_string()))
}

/// Decode a CAP operation argument/result from BER.
pub fn decode<T: rasn::Decode>(bytes: &[u8]) -> Result<T, CapError> {
    rasn::ber::decode(bytes).map_err(|e| CapError::Decode(e.to_string()))
}
