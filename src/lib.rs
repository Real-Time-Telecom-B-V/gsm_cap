//! # gsm_cap
//!
//! **CAMEL Application Part (CAP)** operation codec, 3GPP TS 29.078. BER
//! encode/decode of the gsmSSF ↔ gsmSCF operations that drive CAMEL Intelligent
//! Network services (prepaid call control, service triggering, charging, and
//! CAMEL control of SMS).
//!
//! CAP rides on TCAP over SCCP; this crate is the **operation layer**: the
//! argument/result types (via [`rasn`] ASN.1 BER), the
//! [operation codes](op_codes) and the
//! [application-context names](application_context). A consumer wraps a CAP
//! argument in a TCAP Invoke with the matching operation code; the surrounding
//! dialogue (application context, transaction IDs) is the TCAP layer's job.
//!
//! ```
//! use gsm_cap::operations::EventReportBcsmArg;
//! use gsm_cap::types::{EventTypeBcsm, MiscCallInfo, ReceivingSideId, LEG2};
//!
//! // gsmSSF → gsmSCF: the called party answered.
//! let report = EventReportBcsmArg {
//!     leg_id: Some(ReceivingSideId::leg(LEG2)),
//!     misc_call_info: Some(MiscCallInfo::notification()),
//!     ..EventReportBcsmArg::new(EventTypeBcsm::OAnswer)
//! };
//! let ber = gsm_cap::encode(&report).unwrap();
//! // eventTypeBCSM [0] oAnswer(7); legID [3] EXPLICIT { receivingSideID [1]
//! // leg2 }; miscCallInfo [4] { messageType [0] notification(1) }.
//! assert_eq!(
//!     ber,
//!     [0x30, 0x0d, 0x80, 0x01, 0x07, 0xa3, 0x03, 0x81, 0x01, 0x02, 0xa4, 0x03, 0x80, 0x01, 0x01]
//! );
//! let back: EventReportBcsmArg = gsm_cap::decode(&ber).unwrap();
//! assert_eq!(report, back);
//! ```
//!
//! ## What the encodings are checked against
//!
//! The types follow the ASN.1 of TS 29.078 V18.0.0 and, for the imported MAP
//! types, TS 29.002 V18.0.0. A round-trip through this crate cannot show that
//! an encoding is the specified one (a mistake shared by the encoder and the
//! decoder passes it), so the test suite checks every argument two other ways:
//! against a byte vector assembled by hand from the ASN.1, and by handing the
//! encoding to Wireshark's CAMEL dissector and asserting the fields it reads
//! back.
//!
//! (See [`operations`] for the full set and [`op_codes`] for the codes.)

pub mod application_context;
pub mod error;
pub mod op_codes;
pub mod operations;
mod strict;
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
///
/// Decoding is strict about one thing `rasn` is not: a member that is present
/// on the wire but whose content cannot be read is an error, never a silently
/// absent member. `rasn` 0.28 reports an OPTIONAL member behind an EXPLICIT
/// tag as absent when its content fails to decode, and in CAP that is every
/// member whose type is a CHOICE. The guard encodes the decoded value again
/// and checks that it accounts for every element on the wire, so a decode
/// costs one extra encode. `rasn::ber::decode` on the same types skips it.
pub fn decode<T: rasn::Decode + rasn::Encode>(bytes: &[u8]) -> Result<T, CapError> {
    let value: T = rasn::ber::decode(bytes).map_err(|e| CapError::Decode(e.to_string()))?;
    let canonical = rasn::ber::encode(&value).map_err(|e| CapError::Decode(e.to_string()))?;
    strict::nothing_dropped(bytes, &canonical).map_err(CapError::Decode)?;
    Ok(value)
}
