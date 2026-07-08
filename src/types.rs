//! Common CAP types (3GPP TS 29.078). Addresses are carried as `OCTET STRING`s
//! in their respective ITU-T / 3GPP wire formats (Q.763, TS 24.008, TBCD).
//!
//! CAP was derived from INAP CS-2, so a family of leaf IEs is byte-identical
//! between the two. Those are re-exported from the [`inap`] crate (the canonical
//! home) rather than duplicated here, with the same names and wire encoding:
//! [`CalledPartyNumber`], [`CallingPartyNumber`], [`Cause`], [`EventTypeBcsm`],
//! [`MonitorMode`] and [`BcsmEvent`].

use rasn::prelude::*;

// ── Shared IN/CS-2 leaf IEs, re-exported from the canonical `inap` crate ──────
pub use inap::types::{
    BcsmEvent, CalledPartyNumber, CallingPartyNumber, Cause, EventTypeBcsm, MonitorMode,
};

/// Identifies the CAMEL service logic at the gsmSCF.
pub type ServiceKey = Integer;
/// Uniquely identifies a call at the gsmSSF.
pub type CallReferenceNumber = OctetString;
/// Called party number, 3GPP TS 24.008 BCD format.
pub type CalledPartyBcdNumber = OctetString;
/// Location number, Q.763 format.
pub type LocationNumber = OctetString;
/// Original called party ID, Q.763 format.
pub type OriginalCalledPartyId = OctetString;
/// Redirecting party ID, Q.763 format.
pub type RedirectingPartyId = OctetString;
/// IMSI (TBCD in an OCTET STRING).
pub type Imsi = OctetString;
/// ISDN-AddressString (TBCD: byte 0 = NPI/TON, then digits).
pub type IsdnAddressString = OctetString;

/// LocationInformation (TS 29.002). `ageOfLocationInformation` is an untagged
/// plain INTEGER.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationInformation {
    pub age_of_location_information: Option<Integer>,
    #[rasn(tag(context, 0))]
    pub geographical_information: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 2))]
    pub location_number: Option<LocationNumber>,
    #[rasn(tag(context, 3))]
    pub cell_global_id_or_service_area_id_or_lai: Option<OctetString>,
    #[rasn(tag(context, 8))]
    pub msc_number: Option<IsdnAddressString>,
}

/// EventTypeSMS — SMS detection-point events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EventTypeSms {
    SmsCollectedInfo = 1,
    OSmsFailure = 2,
    OSmsSubmission = 3,
    SmsDeliveryRequested = 11,
    TSmsFailure = 12,
    TSmsDelivery = 13,
}

/// SMSEvent — SMS event detection-point configuration.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SmsEvent {
    #[rasn(tag(context, 0))]
    pub event_type_sms: EventTypeSms,
    #[rasn(tag(context, 1))]
    pub monitor_mode: MonitorMode,
}
