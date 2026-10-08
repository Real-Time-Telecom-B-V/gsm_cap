//! CAP operation arguments and results (3GPP TS 29.078). Each type derives
//! `rasn` BER `Encode`/`Decode`; a consumer wraps them in TCAP components with
//! the matching [operation code](crate::op_codes).

use rasn::prelude::*;

use crate::types::{
    BcsmEvent, CallReferenceNumber, CalledPartyBcdNumber, CalledPartyNumber, CallingPartyNumber,
    Cause, EventSpecificInformationBcsm, EventTypeBcsm, EventTypeSms, Extensions, Imsi,
    IsdnAddressString, LocationInformation, MiscCallInfo, OriginalCalledPartyId, ReceivingSideId,
    RedirectingPartyId, ServiceKey, SmsEvent,
};

// ── Call control ────────────────────────────────────────────────────────────

/// InitialDP (op 0) — gsmSSF reports a triggered call to the gsmSCF. Tags are
/// from the CAP ASN.1 (distinct from MAP); fields ascend by tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InitialDpArg {
    #[rasn(tag(context, 0))]
    pub service_key: ServiceKey,
    #[rasn(tag(context, 2))]
    pub called_party_number: Option<CalledPartyNumber>,
    #[rasn(tag(context, 3))]
    pub calling_party_number: Option<CallingPartyNumber>,
    #[rasn(tag(context, 5))]
    pub calling_partys_category: Option<OctetString>,
    #[rasn(tag(context, 12))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 28))]
    pub event_type_bcsm: Option<EventTypeBcsm>,
    #[rasn(tag(context, 29))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 50))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 52))]
    pub location_information: Option<LocationInformation>,
    #[rasn(tag(context, 54))]
    pub call_reference_number: Option<CallReferenceNumber>,
    #[rasn(tag(context, 55))]
    pub msc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 56))]
    pub called_party_bcd_number: Option<CalledPartyBcdNumber>,
    #[rasn(tag(context, 57))]
    pub time_and_timezone: Option<OctetString>,
}

impl InitialDpArg {
    /// An InitialDP for `service_key` with every optional member absent.
    pub fn new(service_key: ServiceKey) -> Self {
        Self {
            service_key,
            called_party_number: None,
            calling_party_number: None,
            calling_partys_category: None,
            original_called_party_id: None,
            event_type_bcsm: None,
            redirecting_party_id: None,
            imsi: None,
            location_information: None,
            call_reference_number: None,
            msc_address: None,
            called_party_bcd_number: None,
            time_and_timezone: None,
        }
    }
}

/// Connect (op 20) — gsmSCF instructs the gsmSSF to route the call.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectArg {
    #[rasn(tag(context, 0))]
    pub destination_routing_address: Vec<CalledPartyNumber>,
    #[rasn(tag(context, 4))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 6))]
    pub calling_partys_category: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 11))]
    pub generic_numbers: Option<Vec<OctetString>>,
}

impl ConnectArg {
    /// A Connect to `destination` with every optional member absent.
    pub fn new(destination: CalledPartyNumber) -> Self {
        Self {
            destination_routing_address: vec![destination],
            original_called_party_id: None,
            calling_partys_category: None,
            redirecting_party_id: None,
            generic_numbers: None,
        }
    }
}

/// ReleaseCall (op 22) — gsmSCF instructs the gsmSSF to release the call. In CAP
/// the argument is a bare `Cause` (Q.850), not a SEQUENCE, so this is a delegate
/// newtype: it BER-encodes as the inner OCTET STRING (matching `inap`'s
/// `ReleaseCallArg`). A named-field struct here would emit an extra SEQUENCE
/// wrapper that a conforming peer / dissector rejects as malformed.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct ReleaseCallArg(pub Cause);

/// Cancel (op 53).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum CancelArg {
    #[rasn(tag(context, 0))]
    InvokeId(Integer),
    #[rasn(tag(context, 1))]
    AllRequests(()),
}

// ── Event reporting ─────────────────────────────────────────────────────────

/// RequestReportBCSMEvent (op 23): the gsmSCF arms detection points.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestReportBcsmEventArg {
    #[rasn(tag(context, 0))]
    pub bcsm_events: Vec<BcsmEvent>,
    #[rasn(tag(context, 2))]
    pub extensions: Option<Extensions>,
}

impl RequestReportBcsmEventArg {
    /// An argument arming `bcsm_events`, without extensions.
    pub fn new(bcsm_events: Vec<BcsmEvent>) -> Self {
        Self {
            bcsm_events,
            extensions: None,
        }
    }
}

/// EventReportBCSM (op 24): the gsmSSF reports a detection point.
///
/// ```text
/// EventReportBCSMArg ::= SEQUENCE {
///   eventTypeBCSM                [0] EventTypeBCSM,
///   eventSpecificInformationBCSM [2] EventSpecificInformationBCSM OPTIONAL,  -- CHOICE: explicit
///   legID                        [3] ReceivingSideID OPTIONAL,               -- CHOICE: explicit
///   miscCallInfo                 [4] MiscCallInfo DEFAULT {messageType request},
///   extensions                   [5] Extensions OPTIONAL,
///   ...}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EventReportBcsmArg {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    #[rasn(tag(explicit(context, 2)))]
    pub event_specific_information_bcsm: Option<EventSpecificInformationBcsm>,
    #[rasn(tag(explicit(context, 3)))]
    pub leg_id: Option<ReceivingSideId>,
    /// `DEFAULT {messageType request}`.
    #[rasn(tag(context, 4))]
    pub misc_call_info: Option<MiscCallInfo>,
    #[rasn(tag(context, 5))]
    pub extensions: Option<Extensions>,
}

impl EventReportBcsmArg {
    /// A report of `event_type_bcsm` with every optional member absent.
    pub fn new(event_type_bcsm: EventTypeBcsm) -> Self {
        Self {
            event_type_bcsm,
            event_specific_information_bcsm: None,
            leg_id: None,
            misc_call_info: None,
            extensions: None,
        }
    }
}

// ── Charging ────────────────────────────────────────────────────────────────

/// ApplyCharging (op 35).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ApplyChargingArg {
    #[rasn(tag(context, 0))]
    pub ach_billing_charging_characteristics: OctetString,
    #[rasn(tag(context, 2))]
    pub party_to_charge: Option<OctetString>,
}

impl ApplyChargingArg {
    /// An ApplyCharging carrying `characteristics` with every optional member
    /// absent.
    pub fn new(characteristics: OctetString) -> Self {
        Self {
            ach_billing_charging_characteristics: characteristics,
            party_to_charge: None,
        }
    }
}

/// ApplyChargingReport (op 36).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ApplyChargingReportArg {
    /// Encoded call result.
    pub call_result: OctetString,
}

/// FurnishChargingInformation (op 34).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct FurnishChargingInformationArg {
    pub fci_billing_charging_characteristics: OctetString,
}

// ── Specialised resources + call-to-resource (shared with INAP) ──────────────

// These user-interaction operations are byte-identical between CAP and INAP
// CS-2, so they are re-exported from the canonical `inap` crate rather than
// duplicated: `ConnectToResourceArg` (op 19), `PlayAnnouncementArg` (op 47) and
// `PromptAndCollectUserInformationArg` / `…Res` (op 48). Same field names, tags
// and wire encoding.
pub use inap::operations::{
    ConnectToResourceArg, PlayAnnouncementArg, PromptAndCollectUserInformationArg,
    PromptAndCollectUserInformationRes,
};

// ── CAMEL for SMS (CAP v3+) ─────────────────────────────────────────────────

/// InitialDPSMS (op 60).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InitialDpSmsArg {
    #[rasn(tag(context, 0))]
    pub service_key: ServiceKey,
    #[rasn(tag(context, 1))]
    pub destination_subscriber_number: Option<CalledPartyBcdNumber>,
    #[rasn(tag(context, 2))]
    pub calling_party_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 3))]
    pub event_type_sms: Option<EventTypeSms>,
    #[rasn(tag(context, 4))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 5))]
    pub location_information_msc: Option<LocationInformation>,
    #[rasn(tag(context, 6))]
    pub smsc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 7))]
    pub time_and_timezone: Option<OctetString>,
    #[rasn(tag(context, 8))]
    pub tp_short_message_specific_info: Option<OctetString>,
    #[rasn(tag(context, 9))]
    pub tp_protocol_identifier: Option<OctetString>,
    #[rasn(tag(context, 10))]
    pub tp_data_coding_scheme: Option<OctetString>,
    #[rasn(tag(context, 11))]
    pub tp_validity_period: Option<OctetString>,
    #[rasn(tag(context, 13))]
    pub sms_reference_number: Option<CallReferenceNumber>,
    #[rasn(tag(context, 14))]
    pub msc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 15))]
    pub sgsn_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 16))]
    pub ms_classmark2: Option<OctetString>,
}

impl InitialDpSmsArg {
    /// An InitialDPSMS for `service_key` with every optional member absent.
    pub fn new(service_key: ServiceKey) -> Self {
        Self {
            service_key,
            destination_subscriber_number: None,
            calling_party_number: None,
            event_type_sms: None,
            imsi: None,
            location_information_msc: None,
            smsc_address: None,
            time_and_timezone: None,
            tp_short_message_specific_info: None,
            tp_protocol_identifier: None,
            tp_data_coding_scheme: None,
            tp_validity_period: None,
            sms_reference_number: None,
            msc_address: None,
            sgsn_number: None,
            ms_classmark2: None,
        }
    }
}

/// ConnectSMS (op 61).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectSmsArg {
    #[rasn(tag(context, 0))]
    pub calling_partys_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub destination_subscriber_number: Option<CalledPartyBcdNumber>,
    #[rasn(tag(context, 2))]
    pub smsc_address: Option<IsdnAddressString>,
}

/// ReleaseSMS (op 62).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReleaseSmsArg {
    /// RP-Cause value.
    pub rp_cause: OctetString,
}

/// RequestReportSMSEvent (op 63).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestReportSmsEventArg {
    #[rasn(tag(context, 0))]
    pub sms_events: Vec<SmsEvent>,
}

/// EventReportSMS (op 64).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EventReportSmsArg {
    #[rasn(tag(context, 0))]
    pub event_type_sms: EventTypeSms,
    #[rasn(tag(context, 1))]
    pub event_specific_information_sms: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub misc_call_info: Option<OctetString>,
}
