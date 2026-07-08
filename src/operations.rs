//! CAP operation arguments and results (3GPP TS 29.078). Each type derives
//! `rasn` BER `Encode`/`Decode`; a consumer wraps them in TCAP components with
//! the matching [operation code](crate::op_codes).

use rasn::prelude::*;

use crate::types::{
    BcsmEvent, CallReferenceNumber, CalledPartyBcdNumber, CalledPartyNumber, CallingPartyNumber,
    Cause, EventTypeBcsm, EventTypeSms, Imsi, IsdnAddressString, LocationInformation,
    OriginalCalledPartyId, RedirectingPartyId, ServiceKey, SmsEvent,
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

/// ReleaseCall (op 22) — gsmSCF instructs the gsmSSF to release the call.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReleaseCallArg {
    /// Q.850 cause value.
    pub cause: Cause,
}

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

/// RequestReportBCSMEvent (op 23).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestReportBcsmEventArg {
    #[rasn(tag(context, 0))]
    pub bcsm_events: Vec<BcsmEvent>,
}

/// EventReportBCSM (op 24) — gsmSSF reports a BCSM event to the gsmSCF.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EventReportBcsmArg {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    #[rasn(tag(context, 2))]
    pub leg_id: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub misc_call_info: Option<OctetString>,
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
