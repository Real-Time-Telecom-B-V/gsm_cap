//! CAP operation arguments and results (3GPP TS 29.078). Each type derives
//! `rasn` BER `Encode`/`Decode`; a consumer wraps them in TCAP components with
//! the matching [operation code](crate::op_codes).

use rasn::prelude::*;

use crate::error::CapError;
use crate::types::{
    AChChargingAddress, AdditionalCallingPartyNumber, AlertingPattern, BcsmEvent, BearerCapability,
    CallReferenceNumber, CalledPartyBcdNumber, CalledPartyNumber, CallingPartyNumber,
    CallingPartysCategory, CamelCallResult, CamelFciBillingChargingCharacteristics, Carrier, Cause,
    CgEncountered, ChargeNumber, CugInterlock, EventSpecificInformationBcsm, EventTypeBcsm,
    EventTypeSms, ExtBasicServiceCode, Extensions, GenericNumbers, HighLayerCompatibility, Imsi,
    InitialDpArgExtension, IpSspCapabilities, IsdnAddressString, LegId, LocationInformation,
    LocationNumber, MiscCallInfo, NaOliInfo, OriginalCalledPartyId, ReceivingSideId,
    RedirectingPartyId, RedirectionInformation, SendingSideId, ServiceInteractionIndicatorsTwo,
    ServiceKey, SmsEvent, SubscriberState, TimeAndTimezone,
};

// ── Call control ────────────────────────────────────────────────────────────

/// InitialDP (op 0): the gsmSSF reports a triggered call to the gsmSCF.
///
/// The members are encoded in the order the ASN.1 lists them, which is not
/// ascending tag order: `cause [17]` follows `redirectionInformation [30]`.
///
/// ```text
/// InitialDPArg ::= SEQUENCE {
///   serviceKey                      [0]  ServiceKey,
///   calledPartyNumber               [2]  CalledPartyNumber OPTIONAL,
///   callingPartyNumber              [3]  CallingPartyNumber OPTIONAL,
///   callingPartysCategory           [5]  CallingPartysCategory OPTIONAL,
///   cGEncountered                   [7]  CGEncountered OPTIONAL,
///   iPSSPCapabilities               [8]  IPSSPCapabilities OPTIONAL,
///   locationNumber                  [10] LocationNumber OPTIONAL,
///   originalCalledPartyID           [12] OriginalCalledPartyID OPTIONAL,
///   extensions                      [15] Extensions OPTIONAL,
///   highLayerCompatibility          [23] HighLayerCompatibility OPTIONAL,
///   additionalCallingPartyNumber    [25] AdditionalCallingPartyNumber OPTIONAL,
///   bearerCapability                [27] BearerCapability OPTIONAL,      -- CHOICE: explicit
///   eventTypeBCSM                   [28] EventTypeBCSM OPTIONAL,
///   redirectingPartyID              [29] RedirectingPartyID OPTIONAL,
///   redirectionInformation          [30] RedirectionInformation OPTIONAL,
///   cause                           [17] Cause OPTIONAL,
///   serviceInteractionIndicatorsTwo [32] ServiceInteractionIndicatorsTwo OPTIONAL,
///   carrier                         [37] Carrier OPTIONAL,
///   cug-Index                       [45] CUG-Index OPTIONAL,
///   cug-Interlock                   [46] CUG-Interlock OPTIONAL,
///   cug-OutgoingAccess              [47] NULL OPTIONAL,
///   iMSI                            [50] IMSI OPTIONAL,
///   subscriberState                 [51] SubscriberState OPTIONAL,       -- CHOICE: explicit
///   locationInformation             [52] LocationInformation OPTIONAL,
///   ext-basicServiceCode            [53] Ext-BasicServiceCode OPTIONAL,  -- CHOICE: explicit
///   callReferenceNumber             [54] CallReferenceNumber OPTIONAL,
///   mscAddress                      [55] ISDN-AddressString OPTIONAL,
///   calledPartyBCDNumber            [56] CalledPartyBCDNumber OPTIONAL,
///   timeAndTimezone                 [57] TimeAndTimezone OPTIONAL,
///   callForwardingSS-Pending        [58] NULL OPTIONAL,
///   initialDPArgExtension           [59] InitialDPArgExtension OPTIONAL,
///   ...}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InitialDpArg {
    #[rasn(tag(context, 0))]
    pub service_key: ServiceKey,
    #[rasn(tag(context, 2))]
    pub called_party_number: Option<CalledPartyNumber>,
    #[rasn(tag(context, 3))]
    pub calling_party_number: Option<CallingPartyNumber>,
    #[rasn(tag(context, 5))]
    pub calling_partys_category: Option<CallingPartysCategory>,
    #[rasn(tag(context, 7))]
    pub cg_encountered: Option<CgEncountered>,
    #[rasn(tag(context, 8))]
    pub ip_ssp_capabilities: Option<IpSspCapabilities>,
    #[rasn(tag(context, 10))]
    pub location_number: Option<LocationNumber>,
    #[rasn(tag(context, 12))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 15))]
    pub extensions: Option<Extensions>,
    #[rasn(tag(context, 23))]
    pub high_layer_compatibility: Option<HighLayerCompatibility>,
    #[rasn(tag(context, 25))]
    pub additional_calling_party_number: Option<AdditionalCallingPartyNumber>,
    #[rasn(tag(explicit(context, 27)))]
    pub bearer_capability: Option<BearerCapability>,
    #[rasn(tag(context, 28))]
    pub event_type_bcsm: Option<EventTypeBcsm>,
    #[rasn(tag(context, 29))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 30))]
    pub redirection_information: Option<RedirectionInformation>,
    #[rasn(tag(context, 17))]
    pub cause: Option<Cause>,
    #[rasn(tag(context, 32))]
    pub service_interaction_indicators_two: Option<ServiceInteractionIndicatorsTwo>,
    #[rasn(tag(context, 37))]
    pub carrier: Option<Carrier>,
    /// CUG-Index, INTEGER (0..32767).
    #[rasn(tag(context, 45))]
    pub cug_index: Option<u16>,
    #[rasn(tag(context, 46))]
    pub cug_interlock: Option<CugInterlock>,
    #[rasn(tag(context, 47))]
    pub cug_outgoing_access: Option<()>,
    #[rasn(tag(context, 50))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(explicit(context, 51)))]
    pub subscriber_state: Option<SubscriberState>,
    #[rasn(tag(context, 52))]
    pub location_information: Option<LocationInformation>,
    #[rasn(tag(explicit(context, 53)))]
    pub ext_basic_service_code: Option<ExtBasicServiceCode>,
    #[rasn(tag(context, 54))]
    pub call_reference_number: Option<CallReferenceNumber>,
    #[rasn(tag(context, 55))]
    pub msc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 56))]
    pub called_party_bcd_number: Option<CalledPartyBcdNumber>,
    #[rasn(tag(context, 57))]
    pub time_and_timezone: Option<TimeAndTimezone>,
    #[rasn(tag(context, 58))]
    pub call_forwarding_ss_pending: Option<()>,
    #[rasn(tag(context, 59))]
    pub initial_dp_arg_extension: Option<InitialDpArgExtension>,
}

impl InitialDpArg {
    /// An InitialDP for `service_key` with every optional member absent.
    pub fn new(service_key: ServiceKey) -> Self {
        Self {
            service_key,
            called_party_number: None,
            calling_party_number: None,
            calling_partys_category: None,
            cg_encountered: None,
            ip_ssp_capabilities: None,
            location_number: None,
            original_called_party_id: None,
            extensions: None,
            high_layer_compatibility: None,
            additional_calling_party_number: None,
            bearer_capability: None,
            event_type_bcsm: None,
            redirecting_party_id: None,
            redirection_information: None,
            cause: None,
            service_interaction_indicators_two: None,
            carrier: None,
            cug_index: None,
            cug_interlock: None,
            cug_outgoing_access: None,
            imsi: None,
            subscriber_state: None,
            location_information: None,
            ext_basic_service_code: None,
            call_reference_number: None,
            msc_address: None,
            called_party_bcd_number: None,
            time_and_timezone: None,
            call_forwarding_ss_pending: None,
            initial_dp_arg_extension: None,
        }
    }
}

/// Connect (op 20): the gsmSCF routes the call.
///
/// The members are encoded in the order the ASN.1 lists them, which is not
/// ascending tag order: `[28] [29] [30]` come before `[14]`.
///
/// ```text
/// ConnectArg ::= SEQUENCE {
///   destinationRoutingAddress       [0]  DestinationRoutingAddress,
///   alertingPattern                 [1]  AlertingPattern OPTIONAL,
///   originalCalledPartyID           [6]  OriginalCalledPartyID OPTIONAL,
///   extensions                      [10] Extensions OPTIONAL,
///   carrier                         [11] Carrier OPTIONAL,
///   callingPartysCategory           [28] CallingPartysCategory OPTIONAL,
///   redirectingPartyID              [29] RedirectingPartyID OPTIONAL,
///   redirectionInformation          [30] RedirectionInformation OPTIONAL,
///   genericNumbers                  [14] GenericNumbers OPTIONAL,
///   serviceInteractionIndicatorsTwo [15] ServiceInteractionIndicatorsTwo OPTIONAL,
///   chargeNumber                    [19] ChargeNumber OPTIONAL,
///   legToBeConnected                [21] LegID OPTIONAL,          -- CHOICE: explicit
///   cug-Interlock                   [31] CUG-Interlock OPTIONAL,
///   cug-OutgoingAccess              [32] NULL OPTIONAL,
///   suppressionOfAnnouncement       [55] SuppressionOfAnnouncement OPTIONAL,
///   oCSIApplicable                  [56] OCSIApplicable OPTIONAL,
///   naOliInfo                       [57] NAOliInfo OPTIONAL,
///   bor-InterrogationRequested      [58] NULL OPTIONAL,
///   ...,
///   suppress-N-CSI                  [59] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectArg {
    /// `SEQUENCE SIZE (1) OF CalledPartyNumber`: exactly one address.
    #[rasn(tag(context, 0))]
    pub destination_routing_address: Vec<CalledPartyNumber>,
    #[rasn(tag(context, 1))]
    pub alerting_pattern: Option<AlertingPattern>,
    #[rasn(tag(context, 6))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 10))]
    pub extensions: Option<Extensions>,
    #[rasn(tag(context, 11))]
    pub carrier: Option<Carrier>,
    #[rasn(tag(context, 28))]
    pub calling_partys_category: Option<CallingPartysCategory>,
    #[rasn(tag(context, 29))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 30))]
    pub redirection_information: Option<RedirectionInformation>,
    #[rasn(tag(context, 14))]
    pub generic_numbers: Option<GenericNumbers>,
    #[rasn(tag(context, 15))]
    pub service_interaction_indicators_two: Option<ServiceInteractionIndicatorsTwo>,
    #[rasn(tag(context, 19))]
    pub charge_number: Option<ChargeNumber>,
    #[rasn(tag(explicit(context, 21)))]
    pub leg_to_be_connected: Option<LegId>,
    #[rasn(tag(context, 31))]
    pub cug_interlock: Option<CugInterlock>,
    #[rasn(tag(context, 32))]
    pub cug_outgoing_access: Option<()>,
    #[rasn(tag(context, 55))]
    pub suppression_of_announcement: Option<()>,
    #[rasn(tag(context, 56))]
    pub o_csi_applicable: Option<()>,
    #[rasn(tag(context, 57))]
    pub na_oli_info: Option<NaOliInfo>,
    #[rasn(tag(context, 58))]
    pub bor_interrogation_requested: Option<()>,
    #[rasn(tag(context, 59))]
    pub suppress_n_csi: Option<()>,
}

impl ConnectArg {
    /// A Connect to `destination` with every optional member absent.
    pub fn new(destination: CalledPartyNumber) -> Self {
        Self {
            destination_routing_address: vec![destination],
            alerting_pattern: None,
            original_called_party_id: None,
            extensions: None,
            carrier: None,
            calling_partys_category: None,
            redirecting_party_id: None,
            redirection_information: None,
            generic_numbers: None,
            service_interaction_indicators_two: None,
            charge_number: None,
            leg_to_be_connected: None,
            cug_interlock: None,
            cug_outgoing_access: None,
            suppression_of_announcement: None,
            o_csi_applicable: None,
            na_oli_info: None,
            bor_interrogation_requested: None,
            suppress_n_csi: None,
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

/// ApplyCharging (op 35): the gsmSCF grants a call period.
///
/// ```text
/// ApplyChargingArg ::= SEQUENCE {
///   aChBillingChargingCharacteristics [0]  AChBillingChargingCharacteristics,
///   partyToCharge                     [2]  SendingSideID DEFAULT sendingSideID : leg1,  -- explicit
///   extensions                        [3]  Extensions OPTIONAL,
///   aChChargingAddress                [50] AChChargingAddress                           -- explicit
///                                          DEFAULT legID:sendingSideID:leg1,
///   ...}
/// ```
///
/// `aChBillingChargingCharacteristics` is an OCTET STRING holding the BER
/// encoding of a CAMEL-AChBillingChargingCharacteristics value. Build it with
/// [`ApplyChargingArg::with_characteristics`] from
/// [`CamelAChBillingChargingCharacteristics`](crate::types::CamelAChBillingChargingCharacteristics)
/// on a phase 4 dialogue or
/// [`CamelAChBillingChargingCharacteristicsV3`](crate::types::CamelAChBillingChargingCharacteristicsV3)
/// on a phase 3 one: the two differ on the wire.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ApplyChargingArg {
    #[rasn(tag(context, 0))]
    pub ach_billing_charging_characteristics: OctetString,
    #[rasn(tag(explicit(context, 2)))]
    pub party_to_charge: Option<SendingSideId>,
    #[rasn(tag(context, 3))]
    pub extensions: Option<Extensions>,
    /// Phase 4 only.
    #[rasn(tag(explicit(context, 50)))]
    pub a_ch_charging_address: Option<AChChargingAddress>,
}

impl ApplyChargingArg {
    /// An ApplyCharging carrying the already encoded `characteristics` with
    /// every optional member absent.
    pub fn new(characteristics: OctetString) -> Self {
        Self {
            ach_billing_charging_characteristics: characteristics,
            party_to_charge: None,
            extensions: None,
            a_ch_charging_address: None,
        }
    }

    /// An ApplyCharging carrying the BER encoding of `characteristics`.
    pub fn with_characteristics<T: rasn::Encode>(characteristics: &T) -> Result<Self, CapError> {
        Ok(Self::new(crate::encode(characteristics)?.into()))
    }

    /// Decode the characteristics as `T`, the phase 3 or the phase 4 type.
    pub fn characteristics<T: rasn::Decode + rasn::Encode>(&self) -> Result<T, CapError> {
        crate::decode(&self.ach_billing_charging_characteristics)
    }
}

/// ApplyChargingReport (op 36): the gsmSSF reports the time used.
///
/// `ApplyChargingReportArg ::= CallResult`, and CallResult is an OCTET STRING
/// holding the BER encoding of a CAMEL-CallResult value. The argument is that
/// bare OCTET STRING; there is no SEQUENCE around it.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct ApplyChargingReportArg(pub OctetString);

impl ApplyChargingReportArg {
    /// An argument carrying the BER encoding of `call_result`.
    pub fn from_call_result(call_result: &CamelCallResult) -> Result<Self, CapError> {
        Ok(Self(crate::encode(call_result)?.into()))
    }

    /// Decode the CAMEL-CallResult inside the OCTET STRING.
    pub fn call_result(&self) -> Result<CamelCallResult, CapError> {
        crate::decode(&self.0)
    }
}

/// FurnishChargingInformation (op 34): the gsmSCF adds data to the call
/// record.
///
/// `FurnishChargingInformationArg ::= FCIBillingChargingCharacteristics`, an
/// OCTET STRING holding the BER encoding of a
/// CAMEL-FCIBillingChargingCharacteristics value. The argument is that bare
/// OCTET STRING; there is no SEQUENCE around it.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct FurnishChargingInformationArg(pub OctetString);

impl FurnishChargingInformationArg {
    /// An argument carrying the BER encoding of `characteristics`.
    pub fn from_characteristics(
        characteristics: &CamelFciBillingChargingCharacteristics,
    ) -> Result<Self, CapError> {
        Ok(Self(crate::encode(characteristics)?.into()))
    }

    /// Decode the CAMEL-FCIBillingChargingCharacteristics inside the OCTET
    /// STRING.
    pub fn characteristics(&self) -> Result<CamelFciBillingChargingCharacteristics, CapError> {
        crate::decode(&self.0)
    }
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
