//! Common CAP types.
//!
//! The definitions follow the ASN.1 of **3GPP TS 29.078 V18.0.0 (Release 18)**
//! clause 5.1 (`CAP-datatypes`) and, for the imported MAP types, **3GPP TS
//! 29.002 V18.0.0** clause 17.7. Both were cross-checked against the modules
//! Wireshark 4.6 generates its CAMEL and GSM MAP dissectors from.
//!
//! Three rules of those modules decide most of the bytes, and getting any of
//! them wrong still round-trips through this crate's own decoder:
//!
//! * The modules are `DEFINITIONS IMPLICIT TAGS`: `[n] OCTET STRING` is the
//!   primitive `8n`, `[n] SEQUENCE` the constructed `An`.
//! * A tag in front of a CHOICE cannot be implicit (X.680 31.2.7; TS 29.078
//!   clause 5.2 says so in as many words). It is an EXPLICIT, constructed
//!   wrapper around the alternative's own tag: `legID [3] ReceivingSideID`
//!   is `A3 03 81 01 02`, not `83 01 02`.
//! * Tag numbers above 30 use the high-tag-number form: `[50]` primitive is
//!   `9F 32`, constructed `BF 32`.
//!
//! Addresses and other externally defined strings are carried as `OCTET
//! STRING`s in their own wire formats (ISUP per ITU-T Q.763, 3GPP TS 24.008,
//! TBCD).
//!
//! Members that the ASN.1 gives a `DEFAULT` are `Option`s here: `None` leaves
//! the member out, which is how a default value is sent.
//!
//! `rasn` rejects a member it does not know, so a peer on a release newer than
//! 18 that adds a member is refused loudly rather than half-read.

use rasn::prelude::*;

// ── Leaf types identical in INAP, re-exported from the `inap` crate ─────────
pub use inap::types::{CalledPartyNumber, CallingPartyNumber, Cause, MonitorMode};

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
/// ISDN-AddressString (octet 0 = extension / nature of address / numbering
/// plan, then TBCD digits).
pub type IsdnAddressString = OctetString;
/// Digits, Q.763 generic number / generic digits format.
pub type Digits = OctetString;
/// LegType, one octet: `01` is leg 1 (the calling side), `02` leg 2.
pub type LegType = OctetString;

/// `leg1 LegType ::= '01'H`.
pub const LEG1: u8 = 0x01;
/// `leg2 LegType ::= '02'H`.
pub const LEG2: u8 = 0x02;

// ── Leg identifiers ─────────────────────────────────────────────────────────

/// LegID (CS1-DataTypes). A CHOICE, so every tagged member of this type is
/// EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum LegId {
    /// Used in operations the gsmSCF sends.
    #[rasn(tag(context, 0))]
    SendingSideId(LegType),
    /// Used in operations the gsmSSF sends.
    #[rasn(tag(context, 1))]
    ReceivingSideId(LegType),
}

impl LegId {
    /// `sendingSideID` for leg `leg` ([`LEG1`] or [`LEG2`]).
    pub fn sending(leg: u8) -> Self {
        Self::SendingSideId(vec![leg].into())
    }

    /// `receivingSideID` for leg `leg` ([`LEG1`] or [`LEG2`]).
    pub fn receiving(leg: u8) -> Self {
        Self::ReceivingSideId(vec![leg].into())
    }
}

/// SendingSideID: the `sendingSideID [0]` alternative of [`LegId`] on its own.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SendingSideId {
    #[rasn(tag(context, 0))]
    SendingSideId(LegType),
}

impl SendingSideId {
    /// `sendingSideID` for leg `leg` ([`LEG1`] or [`LEG2`]).
    pub fn leg(leg: u8) -> Self {
        Self::SendingSideId(vec![leg].into())
    }

    /// The LegType octets.
    pub fn leg_type(&self) -> &LegType {
        let Self::SendingSideId(leg) = self;
        leg
    }
}

/// ReceivingSideID: the `receivingSideID [1]` alternative of [`LegId`] on its
/// own.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum ReceivingSideId {
    #[rasn(tag(context, 1))]
    ReceivingSideId(LegType),
}

impl ReceivingSideId {
    /// `receivingSideID` for leg `leg` ([`LEG1`] or [`LEG2`]).
    pub fn leg(leg: u8) -> Self {
        Self::ReceivingSideId(vec![leg].into())
    }

    /// The LegType octets.
    pub fn leg_type(&self) -> &LegType {
        let Self::ReceivingSideId(leg) = self;
        leg
    }
}

// ── Extensions ──────────────────────────────────────────────────────────────

/// Code (ROS): how an extension (or an operation) is identified.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum Code {
    Local(Integer),
    Global(ObjectIdentifier),
}

/// CriticalityType (CS2-datatypes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum CriticalityType {
    Ignore = 0,
    Abort = 1,
}

/// ExtensionField: one network-specific extension.
///
/// `value` is an open type behind `[1]`, so the tag is EXPLICIT and `value`
/// holds the complete BER encoding (tag, length, content) of the extension's
/// own type.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExtensionField {
    pub extension_type: Code,
    /// `DEFAULT ignore`.
    pub criticality: Option<CriticalityType>,
    #[rasn(tag(explicit(context, 1)))]
    pub value: Any,
}

/// Extensions: `SEQUENCE SIZE (1..numOfExtensions) OF ExtensionField`.
pub type Extensions = Vec<ExtensionField>;

// ── Detection points and events ─────────────────────────────────────────────

/// EventTypeBCSM: the detection points of the basic call state models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EventTypeBcsm {
    CollectedInfo = 2,
    /// `analyzedInformation` in the ASN.1.
    AnalysedInformation = 3,
    RouteSelectFailure = 4,
    OCalledPartyBusy = 5,
    ONoAnswer = 6,
    OAnswer = 7,
    OMidCall = 8,
    ODisconnect = 9,
    OAbandon = 10,
    TermAttemptAuthorized = 12,
    TBusy = 13,
    TNoAnswer = 14,
    TAnswer = 15,
    TMidCall = 16,
    TDisconnect = 17,
    TAbandon = 18,
    OTermSeized = 19,
    CallAccepted = 27,
    OChangeOfPosition = 50,
    TChangeOfPosition = 51,
    OServiceChange = 52,
    TServiceChange = 53,
}

/// The `messageType` of [`MiscCallInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum MessageType {
    /// The detection point was armed as interrupted: the gsmSSF waits.
    Request = 0,
    /// The detection point was armed as notify-and-continue.
    Notification = 1,
}

/// The `dpAssignment` of [`MiscCallInfo`]. Defined by CS2, not used by CAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum DpAssignment {
    IndividualBased = 0,
    GroupBased = 1,
    SwitchBased = 2,
}

/// MiscCallInfo (CS2-datatypes).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MiscCallInfo {
    #[rasn(tag(context, 0))]
    pub message_type: MessageType,
    /// Present in the imported CS2 type; CAP does not send it.
    #[rasn(tag(context, 1))]
    pub dp_assignment: Option<DpAssignment>,
}

impl MiscCallInfo {
    /// `{messageType request}`.
    pub fn request() -> Self {
        Self {
            message_type: MessageType::Request,
            dp_assignment: None,
        }
    }

    /// `{messageType notification}`.
    pub fn notification() -> Self {
        Self {
            message_type: MessageType::Notification,
            dp_assignment: None,
        }
    }
}

/// MidCallControlInfo: which DTMF digit strings the gsmSSF reports mid-call.
/// Digit members are one BCD digit per octet (`0B` is `*`, `0C` is `#`).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MidCallControlInfo {
    /// `DEFAULT 1`.
    #[rasn(tag(context, 0))]
    pub minimum_number_of_digits: Option<u8>,
    /// `DEFAULT 30`.
    #[rasn(tag(context, 1))]
    pub maximum_number_of_digits: Option<u8>,
    #[rasn(tag(context, 2))]
    pub end_of_reply_digit: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub cancel_digit: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub start_digit: Option<OctetString>,
    /// `DEFAULT 10`, seconds.
    #[rasn(tag(context, 6))]
    pub inter_digit_timeout: Option<u8>,
}

/// ChangeOfLocationAlt: an empty extensible SEQUENCE.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ChangeOfLocationAlt {}

/// ChangeOfLocation: one criterion for the change-of-position detection
/// point.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum ChangeOfLocation {
    /// CellGlobalIdOrServiceAreaIdFixedLength, 7 octets.
    #[rasn(tag(context, 0))]
    CellGlobalId(OctetString),
    /// CellGlobalIdOrServiceAreaIdFixedLength, 7 octets.
    #[rasn(tag(context, 1))]
    ServiceAreaId(OctetString),
    /// LAIFixedLength, 5 octets.
    #[rasn(tag(context, 2))]
    LocationAreaId(OctetString),
    #[rasn(tag(context, 3))]
    InterSystemHandOver(()),
    #[rasn(tag(context, 4))]
    InterPlmnHandOver(()),
    #[rasn(tag(context, 5))]
    InterMscHandOver(()),
    #[rasn(tag(context, 6))]
    ChangeOfLocationAlt(ChangeOfLocationAlt),
}

/// DpSpecificCriteriaAlt. Every member sits after the extension marker, so a
/// peer may leave any of them out.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DpSpecificCriteriaAlt {
    /// ChangeOfPositionControlInfo.
    #[rasn(tag(context, 0))]
    pub change_of_position_control_info: Option<Vec<ChangeOfLocation>>,
    #[rasn(tag(context, 1))]
    pub number_of_digits: Option<u8>,
    #[rasn(tag(context, 2))]
    pub inter_digit_timeout: Option<u8>,
}

/// DpSpecificCriteria: what qualifies an armed detection point.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum DpSpecificCriteria {
    /// No-answer timer in seconds, INTEGER (0..2047).
    #[rasn(tag(context, 1))]
    ApplicationTimer(u16),
    #[rasn(tag(context, 2))]
    MidCallControlInfo(MidCallControlInfo),
    #[rasn(tag(context, 3))]
    DpSpecificCriteriaAlt(DpSpecificCriteriaAlt),
}

/// BCSMEvent: one detection point to arm.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct BcsmEvent {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    #[rasn(tag(context, 1))]
    pub monitor_mode: MonitorMode,
    /// A CHOICE, so `[2]` is EXPLICIT: `A2 03 80 01 02`.
    #[rasn(tag(explicit(context, 2)))]
    pub leg_id: Option<LegId>,
    /// A CHOICE, so `[30]` is EXPLICIT.
    #[rasn(tag(explicit(context, 30)))]
    pub dp_specific_criteria: Option<DpSpecificCriteria>,
    #[rasn(tag(context, 50))]
    pub automatic_rearm: Option<()>,
}

impl BcsmEvent {
    /// An event with no leg and no criteria.
    pub fn new(event_type_bcsm: EventTypeBcsm, monitor_mode: MonitorMode) -> Self {
        Self {
            event_type_bcsm,
            monitor_mode,
            leg_id: None,
            dp_specific_criteria: None,
            automatic_rearm: None,
        }
    }
}

/// Ext-BasicServiceCode (MAP-CommonDataTypes).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum ExtBasicServiceCode {
    #[rasn(tag(context, 2))]
    ExtBearerService(OctetString),
    #[rasn(tag(context, 3))]
    ExtTeleservice(OctetString),
}

/// Event-specific information carrying only a cause: route select failure,
/// O-called-party-busy, O-disconnect and T-disconnect.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CauseSpecificInfo {
    /// `failureCause`, `busyCause` or `releaseCause` depending on the event;
    /// `[0]` in all four.
    #[rasn(tag(context, 0))]
    pub cause: Option<Cause>,
}

/// oNoAnswerSpecificInfo: nothing defined.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ONoAnswerSpecificInfo {}

/// oAnswerSpecificInfo and tAnswerSpecificInfo (identical bodies).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnswerSpecificInfo {
    #[rasn(tag(context, 50))]
    pub destination_address: Option<CalledPartyNumber>,
    #[rasn(tag(context, 51))]
    pub or_call: Option<()>,
    #[rasn(tag(context, 52))]
    pub forwarded_call: Option<()>,
    #[rasn(tag(context, 53))]
    pub charge_indicator: Option<OctetString>,
    #[rasn(tag(explicit(context, 54)))]
    pub ext_basic_service_code: Option<ExtBasicServiceCode>,
    #[rasn(tag(explicit(context, 55)))]
    pub ext_basic_service_code2: Option<ExtBasicServiceCode>,
}

/// `midCallEvents` of the mid-call specific information.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum MidCallEvents {
    #[rasn(tag(context, 3))]
    DtmfDigitsCompleted(Digits),
    #[rasn(tag(context, 4))]
    DtmfDigitsTimeOut(Digits),
}

/// oMidCallSpecificInfo and tMidCallSpecificInfo (identical bodies).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MidCallSpecificInfo {
    #[rasn(tag(explicit(context, 1)))]
    pub mid_call_events: Option<MidCallEvents>,
}

/// tBusySpecificInfo.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct TBusySpecificInfo {
    #[rasn(tag(context, 0))]
    pub busy_cause: Option<Cause>,
    #[rasn(tag(context, 50))]
    pub call_forwarded: Option<()>,
    #[rasn(tag(context, 51))]
    pub route_not_permitted: Option<()>,
    #[rasn(tag(context, 52))]
    pub forwarding_destination_number: Option<CalledPartyNumber>,
}

/// tNoAnswerSpecificInfo.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct TNoAnswerSpecificInfo {
    #[rasn(tag(context, 50))]
    pub call_forwarded: Option<()>,
    #[rasn(tag(context, 52))]
    pub forwarding_destination_number: Option<CalledPartyNumber>,
}

/// oTermSeizedSpecificInfo and callAcceptedSpecificInfo (identical bodies).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AlertingSpecificInfo {
    #[rasn(tag(context, 50))]
    pub location_information: Option<LocationInformation>,
}

/// oAbandonSpecificInfo.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct OAbandonSpecificInfo {
    #[rasn(tag(context, 50))]
    pub route_not_permitted: Option<()>,
}

/// MetDPCriterionAlt: an empty extensible SEQUENCE.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MetDpCriterionAlt {}

/// MetDPCriterion: which change-of-position criterion fired.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum MetDpCriterion {
    #[rasn(tag(context, 0))]
    EnteringCellGlobalId(OctetString),
    #[rasn(tag(context, 1))]
    LeavingCellGlobalId(OctetString),
    #[rasn(tag(context, 2))]
    EnteringServiceAreaId(OctetString),
    #[rasn(tag(context, 3))]
    LeavingServiceAreaId(OctetString),
    #[rasn(tag(context, 4))]
    EnteringLocationAreaId(OctetString),
    #[rasn(tag(context, 5))]
    LeavingLocationAreaId(OctetString),
    #[rasn(tag(context, 6))]
    InterSystemHandOverToUmts(()),
    #[rasn(tag(context, 7))]
    InterSystemHandOverToGsm(()),
    #[rasn(tag(context, 8))]
    InterPlmnHandOver(()),
    #[rasn(tag(context, 9))]
    InterMscHandOver(()),
    #[rasn(tag(context, 10))]
    MetDpCriterionAlt(MetDpCriterionAlt),
}

/// oChangeOfPositionSpecificInfo and tChangeOfPositionSpecificInfo (identical
/// bodies).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ChangeOfPositionSpecificInfo {
    #[rasn(tag(context, 50))]
    pub location_information: Option<LocationInformation>,
    /// MetDPCriteriaList.
    #[rasn(tag(context, 51))]
    pub met_dp_criteria_list: Option<Vec<MetDpCriterion>>,
}

/// InitiatorOfServiceChange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum InitiatorOfServiceChange {
    ASide = 0,
    BSide = 1,
}

/// NatureOfServiceChange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum NatureOfServiceChange {
    UserInitiated = 0,
    NetworkInitiated = 1,
}

/// oServiceChangeSpecificInfo and tServiceChangeSpecificInfo (identical
/// bodies).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ServiceChangeSpecificInfo {
    #[rasn(tag(explicit(context, 0)))]
    pub ext_basic_service_code: Option<ExtBasicServiceCode>,
    #[rasn(tag(context, 1))]
    pub initiator_of_service_change: Option<InitiatorOfServiceChange>,
    #[rasn(tag(context, 2))]
    pub nature_of_service_change: Option<NatureOfServiceChange>,
}

/// collectedInfoSpecificInfo.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CollectedInfoSpecificInfo {
    #[rasn(tag(context, 0))]
    pub called_party_number: Option<CalledPartyNumber>,
}

/// DpSpecificInfoAlt. Every member sits after the extension marker and one
/// report concerns one detection point, so each is optional here.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DpSpecificInfoAlt {
    #[rasn(tag(context, 0))]
    pub o_service_change_specific_info: Option<ServiceChangeSpecificInfo>,
    #[rasn(tag(context, 1))]
    pub t_service_change_specific_info: Option<ServiceChangeSpecificInfo>,
    #[rasn(tag(context, 2))]
    pub collected_info_specific_info: Option<CollectedInfoSpecificInfo>,
}

/// EventSpecificInformationBCSM: what the gsmSSF knows about the event it
/// reports. The alternative must match the reported detection point.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum EventSpecificInformationBcsm {
    #[rasn(tag(context, 2))]
    RouteSelectFailureSpecificInfo(CauseSpecificInfo),
    #[rasn(tag(context, 3))]
    OCalledPartyBusySpecificInfo(CauseSpecificInfo),
    #[rasn(tag(context, 4))]
    ONoAnswerSpecificInfo(ONoAnswerSpecificInfo),
    #[rasn(tag(context, 5))]
    OAnswerSpecificInfo(AnswerSpecificInfo),
    #[rasn(tag(context, 6))]
    OMidCallSpecificInfo(MidCallSpecificInfo),
    #[rasn(tag(context, 7))]
    ODisconnectSpecificInfo(CauseSpecificInfo),
    #[rasn(tag(context, 8))]
    TBusySpecificInfo(TBusySpecificInfo),
    #[rasn(tag(context, 9))]
    TNoAnswerSpecificInfo(TNoAnswerSpecificInfo),
    #[rasn(tag(context, 10))]
    TAnswerSpecificInfo(AnswerSpecificInfo),
    #[rasn(tag(context, 11))]
    TMidCallSpecificInfo(MidCallSpecificInfo),
    #[rasn(tag(context, 12))]
    TDisconnectSpecificInfo(CauseSpecificInfo),
    #[rasn(tag(context, 13))]
    OTermSeizedSpecificInfo(AlertingSpecificInfo),
    #[rasn(tag(context, 20))]
    CallAcceptedSpecificInfo(AlertingSpecificInfo),
    #[rasn(tag(context, 21))]
    OAbandonSpecificInfo(OAbandonSpecificInfo),
    #[rasn(tag(context, 50))]
    OChangeOfPositionSpecificInfo(ChangeOfPositionSpecificInfo),
    #[rasn(tag(context, 51))]
    TChangeOfPositionSpecificInfo(ChangeOfPositionSpecificInfo),
    #[rasn(tag(context, 52))]
    DpSpecificInfoAlt(DpSpecificInfoAlt),
}

// ── MAP types CAP imports (3GPP TS 29.002 V18.0.0 clause 17.7) ───────────────
//
// The MAP modules are `DEFINITIONS IMPLICIT TAGS`, like the CAP ones. A tag in
// front of a CHOICE is always EXPLICIT (X.680 31.2.7), which is why
// `cellGlobalIdOrServiceAreaIdOrLAI [3]` is a constructed wrapper around the
// alternative's own tag and not a retagged OCTET STRING.

/// GeographicalInformation, 8 octets (TS 23.032 ellipsoid point with
/// uncertainty circle).
pub type GeographicalInformation = OctetString;
/// GeodeticInformation, 10 octets (Q.763 calling geodetic location).
pub type GeodeticInformation = OctetString;
/// LSAIdentity, 3 octets.
pub type LsaIdentity = OctetString;
/// E-UTRAN-CGI, 7 octets.
pub type EUtranCgi = OctetString;
/// TA-Id, 5 octets.
pub type TaId = OctetString;
/// DiameterIdentity (an FQDN as octets).
pub type DiameterIdentity = OctetString;
/// CSG-Id, a 27-bit string.
pub type CsgId = BitString;

/// PrivateExtension (MAP-ExtensionDataTypes): an object identifier and an
/// optional value of the type that identifier names.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrivateExtension {
    pub ext_id: ObjectIdentifier,
    pub ext_type: Option<Any>,
}

/// PCS-Extensions (MAP-ExtensionDataTypes): an empty extensible SEQUENCE.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PcsExtensions {}

/// ExtensionContainer (MAP-ExtensionDataTypes).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExtensionContainer {
    #[rasn(tag(context, 0))]
    pub private_extension_list: Option<Vec<PrivateExtension>>,
    #[rasn(tag(context, 1))]
    pub pcs_extensions: Option<PcsExtensions>,
}

/// CellGlobalIdOrServiceAreaIdOrLAI (MAP-CommonDataTypes).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum CellGlobalIdOrServiceAreaIdOrLai {
    /// CellGlobalIdOrServiceAreaIdFixedLength, 7 octets: MCC/MNC (3), LAC (2),
    /// cell identity or service area code (2).
    #[rasn(tag(context, 0))]
    CellGlobalIdOrServiceAreaIdFixedLength(OctetString),
    /// LAIFixedLength, 5 octets: MCC/MNC (3), LAC (2).
    #[rasn(tag(context, 1))]
    LaiFixedLength(OctetString),
}

/// LocationInformationEPS (MAP-MS-DataTypes).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationInformationEps {
    #[rasn(tag(context, 0))]
    pub e_utran_cell_global_identity: Option<EUtranCgi>,
    #[rasn(tag(context, 1))]
    pub tracking_area_identity: Option<TaId>,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub geographical_information: Option<GeographicalInformation>,
    #[rasn(tag(context, 4))]
    pub geodetic_information: Option<GeodeticInformation>,
    #[rasn(tag(context, 5))]
    pub current_location_retrieved: Option<()>,
    #[rasn(tag(context, 6))]
    pub age_of_location_information: Option<u16>,
    #[rasn(tag(context, 7))]
    pub mme_name: Option<DiameterIdentity>,
}

/// UserCSGInformation (MAP-MS-DataTypes).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UserCsgInformation {
    #[rasn(tag(context, 0))]
    pub csg_id: CsgId,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 2))]
    pub access_mode: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub cmi: Option<OctetString>,
}

/// LocationInformation (MAP-MS-DataTypes), the location of a circuit-switched
/// subscriber as the VLR knows it.
///
/// `ageOfLocationInformation` carries no context tag: it is the one untagged
/// member, a plain INTEGER (0..32767).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationInformation {
    pub age_of_location_information: Option<u16>,
    #[rasn(tag(context, 0))]
    pub geographical_information: Option<GeographicalInformation>,
    #[rasn(tag(context, 1))]
    pub vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 2))]
    pub location_number: Option<LocationNumber>,
    #[rasn(tag(explicit(context, 3)))]
    pub cell_global_id_or_service_area_id_or_lai: Option<CellGlobalIdOrServiceAreaIdOrLai>,
    #[rasn(tag(context, 4))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub selected_lsa_id: Option<LsaIdentity>,
    #[rasn(tag(context, 6))]
    pub msc_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 7))]
    pub geodetic_information: Option<GeodeticInformation>,
    #[rasn(tag(context, 8))]
    pub current_location_retrieved: Option<()>,
    #[rasn(tag(context, 9))]
    pub sai_present: Option<()>,
    #[rasn(tag(context, 10))]
    pub location_information_eps: Option<LocationInformationEps>,
    #[rasn(tag(context, 11))]
    pub user_csg_information: Option<UserCsgInformation>,
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
