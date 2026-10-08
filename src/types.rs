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
