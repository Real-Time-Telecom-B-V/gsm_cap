//! LocationInformation (3GPP TS 29.002 V18.0.0, MAP-MS-DataTypes), which CAP
//! imports for InitialDP, InitialDPSMS and the event-specific information.
//!
//! All values are synthetic: PLMN 001/01 (the 3GPP test network), numbers in
//! the fictional `+1 555 01xx` range, the `.test` domain, the `2.999` example
//! object identifier arc.

mod common;

use common::{dissect, known_answer, vector, Carrier};
use gsm_cap::application_context as ac;
use gsm_cap::op_codes;
use gsm_cap::operations::InitialDpArg;
use gsm_cap::types::{
    CellGlobalIdOrServiceAreaIdOrLai, ExtensionContainer, LocationInformation,
    LocationInformationEps, PrivateExtension, UserCsgInformation,
};
use rasn::types::{BitString, Integer, ObjectIdentifier};

fn unhex(text: &str) -> Vec<u8> {
    vector(text)
}

/// Every member of LocationInformation, hand-assembled from the ASN.1:
///
/// ```text
/// LocationInformation ::= SEQUENCE {
///   ageOfLocationInformation          AgeOfLocationInformation OPTIONAL,  -- INTEGER, untagged
///   geographicalInformation       [0] GeographicalInformation OPTIONAL,
///   vlr-number                    [1] ISDN-AddressString OPTIONAL,
///   locationNumber                [2] LocationNumber OPTIONAL,
///   cellGlobalIdOrServiceAreaIdOrLAI [3] CellGlobalIdOrServiceAreaIdOrLAI OPTIONAL,  -- CHOICE: explicit
///   extensionContainer            [4] ExtensionContainer OPTIONAL,
///   ...,
///   selectedLSA-Id                [5] LSAIdentity OPTIONAL,
///   msc-Number                    [6] ISDN-AddressString OPTIONAL,
///   geodeticInformation           [7] GeodeticInformation OPTIONAL,
///   currentLocationRetrieved      [8] NULL OPTIONAL,
///   sai-Present                   [9] NULL OPTIONAL,
///   locationInformationEPS       [10] LocationInformationEPS OPTIONAL,
///   userCSGInformation           [11] UserCSGInformation OPTIONAL }
/// ```
///
/// Implicit tagging: a primitive member keeps the primitive form under its
/// context tag (`8x`), a SEQUENCE member becomes constructed (`Ax`). Member
/// lengths add up to 125 (0x7d).
const FULL: &str = "
    30 7d
       02 01 05                               -- age 5 minutes, universal INTEGER
       80 08 10 12 34 56 12 34 56 0a          -- [0] 8 octets
       81 05 91 51 55 10 00                   -- [1] international E.164 15550100
       82 06 04 13 51 55 10 00                -- [2] Q.763 location number
       a3 09                                  -- [3] EXPLICIT, constructed
          80 07 00 f1 10 00 01 00 02          --     [0] MCC 001 MNC 01, LAC 1, CI 2
       a4 09                                  -- [4] ExtensionContainer
          a0 07                               --     [0] privateExtensionList
             30 05 06 03 88 37 01             --         { extId 2.999.1 }
       85 03 00 00 01                         -- [5] LSA identity
       86 05 91 51 55 10 10                   -- [6] international E.164 15550101
       87 0a 00 01 12 34 56 12 34 56 0a 00    -- [7] 10 octets
       88 00                                  -- [8] NULL
       89 00                                  -- [9] NULL
       aa 1e                                  -- [10] LocationInformationEPS
          80 07 00 f1 10 00 00 01 01          --     [0] E-UTRAN CGI
          81 05 00 f1 10 00 01                --     [1] tracking area
          86 01 03                            --     [6] age 3 minutes
          87 09 6d 6d 65 31 2e 74 65 73 74    --     [7] mme1.test
       ab 0d                                  -- [11] UserCSGInformation
          80 05 05 00 00 00 20                --     [0] BIT STRING, 27 bits, 5 unused
          82 01 00                            --     [2] access mode
          83 01 01                            --     [3] CSG membership indication
";

fn full() -> LocationInformation {
    let mut csg_id = BitString::from_vec(vec![0x00, 0x00, 0x00, 0x20]);
    csg_id.truncate(27);
    LocationInformation {
        age_of_location_information: Some(5),
        geographical_information: Some(unhex("10 12 34 56 12 34 56 0a").into()),
        vlr_number: Some(unhex("91 51 55 10 00").into()),
        location_number: Some(unhex("04 13 51 55 10 00").into()),
        cell_global_id_or_service_area_id_or_lai: Some(
            CellGlobalIdOrServiceAreaIdOrLai::CellGlobalIdOrServiceAreaIdFixedLength(
                unhex("00 f1 10 00 01 00 02").into(),
            ),
        ),
        extension_container: Some(ExtensionContainer {
            private_extension_list: Some(vec![PrivateExtension {
                ext_id: ObjectIdentifier::new_unchecked(vec![2, 999, 1].into()),
                ext_type: None,
            }]),
            pcs_extensions: None,
        }),
        selected_lsa_id: Some(unhex("00 00 01").into()),
        msc_number: Some(unhex("91 51 55 10 10").into()),
        geodetic_information: Some(unhex("00 01 12 34 56 12 34 56 0a 00").into()),
        current_location_retrieved: Some(()),
        sai_present: Some(()),
        location_information_eps: Some(LocationInformationEps {
            e_utran_cell_global_identity: Some(unhex("00 f1 10 00 00 01 01").into()),
            tracking_area_identity: Some(unhex("00 f1 10 00 01").into()),
            age_of_location_information: Some(3),
            mme_name: Some(b"mme1.test".to_vec().into()),
            ..Default::default()
        }),
        user_csg_information: Some(UserCsgInformation {
            csg_id,
            extension_container: None,
            access_mode: Some(vec![0x00].into()),
            cmi: Some(vec![0x01].into()),
        }),
    }
}

#[test]
fn every_member_matches_the_hand_assembled_bytes() {
    known_answer(&full(), FULL);
}

#[test]
fn decodes_a_location_area_only_report() {
    // A VLR that knows the location area but not the cell: the laiFixedLength
    // alternative, [1] inside the explicit [3]. msc-Number is [6].
    //   30 12
    //      a3 07 81 05 00 f1 10 00 01     LAI: MCC 001 MNC 01, LAC 1
    //      86 05 91 51 55 10 10           msc-Number
    //      88 00                          currentLocationRetrieved
    let decoded: LocationInformation = gsm_cap::decode(&unhex(
        "30 12 a3 07 81 05 00 f1 10 00 01 86 05 91 51 55 10 10 88 00",
    ))
    .unwrap();
    assert_eq!(
        decoded,
        LocationInformation {
            cell_global_id_or_service_area_id_or_lai: Some(
                CellGlobalIdOrServiceAreaIdOrLai::LaiFixedLength(unhex("00 f1 10 00 01").into())
            ),
            msc_number: Some(unhex("91 51 55 10 10").into()),
            current_location_retrieved: Some(()),
            ..Default::default()
        }
    );
}

#[test]
fn rejects_the_encoding_this_crate_used_to_emit() {
    // Before 2.0.0: cellGlobalIdOrServiceAreaIdOrLAI as a primitive [3] OCTET
    // STRING and msc-Number on [8]. Neither is what MAP says, and [8] is a
    // NULL (currentLocationRetrieved), so a correct decoder must not accept
    // five octets of content there.
    let old = unhex("30 10 83 07 00 f1 10 00 01 00 02 88 05 91 51 55 10 10");
    assert!(gsm_cap::decode::<LocationInformation>(&old).is_err());
}

#[test]
fn wireshark_reads_back_every_member() {
    let idp = InitialDpArg {
        location_information: Some(full()),
        ..InitialDpArg::new(Integer::from(1))
    };
    let ber = gsm_cap::encode(&idp).unwrap();
    let context = ac::object_identifier(&ac::CAP_V4_GSMSSF_SCF_GENERIC);
    let Some(d) = dissect(op_codes::INITIAL_DP, Some(&ber), Carrier::Begin(&context)) else {
        return;
    };
    d.show("camel.serviceKey", "1")
        .present("camel.locationInformation_element")
        // Both LocationInformation and LocationInformationEPS carry an age.
        .show_all("gsm_map.ms.ageOfLocationInformation", &["5", "3"])
        .hex("gsm_map.ms.geographicalInformation", "101234561234560a")
        .hex("gsm_map.ms.vlr_number", "9151551000")
        .hex("gsm_map.ms.locationNumber", "041351551000")
        // The explicit [3] wrapper was understood: Wireshark reports the
        // chosen alternative (0) and its seven octets.
        .show("gsm_map.ms.cellGlobalIdOrServiceAreaIdOrLAI", "0")
        .hex(
            "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength",
            "00f11000010002",
        )
        .present("gsm_map.ms.extensionContainer_element")
        .show("gsm_map.extId", "2.999.1")
        .hex("gsm_map.ms.selectedLSA_Id", "000001")
        .hex("gsm_map.ms.msc_Number", "9151551010")
        .hex("gsm_map.ms.geodeticInformation", "00011234561234560a00")
        .present("gsm_map.ms.currentLocationRetrieved_element")
        .present("gsm_map.ms.sai_Present_element")
        .present("gsm_map.ms.locationInformationEPS_element")
        .hex("gsm_map.ms.e_utranCellGlobalIdentity", "00f11000000101")
        .hex("gsm_map.ms.trackingAreaIdentity", "00f1100001")
        .show("gsm_map.ms.mme_Name", "mme1.test")
        .present("gsm_map.ms.userCSGInformation_element")
        .hex("gsm_map.ms.csg_Id", "00000020")
        .hex("gsm_map.ms.accessMode", "00")
        .hex("gsm_map.ms.cmi", "01");
}
