//! InitialDP (op 0), 3GPP TS 29.078 V18.0.0 clause 6.1.1.
//!
//! Vectors are assembled by hand from the ASN.1 (see `tests/bcsm_events.rs`
//! for the tag octet rules). Values are synthetic: IMSI 001 01 0123456789 (the
//! 3GPP test network), numbers in the fictional `+1 555 01xx` range.

mod common;

use common::{dissect, known_answer, vector, Carrier};
use gsm_cap::application_context as ac;
use gsm_cap::op_codes;
use gsm_cap::operations::InitialDpArg;
use gsm_cap::types::{
    BearerCapability, BothwayThroughConnectionInd, CellGlobalIdOrServiceAreaIdOrLai, CgEncountered,
    Code, EventTypeBcsm, ExtBasicServiceCode, ExtensionField, InitialDpArgExtension,
    LocationInformation, NotReachableReason, ServiceInteractionIndicatorsTwo, SubscriberState,
    UuData,
};
use rasn::types::{Any, BitString, Integer};

/// What an MSC sends for a mobile-originated call on the phase 3 context.
///
/// Member sizes: 3 8 3 3 8 7 3 11 5 24 6 7 8 8 11 = 115 (0x73).
const MOBILE_ORIGINATED: &str = "
    30 73
       80 01 2a                                -- serviceKey [0] 42
       83 06 04 13 51 55 10 10                 -- callingPartyNumber [3]: Q.763, international,
                                               --   ISDN plan, presentation allowed, network
                                               --   provided, 15550101
       85 01 0a                                -- callingPartysCategory [5]: ordinary subscriber
       88 01 00                                -- iPSSPCapabilities [8]
       8a 06 04 13 51 55 10 00                 -- locationNumber [10]
       bb 05                                   -- bearerCapability [27] EXPLICIT (a CHOICE)
          80 03 80 90 a3                       --   bearerCap [0]: speech, 64 kbit/s, A-law
       9c 01 02                                -- eventTypeBCSM [28] collectedInfo(2)
       9f 32 08 00 01 01 21 43 65 87 f9        -- iMSI [50]: TBCD 001010123456789
       bf 33 02 80 00                          -- subscriberState [51] EXPLICIT { assumedIdle [0] NULL }
       bf 34 15                                -- locationInformation [52]
          02 01 00                             --   ageOfLocationInformation 0
          81 05 91 51 55 10 00                 --   vlr-number [1]
          a3 09 80 07 00 f1 10 00 01 00 02     --   cell global id [3] EXPLICIT
       bf 35 03 83 01 11                       -- ext-basicServiceCode [53] EXPLICIT { ext-Teleservice }
       9f 36 04 01 02 03 04                    -- callReferenceNumber [54]
       9f 37 05 91 51 55 10 00                 -- mscAddress [55]
       9f 38 05 91 51 55 10 20                 -- calledPartyBCDNumber [56]: TS 24.008, 15550102
       9f 39 08 02 62 01 80 21 43 65 00        -- timeAndTimezone [57]: 2026-10-08 12:34:56
";

fn mobile_originated() -> InitialDpArg {
    InitialDpArg {
        calling_party_number: Some(vector("04 13 51 55 10 10").into()),
        calling_partys_category: Some(vec![0x0a].into()),
        ip_ssp_capabilities: Some(vec![0x00].into()),
        location_number: Some(vector("04 13 51 55 10 00").into()),
        bearer_capability: Some(BearerCapability::BearerCap(vector("80 90 a3").into())),
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        imsi: Some(vector("00 01 01 21 43 65 87 f9").into()),
        subscriber_state: Some(SubscriberState::AssumedIdle(())),
        location_information: Some(LocationInformation {
            age_of_location_information: Some(0),
            vlr_number: Some(vector("91 51 55 10 00").into()),
            cell_global_id_or_service_area_id_or_lai: Some(
                CellGlobalIdOrServiceAreaIdOrLai::CellGlobalIdOrServiceAreaIdFixedLength(
                    vector("00 f1 10 00 01 00 02").into(),
                ),
            ),
            ..Default::default()
        }),
        ext_basic_service_code: Some(ExtBasicServiceCode::ExtTeleservice(vec![0x11].into())),
        call_reference_number: Some(vector("01 02 03 04").into()),
        msc_address: Some(vector("91 51 55 10 00").into()),
        called_party_bcd_number: Some(vector("91 51 55 10 20").into()),
        time_and_timezone: Some(vector("02 62 01 80 21 43 65 00").into()),
        ..InitialDpArg::new(Integer::from(42))
    }
}

#[test]
fn mobile_originated_call() {
    let ber = known_answer(&mobile_originated(), MOBILE_ORIGINATED);
    let context = ac::object_identifier(&ac::CAP_V3_GSMSSF_SCF_GENERIC);
    let Some(d) = dissect(op_codes::INITIAL_DP, Some(&ber), Carrier::Begin(&context)) else {
        return;
    };
    d.show("camel.serviceKey", "42")
        .hex("camel.callingPartyNumber", "041351551010")
        .hex("camel.callingPartysCategory", "0a")
        .hex("camel.iPSSPCapabilities", "00")
        .hex("camel.locationNumber", "041351551000")
        .show("camel.bearerCapability", "0")
        .hex("camel.bearerCap", "8090a3")
        .show("camel.eventTypeBCSM", "2")
        .hex("camel.iMSI", "00010121436587f9")
        .show("camel.subscriberState", "0")
        .present("gsm_map.ms.assumedIdle_element")
        .present("camel.locationInformation_element")
        .show("gsm_map.ms.ageOfLocationInformation", "0")
        .hex("gsm_map.ms.vlr_number", "9151551000")
        .hex(
            "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength",
            "00f11000010002",
        )
        .show("camel.ext_basicServiceCode", "3")
        .show("gsm_map.ext_Teleservice", "17")
        .hex("camel.callReferenceNumber", "01020304")
        .hex("camel.mscAddress", "9151551000")
        .hex("camel.calledPartyBCDNumber", "9151551020")
        .hex("camel.timeAndTimezone", "0262018021436500")
        // Wireshark read the BCD the way the comment in the vector says.
        .show("camel.timeandtimezone.time", "20261008123456");
}

/// The members the first vector does not use: a forwarded, terminating call
/// with the phase 4 extension.
///
/// Member sizes: 3 8 3 8 12 4 9 3 8 4 4 6 7 4 7 3 6 3 83 = 185 (0xb9).
const REMAINING_MEMBERS: &str = "
    30 81 b9
       80 01 01                                -- serviceKey [0] 1
       82 06 04 10 51 55 10 20                 -- calledPartyNumber [2]
       87 01 01                                -- cGEncountered [7] manualCGencountered(1)
       8c 06 04 10 51 55 10 00                 -- originalCalledPartyID [12]
       af 0a 30 08 02 01 01 a1 03 01 01 ff     -- extensions [15]
       97 02 91 81                             -- highLayerCompatibility [23]: telephony
       99 07 06 04 10 51 55 10 30              -- additionalCallingPartyNumber [25]
       9c 01 0c                                -- eventTypeBCSM [28] termAttemptAuthorized(12)
       9d 06 04 10 51 55 10 10                 -- redirectingPartyID [29]
       9e 02 13 61                             -- redirectionInformation [30]
       91 02 80 90                             -- cause [17], listed after [30] in the ASN.1
       bf 20 03 82 01 00                       -- serviceInteractionIndicatorsTwo [32]
       9f 25 04 01 21 43 65                    -- carrier [37]
       9f 2d 01 05                             -- cug-Index [45] 5
       9f 2e 04 00 01 00 01                    -- cug-Interlock [46]
       9f 2f 00                                -- cug-OutgoingAccess [47] NULL
       bf 33 03 0a 01 01                       -- subscriberState [51] EXPLICIT
                                               --   { netDetNotReachable ENUMERATED imsiDetached }
       9f 3a 00                                -- callForwardingSS-Pending [58] NULL
       bf 3b 50                                -- initialDPArgExtension [59], 80 octets
          80 05 91 51 55 10 00                 --   gmscAddress [0]
          81 06 04 10 51 55 10 20              --   forwardingDestinationNumber [1]
          82 03 33 19 a2                       --   ms-Classmark2 [2]
          83 08 00 01 01 21 43 65 87 f0        --   iMEI [3]
          84 02 04 f0                          --   supportedCamelPhases [4]: 4 bits, 4 unused
          85 03 00 ff 00                       --   offeredCamel4Functionalities [5]: 16 bits
          a6 05 80 03 80 90 a3                 --   bearerCapability2 [6] EXPLICIT
          a7 03 82 01 1f                       --   ext-basicServiceCode2 [7] EXPLICIT
          88 02 91 81                          --   highLayerCompatibility2 [8]
          89 02 80 90                          --   lowLayerCompatibility [9]
          8a 02 80 90                          --   lowLayerCompatibility2 [10]
          8b 00                                --   enhancedDialledServicesAllowed [11] NULL
          ac 09                                --   uu-Data [12]
             80 01 01                          --     uuIndicator [0]
             81 02 04 31                       --     uui [1]
             82 00                             --     uusCFInteraction [2] NULL
          8d 00                                --   collectInformationAllowed [13] NULL
          8e 00                                --   releaseCallArgExtensionAllowed [14] NULL
";

fn remaining_members() -> InitialDpArg {
    let mut phases = BitString::from_vec(vec![0xf0]);
    phases.truncate(4);
    InitialDpArg {
        called_party_number: Some(vector("04 10 51 55 10 20").into()),
        cg_encountered: Some(CgEncountered::ManualCgEncountered),
        original_called_party_id: Some(vector("04 10 51 55 10 00").into()),
        extensions: Some(vec![ExtensionField {
            extension_type: Code::Local(Integer::from(1)),
            criticality: None,
            value: Any::new(vec![0x01, 0x01, 0xff]),
        }]),
        high_layer_compatibility: Some(vector("91 81").into()),
        additional_calling_party_number: Some(vector("06 04 10 51 55 10 30").into()),
        event_type_bcsm: Some(EventTypeBcsm::TermAttemptAuthorized),
        redirecting_party_id: Some(vector("04 10 51 55 10 10").into()),
        redirection_information: Some(vector("13 61").into()),
        cause: Some(vector("80 90").into()),
        service_interaction_indicators_two: Some(ServiceInteractionIndicatorsTwo {
            bothway_through_connection_ind: Some(BothwayThroughConnectionInd::BothwayPathRequired),
            ..Default::default()
        }),
        carrier: Some(vector("01 21 43 65").into()),
        cug_index: Some(5),
        cug_interlock: Some(vector("00 01 00 01").into()),
        cug_outgoing_access: Some(()),
        subscriber_state: Some(SubscriberState::NetDetNotReachable(
            NotReachableReason::ImsiDetached,
        )),
        call_forwarding_ss_pending: Some(()),
        initial_dp_arg_extension: Some(InitialDpArgExtension {
            gmsc_address: Some(vector("91 51 55 10 00").into()),
            forwarding_destination_number: Some(vector("04 10 51 55 10 20").into()),
            ms_classmark2: Some(vector("33 19 a2").into()),
            imei: Some(vector("00 01 01 21 43 65 87 f0").into()),
            supported_camel_phases: Some(phases),
            offered_camel4_functionalities: Some(BitString::from_vec(vec![0xff, 0x00])),
            bearer_capability2: Some(BearerCapability::BearerCap(vector("80 90 a3").into())),
            ext_basic_service_code2: Some(ExtBasicServiceCode::ExtBearerService(vec![0x1f].into())),
            high_layer_compatibility2: Some(vector("91 81").into()),
            low_layer_compatibility: Some(vector("80 90").into()),
            low_layer_compatibility2: Some(vector("80 90").into()),
            enhanced_dialled_services_allowed: Some(()),
            uu_data: Some(UuData {
                uu_indicator: Some(vec![0x01].into()),
                uui: Some(vector("04 31").into()),
                uus_cf_interaction: Some(()),
                extension_container: None,
            }),
            collect_information_allowed: Some(()),
            release_call_arg_extension_allowed: Some(()),
        }),
        ..InitialDpArg::new(Integer::from(1))
    }
}

#[test]
fn forwarded_terminating_call_with_the_phase_4_extension() {
    let ber = known_answer(&remaining_members(), REMAINING_MEMBERS);
    let context = ac::object_identifier(&ac::CAP_V4_GSMSSF_SCF_GENERIC);
    let Some(d) = dissect(op_codes::INITIAL_DP, Some(&ber), Carrier::Begin(&context)) else {
        return;
    };
    d.show("camel.serviceKey", "1")
        .hex("camel.calledPartyNumber", "041051551020")
        .show("camel.cGEncountered", "1")
        .hex("camel.originalCalledPartyID", "041051551000")
        .show("camel.extensions", "1")
        .show("camel.extension_code_local", "1")
        .hex("camel.highLayerCompatibility", "9181")
        .hex("camel.additionalCallingPartyNumber", "06041051551030")
        .show("camel.eventTypeBCSM", "12")
        .hex("camel.redirectingPartyID", "041051551010")
        .hex("camel.redirectionInformation", "1361")
        .hex("camel.cause", "8090")
        .present("camel.serviceInteractionIndicatorsTwo_element")
        .show("camel.bothwayThroughConnectionInd", "0")
        .hex("camel.carrier", "01214365")
        .show("camel.cug_Index", "5")
        .hex("camel.cug_Interlock", "00010001")
        .present("camel.cug_OutgoingAccess_element")
        .show("camel.subscriberState", "2")
        .show("gsm_map.ms.netDetNotReachable", "1")
        .present("camel.callForwardingSS_Pending_element")
        .present("camel.initialDPArgExtension_element")
        .hex("camel.gmscAddress", "9151551000")
        .hex("camel.forwardingDestinationNumber", "041051551020")
        .hex("camel.ms_Classmark2", "3319a2")
        .hex("camel.iMEI", "00010121436587f0")
        .hex("camel.supportedCamelPhases", "f0")
        .hex("camel.offeredCamel4Functionalities", "ff00")
        .show("camel.bearerCapability2", "0")
        .hex("camel.bearerCap", "8090a3")
        .show("camel.ext_basicServiceCode2", "2")
        .show("gsm_map.ext_BearerService", "31")
        .hex("camel.highLayerCompatibility2", "9181")
        .hex("camel.lowLayerCompatibility", "8090")
        .hex("camel.lowLayerCompatibility2", "8090")
        .present("camel.enhancedDialledServicesAllowed_element")
        .present("camel.uu_Data_element")
        .hex("gsm_map.ch.uuIndicator", "01")
        .hex("gsm_map.ch.uui", "0431")
        .present("gsm_map.ch.uusCFInteraction_element")
        .present("camel.collectInformationAllowed_element")
        .present("camel.releaseCallArgExtensionAllowed_element");
}

#[test]
fn release_1999_extension_carries_only_the_gmsc_address() {
    // InitialDPArgExtension in TS 29.078 V3.16.0 is { gmscAddress [0] }.
    //   30 0d
    //      80 01 01                           serviceKey 1
    //      bf 3b 07 80 05 91 51 55 10 00      initialDPArgExtension [59] { gmscAddress [0] }
    known_answer(
        &InitialDpArg {
            initial_dp_arg_extension: Some(InitialDpArgExtension {
                gmsc_address: Some(vector("91 51 55 10 00").into()),
                ..Default::default()
            }),
            ..InitialDpArg::new(Integer::from(1))
        },
        "30 0d 80 01 01 bf 3b 07 80 05 91 51 55 10 00",
    );
}

#[test]
fn a_member_this_crate_does_not_know_is_refused_not_skipped() {
    // [60] does not exist in InitialDPArg. rasn has no way to skip an unknown
    // member, so a later release that adds one is refused as a whole. That is
    // loud, which is the property that matters: the known members are never
    // returned with the unknown one quietly discarded.
    let unknown = vector("30 07 80 01 01 9f 3c 01 00");
    assert!(gsm_cap::decode::<InitialDpArg>(&unknown).is_err());
}
