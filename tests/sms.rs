//! CAMEL control of SMS: InitialDPSMS (op 60), ConnectSMS (op 62),
//! RequestReportSMSEvent (op 63), EventReportSMS (op 64) and ReleaseSMS
//! (op 66), 3GPP TS 29.078 V18.0.0 clauses 5.1 and 7.1.
//!
//! Vectors are assembled by hand from the ASN.1 (see `tests/bcsm_events.rs`
//! for the tag octet rules). Values are synthetic: IMSI 001 01 0123456789,
//! numbers in the fictional `+1 555 01xx` range.

mod common;

use common::{dissect, known_answer, vector, Carrier};
use gsm_cap::application_context as ac;
use gsm_cap::op_codes;
use gsm_cap::operations::{
    ConnectSmsArg, EventReportSmsArg, InitialDpSmsArg, ReleaseSmsArg, RequestReportSmsEventArg,
};
use gsm_cap::types::{
    CellGlobalIdOrServiceAreaIdOrLai, Code, EmptySmsSpecificInfo, EventSpecificInformationSms,
    EventTypeSms, ExtensionField, GprsMsClass, LocationInformation, LocationInformationGprs,
    MiscCallInfo, MoSmsCause, MonitorMode, OSmsFailureSpecificInfo, SmsEvent,
    TSmsFailureSpecificInfo, UserCsgInformation,
};
use rasn::types::{Any, BitString, Integer};

fn extension() -> ExtensionField {
    ExtensionField {
        extension_type: Code::Local(Integer::from(1)),
        criticality: None,
        value: Any::new(vec![0x01, 0x01, 0xff]),
    }
}

// ── InitialDPSMS ────────────────────────────────────────────────────────────

/// A mobile-originated short message reported by an MSC.
///
/// Member sizes: 3 7 7 3 10 23 7 10 3 3 3 3 3 7 5 10 7 = 114 (0x72).
const FROM_MSC: &str = "
    30 72
       80 01 07                                -- serviceKey [0] 7
       81 05 91 51 55 10 20                    -- destinationSubscriberNumber [1], 15550102
       82 05 91 51 55 10 10                    -- callingPartyNumber [2], 15550101
       83 01 01                                -- eventTypeSMS [3] sms-CollectedInfo(1)
       84 08 00 01 01 21 43 65 87 f9           -- iMSI [4]: TBCD 001010123456789
       a5 15                                   -- locationInformationMSC [5]
          02 01 00                             --   ageOfLocationInformation 0
          81 05 91 51 55 10 00                 --   vlr-number [1]
          a3 09 80 07 00 f1 10 00 01 00 02     --   cell global id [3] EXPLICIT
       87 05 91 51 55 10 30                    -- sMSCAddress [7], 15550103
       88 08 02 62 01 80 21 43 65 00           -- timeAndTimezone [8]
       89 01 11                                -- tPShortMessageSpecificInfo [9]: SMS-SUBMIT
       8a 01 00                                -- tPProtocolIdentifier [10]
       8b 01 00                                -- tPDataCodingScheme [11]
       8c 01 a7                                -- tPValidityPeriod [12]: 24 hours, relative
       8e 01 01                                -- smsReferenceNumber [14]
       8f 05 91 51 55 10 00                    -- mscAddress [15]
       91 03 33 19 a2                          -- ms-Classmark2 [17]
       93 08 00 01 01 21 43 65 87 f0           -- iMEI [19]
       94 05 91 51 55 10 20                    -- calledPartyNumber [20]
";

fn from_msc() -> InitialDpSmsArg {
    InitialDpSmsArg {
        destination_subscriber_number: Some(vector("91 51 55 10 20").into()),
        calling_party_number: Some(vector("91 51 55 10 10").into()),
        event_type_sms: Some(EventTypeSms::SmsCollectedInfo),
        imsi: Some(vector("00 01 01 21 43 65 87 f9").into()),
        location_information_msc: Some(LocationInformation {
            age_of_location_information: Some(0),
            vlr_number: Some(vector("91 51 55 10 00").into()),
            cell_global_id_or_service_area_id_or_lai: Some(
                CellGlobalIdOrServiceAreaIdOrLai::CellGlobalIdOrServiceAreaIdFixedLength(
                    vector("00 f1 10 00 01 00 02").into(),
                ),
            ),
            ..Default::default()
        }),
        smsc_address: Some(vector("91 51 55 10 30").into()),
        time_and_timezone: Some(vector("02 62 01 80 21 43 65 00").into()),
        tp_short_message_specific_info: Some(vec![0x11].into()),
        tp_protocol_identifier: Some(vec![0x00].into()),
        tp_data_coding_scheme: Some(vec![0x00].into()),
        tp_validity_period: Some(vec![0xa7].into()),
        sms_reference_number: Some(vec![0x01].into()),
        msc_address: Some(vector("91 51 55 10 00").into()),
        ms_classmark2: Some(vector("33 19 a2").into()),
        imei: Some(vector("00 01 01 21 43 65 87 f0").into()),
        called_party_number: Some(vector("91 51 55 10 20").into()),
        ..InitialDpSmsArg::new(Integer::from(7))
    }
}

#[test]
fn initial_dp_sms_from_an_msc() {
    let ber = known_answer(&from_msc(), FROM_MSC);
    let context = ac::object_identifier(&ac::CAP_V3_SMS);
    let Some(d) = dissect(
        op_codes::INITIAL_DP_SMS,
        Some(&ber),
        Carrier::Begin(&context),
    ) else {
        return;
    };
    d.show("camel.serviceKey", "7")
        .hex("camel.destinationSubscriberNumber", "9151551020")
        .hex("camel.callingPartyNumber", "9151551010")
        .show("camel.eventTypeSMS", "1")
        .hex("camel.iMSI", "00010121436587f9")
        .present("camel.locationInformationMSC_element")
        .show("gsm_map.ms.ageOfLocationInformation", "0")
        .hex("gsm_map.ms.vlr_number", "9151551000")
        .hex(
            "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength",
            "00f11000010002",
        )
        .hex("camel.sMSCAddress", "9151551030")
        .hex("camel.timeAndTimezone", "0262018021436500")
        .hex("camel.tPShortMessageSpecificInfo", "11")
        .hex("camel.tPProtocolIdentifier", "00")
        .hex("camel.tPDataCodingScheme", "00")
        .hex("camel.tPValidityPeriod", "a7")
        .hex("camel.smsReferenceNumber", "01")
        .hex("camel.mscAddress", "9151551000")
        .hex("camel.ms_Classmark2", "3319a2")
        .hex("camel.iMEI", "00010121436587f0")
        .hex("camel.calledPartyNumber", "9151551020");
}

/// A mobile-terminated short message reported by an SGSN: the members the
/// first vector does not use.
///
/// Member sizes: 3 3 43 12 7 11 = 79 (0x4f).
const FROM_SGSN: &str = "
    30 4f
       80 01 07                                -- serviceKey [0] 7
       83 01 0b                                -- eventTypeSMS [3] sms-DeliveryRequested(11)
       a6 29                                   -- locationInformationGPRS [6], 41 octets
          80 07 00 f1 10 00 01 00 02           --   cellGlobalIdOrServiceAreaIdOrLAI [0], a plain
                                               --     OCTET STRING here, so primitive
          81 06 00 f1 10 00 01 01              --   routeingAreaIdentity [1]
          82 08 10 12 34 56 12 34 56 0a        --   geographicalInformation [2]
          83 05 91 51 55 10 40                 --   sgsn-Number [3], 15550104
          84 03 00 00 01                       --   selectedLSAIdentity [4]
          86 00                                --   sai-Present [6] NULL
       ad 0a 30 08 02 01 01 a1 03 01 01 ff     -- extensions [13]
       90 05 91 51 55 10 40                    -- sgsn-Number [16]
       b2 09                                   -- gPRSMSClass [18]
          80 02 e5 e0                          --   mSNetworkCapability [0]
          81 03 17 a3 00                       --   mSRadioAccessCapability [1]
";

fn from_sgsn() -> InitialDpSmsArg {
    InitialDpSmsArg {
        event_type_sms: Some(EventTypeSms::SmsDeliveryRequested),
        location_information_gprs: Some(LocationInformationGprs {
            cell_global_id_or_service_area_id_or_lai: Some(vector("00 f1 10 00 01 00 02").into()),
            routeing_area_identity: Some(vector("00 f1 10 00 01 01").into()),
            geographical_information: Some(vector("10 12 34 56 12 34 56 0a").into()),
            sgsn_number: Some(vector("91 51 55 10 40").into()),
            selected_lsa_identity: Some(vector("00 00 01").into()),
            extension_container: None,
            sai_present: Some(()),
            user_csg_information: None,
        }),
        extensions: Some(vec![extension()]),
        sgsn_number: Some(vector("91 51 55 10 40").into()),
        gprs_ms_class: Some(GprsMsClass {
            ms_network_capability: vector("e5 e0").into(),
            ms_radio_access_capability: Some(vector("17 a3 00").into()),
        }),
        ..InitialDpSmsArg::new(Integer::from(7))
    }
}

#[test]
fn initial_dp_sms_from_an_sgsn() {
    let ber = known_answer(&from_sgsn(), FROM_SGSN);
    let context = ac::object_identifier(&ac::CAP_V4_SMS);
    let Some(d) = dissect(
        op_codes::INITIAL_DP_SMS,
        Some(&ber),
        Carrier::Begin(&context),
    ) else {
        return;
    };
    d.show("camel.serviceKey", "7")
        .show("camel.eventTypeSMS", "11")
        .present("camel.locationInformationGPRS_element")
        .hex("camel.cellGlobalIdOrServiceAreaIdOrLAI", "00f11000010002")
        .hex("camel.routeingAreaIdentity", "00f110000101")
        .hex("camel.geographicalInformation", "101234561234560a")
        // Once inside locationInformationGPRS [3], once as the argument's own [16].
        .hex_all("camel.sgsn_Number", &["9151551040", "9151551040"])
        .hex("camel.selectedLSAIdentity", "000001")
        .present("camel.sai_Present_element")
        .show("camel.extensions", "1")
        .show("camel.extension_code_local", "1")
        .present("camel.gPRSMSClass_element")
        .hex("gsm_map.ms.mSNetworkCapability", "e5e0")
        .hex("gsm_map.ms.mSRadioAccessCapability", "17a300");
}

#[test]
fn user_csg_information_in_the_gprs_location_is_pinned_by_bytes_only() {
    // userCSGInformation [7] of LocationInformationGPRS is in TS 29.078
    // V18.0.0 but not in the Release 7 module Wireshark 4.6 dissects with, so
    // there is no independent decoder for it here: known-answer only. The same
    // UserCSGInformation type inside the MAP LocationInformation is checked
    // against Wireshark in `tests/location_information.rs`.
    let mut csg_id = BitString::from_vec(vec![0x00, 0x00, 0x00, 0x20]);
    csg_id.truncate(27);
    known_answer(
        &LocationInformationGprs {
            user_csg_information: Some(UserCsgInformation {
                csg_id,
                extension_container: None,
                access_mode: None,
                cmi: None,
            }),
            ..Default::default()
        },
        "
        30 09
           a7 07                               -- userCSGInformation [7]
              80 05 05 00 00 00 20             --   csg-Id [0] BIT STRING, 27 bits, 5 unused
        ",
    );
}

#[test]
fn initial_dp_sms_rejects_the_tags_this_crate_used_to_emit() {
    // Before 2.0.0 every member from sMSCAddress on was one tag too low
    // (sMSCAddress on [6], which is locationInformationGPRS, and so on).
    let old = vector("30 0a 80 01 07 86 05 91 51 55 10 30");
    assert!(gsm_cap::decode::<InitialDpSmsArg>(&old).is_err());
}

// ── ConnectSMS, ReleaseSMS ──────────────────────────────────────────────────

#[test]
fn connect_sms_with_every_member() {
    let arg = ConnectSmsArg {
        calling_partys_number: Some(vector("91 51 55 10 10").into()),
        destination_subscriber_number: Some(vector("91 51 55 10 20").into()),
        smsc_address: Some(vector("91 51 55 10 30").into()),
        extensions: Some(vec![extension()]),
    };
    let ber = known_answer(
        &arg,
        "
        30 21                                  -- 7 + 7 + 7 + 12 = 33
           80 05 91 51 55 10 10                -- callingPartysNumber [0]
           81 05 91 51 55 10 20                -- destinationSubscriberNumber [1]
           82 05 91 51 55 10 30                -- sMSCAddress [2]
           aa 0a 30 08 02 01 01 a1 03 01 01 ff -- extensions [10]
        ",
    );
    let Some(d) = dissect(op_codes::CONNECT_SMS, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.present("camel.ConnectSMSArg_element")
        .hex("camel.callingPartysNumber", "9151551010")
        .hex("camel.destinationSubscriberNumber", "9151551020")
        .hex("camel.sMSCAddress", "9151551030")
        .show("camel.extensions", "1")
        .show("camel.extension_code_local", "1");
}

#[test]
fn release_sms_is_a_bare_rp_cause() {
    // ReleaseSMSArg ::= RPCause ::= OCTET STRING (SIZE (1)). 0x15 is RP-Cause
    // 21, short message transfer rejected (TS 24.011).
    let ber = known_answer(&ReleaseSmsArg(vec![0x15].into()), "04 01 15");
    let Some(d) = dissect(op_codes::RELEASE_SMS, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.hex("camel.ReleaseSMSArg", "15")
        .show("camel.RP_Cause", "21");
}

#[test]
fn release_sms_rejects_the_sequence_wrapper() {
    // Before 2.0.0: SEQUENCE { OCTET STRING }.
    assert!(gsm_cap::decode::<ReleaseSmsArg>(&vector("30 03 04 01 15")).is_err());
}

// ── RequestReportSMSEvent, EventReportSMS ───────────────────────────────────

#[test]
fn request_report_sms_event() {
    let arg = RequestReportSmsEventArg {
        sms_events: vec![
            SmsEvent {
                event_type_sms: EventTypeSms::OSmsFailure,
                monitor_mode: MonitorMode::Interrupted,
            },
            SmsEvent {
                event_type_sms: EventTypeSms::OSmsSubmission,
                monitor_mode: MonitorMode::NotifyAndContinue,
            },
        ],
        extensions: Some(vec![extension()]),
    };
    let ber = known_answer(
        &arg,
        "
        30 1e                                  -- 18 + 12 = 30
           a0 10                               -- sMSEvents [0]
              30 06 80 01 02 81 01 00          --   o-smsFailure(2), interrupted(0)
              30 06 80 01 03 81 01 01          --   o-smsSubmission(3), notifyAndContinue(1)
           aa 0a 30 08 02 01 01 a1 03 01 01 ff -- extensions [10]
        ",
    );
    let Some(d) = dissect(
        op_codes::REQUEST_REPORT_SMS_EVENT,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("camel.sMSEvents", "2")
        .show_all("camel.eventTypeSMS", &["2", "3"])
        .show_all("camel.monitorMode", &["0", "1"])
        .show("camel.extensions", "1");
}

fn sms_report(
    event: EventTypeSms,
    info: EventSpecificInformationSms,
    misc: MiscCallInfo,
) -> EventReportSmsArg {
    EventReportSmsArg {
        event_specific_information_sms: Some(info),
        misc_call_info: Some(misc),
        ..EventReportSmsArg::new(event)
    }
}

#[test]
fn event_report_sms_alternatives() {
    let cases = [
        (
            sms_report(
                EventTypeSms::OSmsFailure,
                EventSpecificInformationSms::OSmsFailureSpecificInfo(OSmsFailureSpecificInfo {
                    failure_cause: Some(MoSmsCause::FacilityNotSupported),
                }),
                MiscCallInfo::request(),
            ),
            "
            30 0f                              -- 3 + 7 + 5 = 15
               80 01 02                        -- eventTypeSMS o-smsFailure(2)
               a1 05                           -- eventSpecificInformationSMS [1] EXPLICIT
                  a0 03 80 01 02               --   o-smsFailureSpecificInfo [0]
                                               --     { failureCause [0] facilityNotSupported(2) }
               a2 03 80 01 00                  -- miscCallInfo [2] { messageType request }
            ",
        ),
        (
            sms_report(
                EventTypeSms::OSmsSubmission,
                EventSpecificInformationSms::OSmsSubmissionSpecificInfo(EmptySmsSpecificInfo {}),
                MiscCallInfo::notification(),
            ),
            "
            30 0c
               80 01 03                        -- o-smsSubmission(3)
               a1 02 a1 00                     -- [1] EXPLICIT { o-smsSubmissionSpecificInfo [1] {} }
               a2 03 80 01 01                  -- messageType notification
            ",
        ),
        (
            sms_report(
                EventTypeSms::TSmsFailure,
                EventSpecificInformationSms::TSmsFailureSpecificInfo(TSmsFailureSpecificInfo {
                    failure_cause: Some(vec![0x6f].into()),
                }),
                MiscCallInfo::request(),
            ),
            "
            30 0f
               80 01 0c                        -- t-smsFailure(12)
               a1 05                           -- [1] EXPLICIT
                  a2 03 80 01 6f               --   t-smsFailureSpecificInfo [2] { failureCause [0]
                                               --     RP-Cause 111, protocol error unspecified }
               a2 03 80 01 00
            ",
        ),
        (
            sms_report(
                EventTypeSms::TSmsDelivery,
                EventSpecificInformationSms::TSmsDeliverySpecificInfo(EmptySmsSpecificInfo {}),
                MiscCallInfo::notification(),
            ),
            "
            30 0c
               80 01 0d                        -- t-smsDelivery(13)
               a1 02 a3 00                     -- [1] EXPLICIT { t-smsDeliverySpecificInfo [3] {} }
               a2 03 80 01 01
            ",
        ),
    ];
    // What Wireshark must report for each case: event type, the chosen
    // alternative, the message type, and the cause field with its octet.
    let expected = [
        ("2", "0", "0", Some(("camel.mo-smsfailureCause", "02"))),
        ("3", "1", "1", None),
        ("12", "2", "0", Some(("camel.t-smsfailureCause", "6f"))),
        ("13", "3", "1", None),
    ];
    for ((arg, hand), (event, alternative, message_type, cause)) in cases.iter().zip(expected) {
        let ber = known_answer(arg, hand);
        let Some(d) = dissect(op_codes::EVENT_REPORT_SMS, Some(&ber), Carrier::Continue) else {
            return;
        };
        d.show("camel.eventTypeSMS", event)
            .show("camel.eventSpecificInformationSMS", alternative)
            .present("camel.miscCallInfo_element")
            .show("inap.messageType", message_type);
        if let Some((field, octet)) = cause {
            d.hex(field, octet);
        }
    }
}

#[test]
fn event_report_sms_rejects_primitive_members() {
    // Before 2.0.0 eventSpecificInformationSMS and miscCallInfo were opaque
    // primitive OCTET STRINGs, so a caller could put anything in them. A
    // miscCallInfo that is not the SEQUENCE the ASN.1 defines is refused.
    let old = vector("30 08 80 01 03 82 03 de ad 00");
    assert!(gsm_cap::decode::<EventReportSmsArg>(&old).is_err());
}
