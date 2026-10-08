//! The CHOICE alternatives and optional members the operation-focused test
//! files do not reach, so that every alternative this crate can emit has a
//! hand-assembled vector, and a Wireshark dissection where Wireshark knows it.
//!
//! See `tests/bcsm_events.rs` for the tag octet rules. Values are synthetic.

mod common;

use common::{dissect, known_answer, vector, Carrier};
use gsm_cap::application_context as ac;
use gsm_cap::op_codes;
use gsm_cap::operations::{EventReportBcsmArg, InitialDpArg, RequestReportBcsmEventArg};
use gsm_cap::types::{
    BcsmEvent, ChangeOfLocation, ChangeOfLocationAlt, ChangeOfPositionSpecificInfo, Code,
    CriticalityType, DpAssignment, DpSpecificCriteria, DpSpecificCriteriaAlt,
    EventSpecificInformationBcsm, EventTypeBcsm, ExtensionContainer, ExtensionField, LegId,
    LocationInformation, MessageType, MetDpCriterion, MetDpCriterionAlt, MiscCallInfo, MonitorMode,
    NotReachableReason, PcsExtensions, PrivateExtension, SubscriberState, LEG1,
};
use rasn::types::{Any, Integer, ObjectIdentifier};

#[test]
fn change_of_location_alternatives_and_digit_criteria() {
    let arg = RequestReportBcsmEventArg::new(vec![
        BcsmEvent {
            dp_specific_criteria: Some(DpSpecificCriteria::DpSpecificCriteriaAlt(
                DpSpecificCriteriaAlt {
                    change_of_position_control_info: Some(vec![
                        ChangeOfLocation::ServiceAreaId(vector("00 f1 10 00 01 00 03").into()),
                        ChangeOfLocation::LocationAreaId(vector("00 f1 10 00 01").into()),
                        ChangeOfLocation::InterSystemHandOver(()),
                        ChangeOfLocation::InterPlmnHandOver(()),
                        ChangeOfLocation::ChangeOfLocationAlt(ChangeOfLocationAlt {}),
                    ]),
                    ..Default::default()
                },
            )),
            ..BcsmEvent::new(
                EventTypeBcsm::TChangeOfPosition,
                MonitorMode::NotifyAndContinue,
            )
        },
        BcsmEvent {
            leg_id: Some(LegId::receiving(LEG1)),
            dp_specific_criteria: Some(DpSpecificCriteria::DpSpecificCriteriaAlt(
                DpSpecificCriteriaAlt {
                    change_of_position_control_info: Some(vec![
                        ChangeOfLocation::InterMscHandOver(()),
                    ]),
                    number_of_digits: Some(3),
                    inter_digit_timeout: Some(5),
                },
            )),
            ..BcsmEvent::new(EventTypeBcsm::CollectedInfo, MonitorMode::Interrupted)
        },
    ]);
    let ber = known_answer(
        &arg,
        "
        30 41
           a0 3f                               -- bcsmEvents [0], 36 + 27 = 63
              30 22                            -- 3 + 3 + 28 = 34
                 80 01 33                      -- tChangeOfPosition(51)
                 81 01 01                      -- notifyAndContinue
                 be 1a                         -- dpSpecificCriteria [30] EXPLICIT
                    a3 18                      --   dpSpecificCriteriaAlt [3]
                       a0 16                   --     changeOfPositionControlInfo [0], 9+7+2+2+2
                          81 07 00 f1 10 00 01 00 03  -- serviceAreaId [1]
                          82 05 00 f1 10 00 01 --       locationAreaId [2]
                          83 00                --       inter-SystemHandOver [3] NULL
                          84 00                --       inter-PLMNHandOver [4] NULL
                          a6 00                --       changeOfLocationAlt [6] {}
              30 19                            -- 3 + 3 + 5 + 14 = 25
                 80 01 02                      -- collectedInfo(2)
                 81 01 00                      -- interrupted
                 a2 03 81 01 01                -- legID [2] EXPLICIT { receivingSideID [1] leg1 }
                 be 0c                         -- dpSpecificCriteria [30] EXPLICIT
                    a3 0a                      --   dpSpecificCriteriaAlt [3], 4 + 3 + 3
                       a0 02 85 00             --     changeOfPositionControlInfo { inter-MSCHandOver }
                       81 01 03                --     numberOfDigits [1] 3
                       82 01 05                --     interDigitTimeout [2] 5 s
        ",
    );
    let Some(d) = dissect(
        op_codes::REQUEST_REPORT_BCSM_EVENT,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show_all("camel.eventTypeBCSM", &["51", "2"])
        .show_all("camel.ChangeOfLocation", &["1", "2", "3", "4", "6", "5"])
        .hex("camel.serviceAreaId", "00f11000010003")
        .hex("camel.locationAreaId", "00f1100001")
        .present("camel.inter_SystemHandOver_element")
        .present("camel.inter_PLMNHandOver_element")
        .present("camel.changeOfLocationAlt_element")
        .present("camel.inter_MSCHandOver_element")
        .show("camel.legID", "1")
        .hex("inap.receivingSideID", "01")
        .show("camel.numberOfDigits", "3")
        .show("camel.interDigitTimeout", "5");
}

#[test]
fn digit_criteria_without_a_position_list() {
    // The form the ASN.1 as published does not allow (changeOfPositionControlInfo
    // has no OPTIONAL) but which is the only one that makes sense for a
    // collectedInfo criterion. Wireshark follows the ASN.1 and flags it, so
    // this one is pinned by bytes only.
    known_answer(
        &DpSpecificCriteria::DpSpecificCriteriaAlt(DpSpecificCriteriaAlt {
            change_of_position_control_info: None,
            number_of_digits: Some(3),
            inter_digit_timeout: None,
        }),
        "a3 03 81 01 03                        -- dpSpecificCriteriaAlt [3] { numberOfDigits [1] 3 }",
    );
}

#[test]
fn met_dp_criterion_alternatives() {
    let arg = EventReportBcsmArg {
        event_specific_information_bcsm: Some(
            EventSpecificInformationBcsm::OChangeOfPositionSpecificInfo(
                ChangeOfPositionSpecificInfo {
                    location_information: Some(LocationInformation {
                        age_of_location_information: Some(0),
                        ..Default::default()
                    }),
                    met_dp_criteria_list: Some(vec![
                        MetDpCriterion::LeavingCellGlobalId(vector("00 f1 10 00 01 00 02").into()),
                        MetDpCriterion::EnteringServiceAreaId(
                            vector("00 f1 10 00 01 00 03").into(),
                        ),
                        MetDpCriterion::LeavingServiceAreaId(vector("00 f1 10 00 01 00 04").into()),
                        MetDpCriterion::EnteringLocationAreaId(vector("00 f1 10 00 02").into()),
                        MetDpCriterion::LeavingLocationAreaId(vector("00 f1 10 00 01").into()),
                        MetDpCriterion::InterSystemHandOverToUmts(()),
                        MetDpCriterion::InterSystemHandOverToGsm(()),
                        MetDpCriterion::InterPlmnHandOver(()),
                        MetDpCriterion::MetDpCriterionAlt(MetDpCriterionAlt {}),
                    ]),
                },
            ),
        ),
        ..EventReportBcsmArg::new(EventTypeBcsm::OChangeOfPosition)
    };
    let ber = known_answer(
        &arg,
        "
        30 42                                  -- 3 + 63 = 66
           80 01 32                            -- oChangeOfPosition(50)
           a2 3d                               -- eventSpecificInformationBCSM [2] EXPLICIT
              bf 32 3a                         --   oChangeOfPositionSpecificInfo [50], 6 + 52
                 bf 32 03 02 01 00             --     locationInformation [50] { age 0 }
                 bf 33 31                      --     metDPCriteriaList [51], 27 + 14 + 6 + 2 = 49
                    81 07 00 f1 10 00 01 00 02 --       leavingCellGlobalId [1]
                    82 07 00 f1 10 00 01 00 03 --       enteringServiceAreaId [2]
                    83 07 00 f1 10 00 01 00 04 --       leavingServiceAreaId [3]
                    84 05 00 f1 10 00 02       --       enteringLocationAreaId [4]
                    85 05 00 f1 10 00 01       --       leavingLocationAreaId [5]
                    86 00                      --       inter-SystemHandOverToUMTS [6] NULL
                    87 00                      --       inter-SystemHandOverToGSM [7] NULL
                    88 00                      --       inter-PLMNHandOver [8] NULL
                    aa 00                      --       metDPCriterionAlt [10] {}
        ",
    );
    let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.metDPCriteriaList", "9")
        .show_all(
            "camel.MetDPCriterion",
            &["1", "2", "3", "4", "5", "6", "7", "8", "10"],
        )
        .hex("camel.leavingCellGlobalId", "00f11000010002")
        .hex("camel.enteringServiceAreaId", "00f11000010003")
        .hex("camel.leavingServiceAreaId", "00f11000010004")
        .hex("camel.enteringLocationAreaId", "00f1100002")
        .hex("camel.leavingLocationAreaId", "00f1100001")
        .present("camel.inter_SystemHandOverToUMTS_element")
        .present("camel.inter_SystemHandOverToGSM_element")
        .present("camel.inter_PLMNHandOver_element")
        .present("camel.metDPCriterionAlt_element")
        .show("gsm_map.ms.ageOfLocationInformation", "0");
}

#[test]
fn misc_call_info_with_the_cs2_dp_assignment() {
    // MiscCallInfo is imported from CS2-datatypes, where it has a second,
    // optional member. CAP never sends it; it is decoded so that a peer that
    // does is not refused.
    let arg = EventReportBcsmArg {
        misc_call_info: Some(MiscCallInfo {
            message_type: MessageType::Notification,
            dp_assignment: Some(DpAssignment::GroupBased),
        }),
        ..EventReportBcsmArg::new(EventTypeBcsm::OAnswer)
    };
    let ber = known_answer(
        &arg,
        "
        30 0b
           80 01 07                            -- oAnswer(7)
           a4 06                               -- miscCallInfo [4]
              80 01 01                         --   messageType [0] notification(1)
              81 01 01                         --   dpAssignment [1] groupBased(1)
        ",
    );
    let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.messageType", "1")
        .show("inap.dpAssignment", "1");
}

#[test]
fn globally_identified_extension_and_map_extension_container() {
    let example_arc = || ObjectIdentifier::new_unchecked(vec![2, 999, 1].into());
    let arg = InitialDpArg {
        extensions: Some(vec![ExtensionField {
            extension_type: Code::Global(example_arc()),
            criticality: Some(CriticalityType::Ignore),
            value: Any::new(vec![0x01, 0x01, 0xff]),
        }]),
        subscriber_state: Some(SubscriberState::CamelBusy(())),
        location_information: Some(LocationInformation {
            extension_container: Some(ExtensionContainer {
                private_extension_list: Some(vec![PrivateExtension {
                    ext_id: example_arc(),
                    ext_type: Some(Any::new(vec![0x04, 0x01, 0xaa])),
                }]),
                pcs_extensions: Some(PcsExtensions {}),
            }),
            ..Default::default()
        }),
        ..InitialDpArg::new(Integer::from(1))
    };
    let ber = known_answer(
        &arg,
        "
        30 2c                                  -- 3 + 17 + 5 + 19 = 44
           80 01 01                            -- serviceKey 1
           af 0f                               -- extensions [15]
              30 0d                            --   ExtensionField, 5 + 3 + 5
                 06 03 88 37 01                --     type: global 2.999.1 (2*40+999 = 1079 = 88 37)
                 0a 01 00                      --     criticality: ignore(0), the default, sent anyway
                 a1 03 01 01 ff                --     value [1] EXPLICIT BOOLEAN TRUE
           bf 33 02 81 00                      -- subscriberState [51] EXPLICIT { camelBusy [1] NULL }
           bf 34 10                            -- locationInformation [52]
              a4 0e                            --   extensionContainer [4]
                 a0 0a                         --     privateExtensionList [0]
                    30 08 06 03 88 37 01       --       { extId 2.999.1,
                          04 01 aa             --         extType: an OCTET STRING }
                 a1 00                         --     pcs-Extensions [1] {}
        ",
    );
    let context = ac::object_identifier(&ac::CAP_V4_GSMSSF_SCF_GENERIC);
    // Not `dissect`: Wireshark reads the structure but has no dissector for
    // a value identified by the example arc 2.999.1, and says so twice (once
    // per open type). Those two notes are the only complaints allowed.
    let Some(d) =
        common::dissect_unchecked(op_codes::INITIAL_DP, Some(&ber), Carrier::Begin(&context))
    else {
        return;
    };
    let errors: Vec<&str> = d
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .filter(|name| name.starts_with("ber.error") || name.starts_with("_ws.malformed"))
        .collect();
    assert_eq!(
        errors,
        ["ber.error.oid_not_implemented"; 2],
        "{}",
        d.summary()
    );
    d.show("camel.local", "0")
        .show("camel.extensions", "1")
        // Alternative 1 of Code: global.
        .show("camel.type", "1")
        .show("camel.global", "2.999.1")
        .show("camel.criticality", "0")
        .show("camel.subscriberState", "1")
        .present("gsm_map.ms.camelBusy_element")
        .present("gsm_map.ms.extensionContainer_element")
        .show("gsm_map.privateExtensionList", "1")
        .show("gsm_map.extId", "2.999.1")
        .present("gsm_map.pcs_Extensions_element");
}

#[test]
fn subscriber_state_alternatives() {
    for (state, hand) in [
        (
            SubscriberState::AssumedIdle(()),
            "30 08 80 01 01 bf 33 02 80 00      -- assumedIdle [0] NULL",
        ),
        (
            SubscriberState::NotProvidedFromVlr(()),
            "30 08 80 01 01 bf 33 02 82 00      -- notProvidedFromVLR [2] NULL",
        ),
        (
            SubscriberState::NetDetNotReachable(NotReachableReason::NotRegistered),
            "30 09 80 01 01 bf 33 03 0a 01 03   -- netDetNotReachable ENUMERATED notRegistered(3)",
        ),
    ] {
        let arg = InitialDpArg {
            subscriber_state: Some(state),
            ..InitialDpArg::new(Integer::from(1))
        };
        let ber = known_answer(&arg, hand);
        let context = ac::object_identifier(&ac::CAP_V3_GSMSSF_SCF_GENERIC);
        let Some(d) = dissect(op_codes::INITIAL_DP, Some(&ber), Carrier::Begin(&context)) else {
            return;
        };
        d.present("camel.subscriberState");
    }
}
