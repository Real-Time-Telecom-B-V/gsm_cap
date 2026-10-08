//! RequestReportBCSMEvent (op 23) and EventReportBCSM (op 24), 3GPP TS 29.078
//! V18.0.0 clauses 5.1 and 6.1.1.
//!
//! Every vector below was assembled by hand from the ASN.1, with the
//! derivation next to the bytes; none was produced by this crate. Each is
//! checked in both directions (encode gives exactly these bytes, these bytes
//! decode to exactly this value) and, when `tshark` is installed, handed to
//! Wireshark, whose decoded fields are asserted.
//!
//! Tag octets used throughout (IMPLICIT TAGS module):
//!
//! ```text
//!   [n] primitive, n <= 30      80 + n          [0] = 80, [4] = 84
//!   [n] constructed, n <= 30    A0 + n          [2] = A2, [20] = B4, [30] = BE
//!   [n] primitive, n > 30       9F n            [50] = 9F 32, [53] = 9F 35
//!   [n] constructed, n > 30     BF n            [50] = BF 32, [52] = BF 34
//! ```
//!
//! Values are synthetic: PLMN 001/01, numbers in the fictional `+1 555 01xx`
//! range.

mod common;

use common::{dissect, known_answer, vector, Carrier, Dissection};
use gsm_cap::op_codes;
use gsm_cap::operations::{EventReportBcsmArg, RequestReportBcsmEventArg};
use gsm_cap::types::{
    AlertingSpecificInfo, AnswerSpecificInfo, BcsmEvent, CauseSpecificInfo, ChangeOfLocation,
    ChangeOfPositionSpecificInfo, Code, CollectedInfoSpecificInfo, CriticalityType,
    DpSpecificCriteria, DpSpecificCriteriaAlt, DpSpecificInfoAlt, EventSpecificInformationBcsm,
    EventTypeBcsm, ExtBasicServiceCode, ExtensionField, InitiatorOfServiceChange, LegId,
    LocationInformation, MetDpCriterion, MidCallControlInfo, MidCallEvents, MidCallSpecificInfo,
    MiscCallInfo, MonitorMode, NatureOfServiceChange, OAbandonSpecificInfo, ONoAnswerSpecificInfo,
    ReceivingSideId, ServiceChangeSpecificInfo, TBusySpecificInfo, TNoAnswerSpecificInfo, LEG1,
    LEG2,
};
use rasn::types::{Any, Integer};

fn rrbe(arg: &RequestReportBcsmEventArg, hand: &str) -> Option<Dissection> {
    let ber = known_answer(arg, hand);
    dissect(
        op_codes::REQUEST_REPORT_BCSM_EVENT,
        Some(&ber),
        Carrier::Continue,
    )
}

fn erb(arg: &EventReportBcsmArg, hand: &str) -> Option<Dissection> {
    let ber = known_answer(arg, hand);
    dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue)
}

// ── RequestReportBCSMEvent ──────────────────────────────────────────────────
//
//   RequestReportBCSMEventArg ::= SEQUENCE {
//     bcsmEvents [0] SEQUENCE SIZE(1..numOfBCSMEvents) OF BCSMEvent,
//     extensions [2] Extensions OPTIONAL, ...}
//   BCSMEvent ::= SEQUENCE {
//     eventTypeBCSM      [0]  EventTypeBCSM,
//     monitorMode        [1]  MonitorMode,
//     legID              [2]  LegID OPTIONAL,               -- CHOICE: explicit
//     dpSpecificCriteria [30] DpSpecificCriteria OPTIONAL,  -- CHOICE: explicit
//     automaticRearm     [50] NULL OPTIONAL, ...}

#[test]
fn request_report_arms_the_originating_call_model() {
    // What a prepaid service arms after InitialDP on the originating side.
    let arg = RequestReportBcsmEventArg::new(vec![
        BcsmEvent::new(EventTypeBcsm::RouteSelectFailure, MonitorMode::Interrupted),
        BcsmEvent::new(EventTypeBcsm::OCalledPartyBusy, MonitorMode::Interrupted),
        BcsmEvent {
            leg_id: Some(LegId::sending(LEG2)),
            dp_specific_criteria: Some(DpSpecificCriteria::ApplicationTimer(20)),
            ..BcsmEvent::new(EventTypeBcsm::ONoAnswer, MonitorMode::Interrupted)
        },
        BcsmEvent::new(EventTypeBcsm::OAnswer, MonitorMode::NotifyAndContinue),
        BcsmEvent {
            leg_id: Some(LegId::sending(LEG1)),
            ..BcsmEvent::new(EventTypeBcsm::ODisconnect, MonitorMode::Interrupted)
        },
        BcsmEvent {
            leg_id: Some(LegId::sending(LEG2)),
            ..BcsmEvent::new(EventTypeBcsm::ODisconnect, MonitorMode::Interrupted)
        },
        BcsmEvent::new(EventTypeBcsm::OAbandon, MonitorMode::NotifyAndContinue),
    ]);
    let Some(d) = rrbe(
        &arg,
        "
        30 4e                                  -- 78 octets
           a0 4c                               -- bcsmEvents [0], 8+8+18+8+13+13+8 = 76
              30 06 80 01 04 81 01 00          -- routeSelectFailure(4), interrupted(0)
              30 06 80 01 05 81 01 00          -- oCalledPartyBusy(5), interrupted
              30 10 80 01 06 81 01 00          -- oNoAnswer(6), interrupted
                    a2 03 80 01 02             --   legID [2] EXPLICIT { sendingSideID [0] leg2 }
                    be 03 81 01 14             --   dpSpecificCriteria [30] EXPLICIT
                                               --     { applicationTimer [1] 20 s }
              30 06 80 01 07 81 01 01          -- oAnswer(7), notifyAndContinue(1)
              30 0b 80 01 09 81 01 00          -- oDisconnect(9), interrupted
                    a2 03 80 01 01             --   sendingSideID leg1
              30 0b 80 01 09 81 01 00          -- oDisconnect(9), interrupted
                    a2 03 80 01 02             --   sendingSideID leg2
              30 06 80 01 0a 81 01 01          -- oAbandon(10), notifyAndContinue
        ",
    ) else {
        return;
    };
    d.show_all("camel.eventTypeBCSM", &["4", "5", "6", "7", "9", "9", "10"])
        .show_all("camel.monitorMode", &["0", "0", "0", "1", "0", "0", "1"])
        // Wireshark reports the chosen LegID alternative (0 = sendingSideID) and
        // then the leg, for the three events that carry one.
        .show_all("camel.legID", &["0", "0", "0"])
        .hex_all("inap.sendingSideID", &["02", "01", "02"])
        .show("camel.dpSpecificCriteria", "1")
        .show("camel.applicationTimer", "20");
}

#[test]
fn request_report_carries_phase_4_criteria_and_extensions() {
    let arg = RequestReportBcsmEventArg {
        bcsm_events: vec![
            BcsmEvent {
                leg_id: Some(LegId::sending(LEG1)),
                dp_specific_criteria: Some(DpSpecificCriteria::MidCallControlInfo(
                    MidCallControlInfo {
                        minimum_number_of_digits: Some(1),
                        maximum_number_of_digits: Some(4),
                        end_of_reply_digit: Some(vec![0x0c].into()),
                        inter_digit_timeout: Some(5),
                        ..Default::default()
                    },
                )),
                automatic_rearm: Some(()),
                ..BcsmEvent::new(EventTypeBcsm::OMidCall, MonitorMode::NotifyAndContinue)
            },
            BcsmEvent {
                dp_specific_criteria: Some(DpSpecificCriteria::DpSpecificCriteriaAlt(
                    DpSpecificCriteriaAlt {
                        change_of_position_control_info: Some(vec![
                            ChangeOfLocation::CellGlobalId(vector("00 f1 10 00 01 00 02").into()),
                            ChangeOfLocation::InterMscHandOver(()),
                        ]),
                        ..Default::default()
                    },
                )),
                ..BcsmEvent::new(
                    EventTypeBcsm::OChangeOfPosition,
                    MonitorMode::NotifyAndContinue,
                )
            },
        ],
        extensions: Some(vec![ExtensionField {
            extension_type: Code::Local(Integer::from(1)),
            criticality: Some(CriticalityType::Abort),
            // The extension's own type, here a BOOLEAN TRUE.
            value: Any::new(vec![0x01, 0x01, 0xff]),
        }]),
    };
    let Some(d) = rrbe(
        &arg,
        "
        30 4a                                  -- 59 + 15 = 74 octets
           a0 39                               -- bcsmEvents [0], 32 + 25 = 57
              30 1e                            -- 3 + 3 + 5 + 16 + 3 = 30
                 80 01 08                      -- oMidCall(8)
                 81 01 01                      -- notifyAndContinue
                 a2 03 80 01 01                -- legID: sendingSideID leg1
                 be 0e                         -- dpSpecificCriteria [30] EXPLICIT
                    a2 0c                      --   midCallControlInfo [2]
                       80 01 01                --     minimumNumberOfDigits 1
                       81 01 04                --     maximumNumberOfDigits 4
                       82 01 0c                --     endOfReplyDigit '#'
                       86 01 05                --     interDigitTimeout [6] 5 s
                 9f 32 00                      -- automaticRearm [50] NULL
              30 17                            -- 3 + 3 + 17 = 23
                 80 01 32                      -- oChangeOfPosition(50)
                 81 01 01                      -- notifyAndContinue
                 be 0f                         -- dpSpecificCriteria [30] EXPLICIT
                    a3 0d                      --   dpSpecificCriteriaAlt [3]
                       a0 0b                   --     changeOfPositionControlInfo [0]
                          80 07 00 f1 10 00 01 00 02  -- cellGlobalId [0]
                          85 00                --       inter-MSCHandOver [5] NULL
           a2 0d                               -- extensions [2]
              30 0b                            --   ExtensionField
                 02 01 01                      --     type: local 1
                 0a 01 01                      --     criticality: abort(1)
                 a1 03 01 01 ff                --     value [1] EXPLICIT BOOLEAN TRUE
        ",
    ) else {
        return;
    };
    d.show_all("camel.eventTypeBCSM", &["8", "50"])
        .hex("inap.sendingSideID", "01")
        .show_all("camel.dpSpecificCriteria", &["2", "3"])
        .show("camel.minimumNumberOfDigits", "1")
        .show("camel.maximumNumberOfDigits", "4")
        .hex("camel.endOfReplyDigit", "0c")
        .show("camel.interDigitTimeout", "5")
        .present("camel.automaticRearm_element")
        .show("camel.changeOfPositionControlInfo", "2")
        .hex("camel.cellGlobalId", "00f11000010002")
        .present("camel.inter_MSCHandOver_element")
        .show("camel.extensions", "1")
        .show("camel.extension_code_local", "1")
        .show("camel.criticality", "1");
}

#[test]
fn request_report_rejects_a_primitive_leg_id() {
    // What this crate emitted before 2.0.0: legID as `82 01 01`, a primitive
    // [2] OCTET STRING. LegID is a CHOICE, so [2] wraps `80 01 01`.
    let old = vector("30 0d a0 0b 30 09 80 01 09 81 01 00 82 01 01");
    assert!(gsm_cap::decode::<RequestReportBcsmEventArg>(&old).is_err());
}

// ── EventReportBCSM ─────────────────────────────────────────────────────────
//
//   EventReportBCSMArg ::= SEQUENCE {
//     eventTypeBCSM                [0] EventTypeBCSM,
//     eventSpecificInformationBCSM [2] EventSpecificInformationBCSM OPTIONAL,  -- explicit
//     legID                        [3] ReceivingSideID OPTIONAL,               -- explicit
//     miscCallInfo                 [4] MiscCallInfo DEFAULT {messageType request},
//     extensions                   [5] Extensions OPTIONAL, ...}

fn report(
    event: EventTypeBcsm,
    info: EventSpecificInformationBcsm,
    leg: u8,
    misc: MiscCallInfo,
) -> EventReportBcsmArg {
    EventReportBcsmArg {
        event_specific_information_bcsm: Some(info),
        leg_id: Some(ReceivingSideId::leg(leg)),
        misc_call_info: Some(misc),
        ..EventReportBcsmArg::new(event)
    }
}

#[test]
fn event_report_answer() {
    let arg = report(
        EventTypeBcsm::OAnswer,
        EventSpecificInformationBcsm::OAnswerSpecificInfo(AnswerSpecificInfo {
            destination_address: Some(vector("04 10 51 55 10 10").into()),
            forwarded_call: Some(()),
            charge_indicator: Some(vec![0x02].into()),
            ext_basic_service_code: Some(ExtBasicServiceCode::ExtTeleservice(vec![0x11].into())),
            ..Default::default()
        }),
        LEG2,
        MiscCallInfo::notification(),
    );
    let Some(d) = erb(
        &arg,
        "
        30 27                                  -- 3 + 26 + 5 + 5 = 39
           80 01 07                            -- eventTypeBCSM oAnswer(7)
           a2 18                               -- eventSpecificInformationBCSM [2] EXPLICIT
              a5 16                            --   oAnswerSpecificInfo [5], 9 + 3 + 4 + 6
                 9f 32 06 04 10 51 55 10 10    --     destinationAddress [50], 15550101
                 9f 34 00                      --     forwardedCall [52] NULL
                 9f 35 01 02                   --     chargeIndicator [53]
                 bf 36 03 83 01 11             --     ext-basicServiceCode [54] EXPLICIT
                                               --       { ext-Teleservice [3] telephony }
           a3 03 81 01 02                      -- legID [3] EXPLICIT { receivingSideID [1] leg2 }
           a4 03 80 01 01                      -- miscCallInfo [4] { messageType [0] notification }
        ",
    ) else {
        return;
    };
    d.show("camel.eventTypeBCSM", "7")
        .show("camel.eventSpecificInformationBCSM", "5")
        .hex("camel.destinationAddress", "041051551010")
        .present("camel.forwardedCall_element")
        .absent("camel.or_Call_element")
        .hex("camel.chargeIndicator", "02")
        .show("camel.ext_basicServiceCode", "3")
        .show("gsm_map.ext_Teleservice", "17")
        .show("camel.legID", "1")
        .hex("camel.receivingSideID", "02")
        .present("camel.miscCallInfo_element")
        .show("inap.messageType", "1");
}

#[test]
fn event_report_disconnect() {
    let arg = report(
        EventTypeBcsm::ODisconnect,
        EventSpecificInformationBcsm::ODisconnectSpecificInfo(CauseSpecificInfo {
            cause: Some(vec![0x80, 0x90].into()),
        }),
        LEG1,
        MiscCallInfo::request(),
    );
    let Some(d) = erb(
        &arg,
        "
        30 15                                  -- 3 + 8 + 5 + 5 = 21
           80 01 09                            -- oDisconnect(9)
           a2 06                               -- [2] EXPLICIT
              a7 04                            --   oDisconnectSpecificInfo [7]
                 80 02 80 90                   --     releaseCause [0]: normal call clearing
           a3 03 81 01 01                      -- receivingSideID leg1
           a4 03 80 01 00                      -- messageType request(0)
        ",
    ) else {
        return;
    };
    d.show("camel.eventTypeBCSM", "9")
        .show("camel.eventSpecificInformationBCSM", "7")
        .hex("camel.releaseCause", "8090")
        .show("camel.cause_indicator", "16")
        .hex("camel.receivingSideID", "01")
        .show("inap.messageType", "0");
}

#[test]
fn event_report_route_select_failure_busy_and_t_disconnect() {
    // The three other alternatives that carry only a cause on [0].
    let Some(d) = erb(
        &report(
            EventTypeBcsm::RouteSelectFailure,
            EventSpecificInformationBcsm::RouteSelectFailureSpecificInfo(CauseSpecificInfo {
                cause: Some(vec![0x80, 0x83].into()),
            }),
            LEG2,
            MiscCallInfo::request(),
        ),
        "30 15  80 01 04  a2 06 a2 04 80 02 80 83  a3 03 81 01 02  a4 03 80 01 00
         -- routeSelectFailure(4); routeSelectFailureSpecificInfo [2] { failureCause [0] }",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "2")
        .hex("camel.routeSelectfailureCause", "8083");

    let Some(d) = erb(
        &report(
            EventTypeBcsm::OCalledPartyBusy,
            EventSpecificInformationBcsm::OCalledPartyBusySpecificInfo(CauseSpecificInfo {
                cause: Some(vec![0x80, 0x91].into()),
            }),
            LEG2,
            MiscCallInfo::request(),
        ),
        "30 15  80 01 05  a2 06 a3 04 80 02 80 91  a3 03 81 01 02  a4 03 80 01 00
         -- oCalledPartyBusy(5); oCalledPartyBusySpecificInfo [3] { busyCause [0] user busy }",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "3")
        .hex("camel.busyCause", "8091");

    let Some(d) = erb(
        &report(
            EventTypeBcsm::TDisconnect,
            EventSpecificInformationBcsm::TDisconnectSpecificInfo(CauseSpecificInfo {
                cause: Some(vec![0x80, 0x90].into()),
            }),
            LEG2,
            MiscCallInfo::request(),
        ),
        "30 15  80 01 11  a2 06 ac 04 80 02 80 90  a3 03 81 01 02  a4 03 80 01 00
         -- tDisconnect(17); tDisconnectSpecificInfo [12] { releaseCause [0] }",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "12")
        .hex("camel.releaseCause", "8090");
}

#[test]
fn event_report_no_answer_has_an_empty_specific_info() {
    let mut arg = EventReportBcsmArg::new(EventTypeBcsm::ONoAnswer);
    arg.event_specific_information_bcsm = Some(
        EventSpecificInformationBcsm::ONoAnswerSpecificInfo(ONoAnswerSpecificInfo {}),
    );
    arg.leg_id = Some(ReceivingSideId::leg(LEG2));
    let Some(d) = erb(
        &arg,
        "
        30 0c
           80 01 06                            -- oNoAnswer(6)
           a2 02 a4 00                         -- [2] EXPLICIT { oNoAnswerSpecificInfo [4] {} }
           a3 03 81 01 02                      -- receivingSideID leg2
                                               -- miscCallInfo absent: DEFAULT request
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "4")
        .present("camel.oNoAnswerSpecificInfo_element")
        .hex("camel.receivingSideID", "02")
        .absent("camel.miscCallInfo_element");
}

#[test]
fn event_report_terminating_busy_and_no_answer() {
    let Some(d) = erb(
        &report(
            EventTypeBcsm::TBusy,
            EventSpecificInformationBcsm::TBusySpecificInfo(TBusySpecificInfo {
                busy_cause: Some(vec![0x80, 0x91].into()),
                call_forwarded: Some(()),
                route_not_permitted: None,
                forwarding_destination_number: Some(vector("04 10 51 55 10 20").into()),
            }),
            LEG2,
            MiscCallInfo::request(),
        ),
        "
        30 21                                  -- 3 + 20 + 5 + 5 = 33
           80 01 0d                            -- tBusy(13)
           a2 12                               -- [2] EXPLICIT
              a8 10                            --   tBusySpecificInfo [8], 4 + 3 + 9
                 80 02 80 91                   --     busyCause [0]: user busy
                 9f 32 00                      --     callForwarded [50] NULL
                 9f 34 06 04 10 51 55 10 20    --     forwardingDestinationNumber [52], 15550102
           a3 03 81 01 02
           a4 03 80 01 00
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "8")
        .hex("camel.busyCause", "8091")
        .present("camel.callForwarded_element")
        .absent("camel.routeNotPermitted_element")
        .hex("camel.forwardingDestinationNumber", "041051551020");

    let Some(d) = erb(
        &report(
            EventTypeBcsm::TNoAnswer,
            EventSpecificInformationBcsm::TNoAnswerSpecificInfo(TNoAnswerSpecificInfo {
                call_forwarded: Some(()),
                forwarding_destination_number: Some(vector("04 10 51 55 10 20").into()),
            }),
            LEG2,
            MiscCallInfo::request(),
        ),
        "
        30 1d                                  -- 3 + 16 + 5 + 5 = 29
           80 01 0e                            -- tNoAnswer(14)
           a2 0e                               -- [2] EXPLICIT
              a9 0c                            --   tNoAnswerSpecificInfo [9], 3 + 9
                 9f 32 00                      --     callForwarded [50] NULL
                 9f 34 06 04 10 51 55 10 20    --     forwardingDestinationNumber [52]
           a3 03 81 01 02
           a4 03 80 01 00
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "9")
        .present("camel.callForwarded_element")
        .hex("camel.forwardingDestinationNumber", "041051551020");
}

#[test]
fn event_report_terminating_answer() {
    let Some(d) = erb(
        &report(
            EventTypeBcsm::TAnswer,
            EventSpecificInformationBcsm::TAnswerSpecificInfo(AnswerSpecificInfo {
                or_call: Some(()),
                ext_basic_service_code2: Some(ExtBasicServiceCode::ExtBearerService(
                    vec![0x1f].into(),
                )),
                ..Default::default()
            }),
            LEG2,
            MiscCallInfo::notification(),
        ),
        "
        30 1a                                  -- 3 + 13 + 5 + 5 = 26
           80 01 0f                            -- tAnswer(15)
           a2 0b                               -- [2] EXPLICIT
              aa 09                            --   tAnswerSpecificInfo [10], 3 + 6
                 9f 33 00                      --     or-Call [51] NULL
                 bf 37 03 82 01 1f             --     ext-basicServiceCode2 [55] EXPLICIT
                                               --       { ext-BearerService [2] }
           a3 03 81 01 02
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "10")
        .present("camel.or_Call_element")
        .show("camel.ext_basicServiceCode2", "2")
        .show("gsm_map.ext_BearerService", "31");
}

#[test]
fn event_report_mid_call_digits() {
    let Some(d) = erb(
        &report(
            EventTypeBcsm::OMidCall,
            EventSpecificInformationBcsm::OMidCallSpecificInfo(MidCallSpecificInfo {
                mid_call_events: Some(MidCallEvents::DtmfDigitsCompleted(
                    vector("00 21 43").into(),
                )),
            }),
            LEG1,
            MiscCallInfo::notification(),
        ),
        "
        30 18                                  -- 3 + 11 + 5 + 5 = 24
           80 01 08                            -- oMidCall(8)
           a2 09                               -- [2] EXPLICIT
              a6 07                            --   oMidCallSpecificInfo [6]
                 a1 05                         --     midCallEvents [1] EXPLICIT (a CHOICE)
                    83 03 00 21 43             --       dTMFDigitsCompleted [3] Digits
           a3 03 81 01 01
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "6")
        .show("camel.omidCallEvents", "3")
        .hex("camel.dTMFDigitsCompleted", "002143");

    let Some(d) = erb(
        &report(
            EventTypeBcsm::TMidCall,
            EventSpecificInformationBcsm::TMidCallSpecificInfo(MidCallSpecificInfo {
                mid_call_events: Some(MidCallEvents::DtmfDigitsTimeOut(vector("00 21").into())),
            }),
            LEG2,
            MiscCallInfo::notification(),
        ),
        "
        30 17                                  -- 3 + 10 + 5 + 5 = 23
           80 01 10                            -- tMidCall(16)
           a2 08                               -- [2] EXPLICIT
              ab 06                            --   tMidCallSpecificInfo [11]
                 a1 04                         --     midCallEvents [1] EXPLICIT
                    84 02 00 21                --       dTMFDigitsTimeOut [4] Digits
           a3 03 81 01 02
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "11")
        .show("camel.tmidCallEvents", "4")
        .hex("camel.dTMFDigitsTimeOut", "0021");
}

#[test]
fn event_report_alerting_carries_location_information() {
    let location = LocationInformation {
        age_of_location_information: Some(0),
        ..Default::default()
    };
    let Some(d) = erb(
        &report(
            EventTypeBcsm::CallAccepted,
            EventSpecificInformationBcsm::CallAcceptedSpecificInfo(AlertingSpecificInfo {
                location_information: Some(location.clone()),
            }),
            LEG2,
            MiscCallInfo::notification(),
        ),
        "
        30 17                                  -- 3 + 10 + 5 + 5 = 23
           80 01 1b                            -- callAccepted(27)
           a2 08                               -- [2] EXPLICIT
              b4 06                            --   callAcceptedSpecificInfo [20]
                 bf 32 03                      --     locationInformation [50]
                    02 01 00                   --       ageOfLocationInformation 0
           a3 03 81 01 02
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "20")
        .present("camel.locationInformation_element")
        .show("gsm_map.ms.ageOfLocationInformation", "0");

    let Some(d) = erb(
        &report(
            EventTypeBcsm::OTermSeized,
            EventSpecificInformationBcsm::OTermSeizedSpecificInfo(AlertingSpecificInfo {
                location_information: Some(location),
            }),
            LEG2,
            MiscCallInfo::notification(),
        ),
        "
        30 17
           80 01 13                            -- oTermSeized(19)
           a2 08
              ad 06                            --   oTermSeizedSpecificInfo [13]
                 bf 32 03 02 01 00
           a3 03 81 01 02
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "13")
        .show("gsm_map.ms.ageOfLocationInformation", "0");
}

#[test]
fn event_report_abandon() {
    let Some(d) = erb(
        &report(
            EventTypeBcsm::OAbandon,
            EventSpecificInformationBcsm::OAbandonSpecificInfo(OAbandonSpecificInfo {
                route_not_permitted: Some(()),
            }),
            LEG1,
            MiscCallInfo::notification(),
        ),
        "
        30 14                                  -- 3 + 7 + 5 + 5 = 20
           80 01 0a                            -- oAbandon(10)
           a2 05                               -- [2] EXPLICIT
              b5 03                            --   oAbandonSpecificInfo [21]
                 9f 32 00                      --     routeNotPermitted [50] NULL
           a3 03 81 01 01
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "21")
        .present("camel.routeNotPermitted_element");
}

#[test]
fn event_report_change_of_position() {
    let info = ChangeOfPositionSpecificInfo {
        location_information: None,
        met_dp_criteria_list: Some(vec![
            MetDpCriterion::EnteringCellGlobalId(vector("00 f1 10 00 01 00 03").into()),
            MetDpCriterion::InterMscHandOver(()),
        ]),
    };
    let Some(d) = erb(
        &report(
            EventTypeBcsm::OChangeOfPosition,
            EventSpecificInformationBcsm::OChangeOfPositionSpecificInfo(info.clone()),
            LEG1,
            MiscCallInfo::notification(),
        ),
        "
        30 20                                  -- 3 + 19 + 5 + 5 = 32
           80 01 32                            -- oChangeOfPosition(50)
           a2 11                               -- [2] EXPLICIT
              bf 32 0e                         --   oChangeOfPositionSpecificInfo [50]
                 bf 33 0b                      --     metDPCriteriaList [51]
                    80 07 00 f1 10 00 01 00 03 --       enteringCellGlobalId [0]
                    89 00                      --       inter-MSCHandOver [9] NULL
           a3 03 81 01 01
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "50")
        .show("camel.metDPCriteriaList", "2")
        .hex("camel.enteringCellGlobalId", "00f11000010003")
        .present("camel.inter_MSCHandOver_element");

    let Some(d) = erb(
        &report(
            EventTypeBcsm::TChangeOfPosition,
            EventSpecificInformationBcsm::TChangeOfPositionSpecificInfo(info),
            LEG2,
            MiscCallInfo::notification(),
        ),
        "
        30 20
           80 01 33                            -- tChangeOfPosition(51)
           a2 11
              bf 33 0e                         --   tChangeOfPositionSpecificInfo [51]
                 bf 33 0b 80 07 00 f1 10 00 01 00 03 89 00
           a3 03 81 01 02
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "51")
        .hex("camel.enteringCellGlobalId", "00f11000010003");
}

#[test]
fn event_report_service_change() {
    let Some(d) = erb(
        &report(
            EventTypeBcsm::OServiceChange,
            EventSpecificInformationBcsm::DpSpecificInfoAlt(DpSpecificInfoAlt {
                o_service_change_specific_info: Some(ServiceChangeSpecificInfo {
                    ext_basic_service_code: Some(ExtBasicServiceCode::ExtTeleservice(
                        vec![0x11].into(),
                    )),
                    initiator_of_service_change: Some(InitiatorOfServiceChange::BSide),
                    nature_of_service_change: Some(NatureOfServiceChange::NetworkInitiated),
                }),
                ..Default::default()
            }),
            LEG1,
            MiscCallInfo::notification(),
        ),
        "
        30 1f                                  -- 3 + 18 + 5 + 5 = 31
           80 01 34                            -- oServiceChange(52)
           a2 10                               -- [2] EXPLICIT
              bf 34 0d                         --   dpSpecificInfoAlt [52]
                 a0 0b                         --     oServiceChangeSpecificInfo [0]
                    a0 03 83 01 11             --       ext-basicServiceCode [0] EXPLICIT
                    81 01 01                   --       initiatorOfServiceChange b-side(1)
                    82 01 01                   --       natureOfServiceChange networkInitiated(1)
           a3 03 81 01 01
           a4 03 80 01 01
        ",
    ) else {
        return;
    };
    d.show("camel.eventSpecificInformationBCSM", "52")
        .present("camel.oServiceChangeSpecificInfo_element")
        .show("gsm_map.ext_Teleservice", "17")
        .show("camel.initiatorOfServiceChange", "1")
        .show("camel.natureOfServiceChange", "1");
}

#[test]
fn event_report_collected_info_is_pinned_by_bytes_only() {
    // collectedInfoSpecificInfo [2] of DpSpecificInfoAlt is in TS 29.078
    // V18.0.0 but not in the Release 7 module Wireshark 4.6 dissects with, so
    // there is no independent decoder for this one: known-answer only.
    known_answer(
        &report(
            EventTypeBcsm::CollectedInfo,
            EventSpecificInformationBcsm::DpSpecificInfoAlt(DpSpecificInfoAlt {
                collected_info_specific_info: Some(CollectedInfoSpecificInfo {
                    called_party_number: Some(vector("04 10 51 55 10 20").into()),
                }),
                ..Default::default()
            }),
            LEG1,
            MiscCallInfo::request(),
        ),
        "
        30 1c                                  -- 3 + 15 + 5 + 5 = 28
           80 01 02                            -- collectedInfo(2)
           a2 0d                               -- [2] EXPLICIT
              bf 34 0a                         --   dpSpecificInfoAlt [52]
                 a2 08                         --     collectedInfoSpecificInfo [2]
                    80 06 04 10 51 55 10 20    --       calledPartyNumber [0]
           a3 03 81 01 01
           a4 03 80 01 00
        ",
    );
}

#[test]
fn event_report_rejects_the_tags_this_crate_used_to_emit() {
    // Before 2.0.0: legID as primitive [2] and miscCallInfo as primitive [3].
    // [2] is eventSpecificInformationBCSM and [3] is the explicit legID.
    let old = vector("30 0b 80 01 07 82 01 02 83 03 80 01 01");
    assert!(gsm_cap::decode::<EventReportBcsmArg>(&old).is_err());
}

#[test]
fn event_report_with_an_unreadable_leg_is_an_error_not_a_missing_leg() {
    // legID [3] is ReceivingSideID, whose only alternative is [1]. A peer that
    // puts sendingSideID [0] there sent something this type cannot hold.
    // rasn alone answers Ok with leg_id None, having consumed the member.
    let wrong_alternative = vector("30 08 80 01 07 a3 03 80 01 02");
    assert!(
        rasn::ber::decode::<EventReportBcsmArg>(&wrong_alternative)
            .is_ok_and(|arg| arg.leg_id.is_none()),
        "the upstream behaviour this crate guards against has changed, revisit src/strict.rs"
    );
    let error = gsm_cap::decode::<EventReportBcsmArg>(&wrong_alternative).unwrap_err();
    assert!(error.to_string().contains("[3]"), "{error}");

    // Same for an event-specific information alternative that does not exist.
    let unknown_alternative = vector("30 0a 80 01 07 a2 05 bf 63 02 80 00");
    assert!(gsm_cap::decode::<EventReportBcsmArg>(&unknown_alternative).is_err());
}

#[test]
fn event_report_decodes_what_a_peer_may_send_differently() {
    // BER leaves the sender some freedom the decoder has to absorb: a long
    // length form where a short one would do, and the indefinite form for
    // constructed values. Same oDisconnect report as above.
    //   30 81 15 ...                 long-form length
    //   a2 80 a7 80 80 02 80 90 00 00 00 00   indefinite lengths, end-of-contents
    let long_form =
        vector("30 81 15 80 01 09 a2 06 a7 04 80 02 80 90 a3 03 81 01 01 a4 03 80 01 00");
    let indefinite = vector(
        "30 80 80 01 09 a2 80 a7 80 80 02 80 90 00 00 00 00 a3 03 81 01 01 a4 03 80 01 00 00 00",
    );
    let expected = report(
        EventTypeBcsm::ODisconnect,
        EventSpecificInformationBcsm::ODisconnectSpecificInfo(CauseSpecificInfo {
            cause: Some(vec![0x80, 0x90].into()),
        }),
        LEG1,
        MiscCallInfo::request(),
    );
    assert_eq!(
        gsm_cap::decode::<EventReportBcsmArg>(&long_form).unwrap(),
        expected
    );
    assert_eq!(
        gsm_cap::decode::<EventReportBcsmArg>(&indefinite).unwrap(),
        expected
    );
}
