//! ConnectToResource (op 19), PlayAnnouncement (op 47),
//! PromptAndCollectUserInformation (op 48) with its result, and Cancel
//! (op 53): 3GPP TS 29.078 V18.0.0 clauses 5.1, 6.1.1 and 6.2.
//!
//! Vectors are assembled by hand from the ASN.1 (see `tests/bcsm_events.rs`
//! for the tag octet rules).
//!
//! Wireshark does not look at the primitive / constructed bit of an explicit
//! wrapper, so it also accepts `80` where `A0` is required. The byte vectors
//! are what pins that bit here.

mod common;

use common::{dissect, known_answer, vector, Carrier};
use gsm_cap::op_codes;
use gsm_cap::operations::{
    CancelArg, ConnectToResourceArg, PlayAnnouncementArg, PromptAndCollectUserInformationArg,
    PromptAndCollectUserInformationRes,
};
use gsm_cap::types::{
    BothwayThroughConnectionInd, CallSegmentToCancel, CollectedDigits, CollectedInfo,
    ErrorTreatment, InbandInfo, InformationToSend, MessageId, MessageIdText, ResourceAddress,
    ServiceInteractionIndicatorsTwo, Tone, VariableMessage, VariablePart,
};
use rasn::types::{Ia5String, Integer};

// ── ConnectToResource ───────────────────────────────────────────────────────

#[test]
fn connect_to_resource_with_a_co_located_srf() {
    let ber = known_answer(
        &ConnectToResourceArg::new(ResourceAddress::None(())),
        "30 02 83 00                           -- resourceAddress: none [3] NULL",
    );
    let Some(d) = dissect(op_codes::CONNECT_TO_RESOURCE, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.present("camel.ConnectToResourceArg_element")
        .show("camel.resourceAddress", "3")
        .present("camel.none_element");
}

#[test]
fn connect_to_resource_with_an_address() {
    let arg = ConnectToResourceArg {
        service_interaction_indicators_two: Some(ServiceInteractionIndicatorsTwo {
            bothway_through_connection_ind: Some(BothwayThroughConnectionInd::BothwayPathRequired),
            ..Default::default()
        }),
        call_segment_id: Some(1),
        ..ConnectToResourceArg::new(ResourceAddress::IpRoutingAddress(
            vector("04 10 51 55 10 30").into(),
        ))
    };
    let ber = known_answer(
        &arg,
        "
        30 11                                  -- 8 + 5 + 4 = 17
           80 06 04 10 51 55 10 30             -- ipRoutingAddress [0], the CHOICE is untagged
           a7 03 82 01 00                      -- serviceInteractionIndicatorsTwo [7]
           9f 32 01 01                         -- callSegmentID [50] 1
        ",
    );
    let Some(d) = dissect(op_codes::CONNECT_TO_RESOURCE, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.resourceAddress", "0")
        .hex("camel.ipRoutingAddress", "041051551030")
        .present("camel.serviceInteractionIndicatorsTwo_element")
        .show("camel.bothwayThroughConnectionInd", "0")
        .show("camel.callSegmentID", "1");
}

// ── PlayAnnouncement ────────────────────────────────────────────────────────

#[test]
fn play_announcement_elementary_message() {
    let arg = PlayAnnouncementArg {
        disconnect_from_ip_forbidden: Some(false),
        request_announcement_complete_notification: Some(true),
        call_segment_id: Some(1),
        request_announcement_started_notification: Some(true),
        ..PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo {
            number_of_repetitions: Some(2),
            duration: Some(10),
            interval: Some(1),
            ..InbandInfo::new(MessageId::ElementaryMessageId(7))
        }))
    };
    let ber = known_answer(
        &arg,
        "
        30 1f                                  -- 18 + 3 + 3 + 3 + 4 = 31
           a0 10                               -- informationToSend [0] EXPLICIT, constructed
              a0 0e                            --   inbandInfo [0], 5 + 3 + 3 + 3
                 a0 03 80 01 07                --     messageID [0] EXPLICIT
                                               --       { elementaryMessageID [0] 7 }
                 81 01 02                      --     numberOfRepetitions 2
                 82 01 0a                      --     duration 10 s
                 83 01 01                      --     interval 1 s
           81 01 00                            -- disconnectFromIPForbidden FALSE
           82 01 ff                            -- requestAnnouncementCompleteNotification TRUE
           85 01 01                            -- callSegmentID [5] 1
           9f 33 01 ff                         -- requestAnnouncementStartedNotification [51] TRUE
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.informationToSend", "0")
        .present("camel.inbandInfo_element")
        .show("camel.messageID", "0")
        .show("camel.elementaryMessageID", "7")
        .show("camel.numberOfRepetitions", "2")
        .show("camel.inbandInfoDuration", "10")
        .show("camel.interval", "1")
        .show("camel.disconnectFromIPForbidden", "False")
        .show("camel.requestAnnouncementCompleteNotification", "True")
        .show("camel.callSegmentID", "1")
        .show("camel.requestAnnouncementStartedNotification", "True");
}

#[test]
fn play_announcement_tone() {
    let arg = PlayAnnouncementArg::new(InformationToSend::Tone(Tone {
        tone_id: 1,
        duration: Some(5),
    }));
    let ber = known_answer(
        &arg,
        "
        30 0a
           a0 08                               -- informationToSend [0] EXPLICIT
              a1 06 80 01 01 81 01 05          --   tone [1] { toneID 1, duration 5 s }
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.informationToSend", "1")
        .present("camel.tone_element")
        .show("camel.toneID", "1")
        .show("camel.toneDuration", "5")
        // Both BOOLEANs are absent, so their DEFAULT TRUE applies.
        .absent("camel.disconnectFromIPForbidden")
        .absent("camel.requestAnnouncementCompleteNotification");
}

#[test]
fn play_announcement_variable_message() {
    let arg = PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo::new(
        MessageId::VariableMessage(VariableMessage {
            elementary_message_id: 5,
            variable_parts: vec![
                VariablePart::Integer(42),
                VariablePart::Number(vector("00 21 43").into()),
                VariablePart::Time(vector("12 34").into()),
                VariablePart::Date(vector("20 26 10 08").into()),
                VariablePart::Price(vector("00 00 12 34").into()),
            ],
        }),
    )));
    let ber = known_answer(
        &arg,
        "
        30 25
           a0 23                               -- informationToSend [0] EXPLICIT
              a0 21                            --   inbandInfo [0]
                 a0 1f                         --     messageID [0] EXPLICIT
                    be 1d                      --       variableMessage [30], 3 + 26
                       80 01 05                --         elementaryMessageID 5
                       a1 18                   --         variableParts [1], 3 + 5 + 4 + 6 + 6
                          80 01 2a             --           integer [0] 42
                          81 03 00 21 43       --           number [1]
                          82 02 12 34          --           time [2] 12:34
                          83 04 20 26 10 08    --           date [3] 2026-10-08
                          84 04 00 00 12 34    --           price [4]
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.messageID", "30")
        .present("camel.variableMessage_element")
        .show("camel.elementaryMessageID", "5")
        .show("camel.variableParts", "5")
        .show_all("camel.VariablePart", &["0", "1", "2", "3", "4"])
        .show("camel.integer", "42")
        .hex("camel.number", "002143")
        .hex("camel.time", "1234")
        .hex("camel.date", "20261008")
        .hex("camel.price", "00001234");
}

#[test]
fn play_announcement_text_and_message_list() {
    let text = PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo::new(
        MessageId::Text(MessageIdText {
            message_content: Ia5String::try_from("hi").unwrap(),
            attributes: Some(vector("00 01").into()),
        }),
    )));
    let ber = known_answer(
        &text,
        "
        30 10
           a0 0e                               -- informationToSend [0] EXPLICIT
              a0 0c                            --   inbandInfo [0]
                 a0 0a                         --     messageID [0] EXPLICIT
                    a1 08                      --       text [1]
                       80 02 68 69             --         messageContent [0] IA5String \"hi\"
                       81 02 00 01             --         attributes [1]
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.messageID", "1")
        .present("camel.text_element")
        .show("camel.messageContent", "hi")
        .hex("camel.attributes", "0001");

    let list = PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo::new(
        MessageId::ElementaryMessageIds(vec![1, 2]),
    )));
    let ber = known_answer(
        &list,
        "
        30 0e
           a0 0c                               -- informationToSend [0] EXPLICIT
              a0 0a                            --   inbandInfo [0]
                 a0 08                         --     messageID [0] EXPLICIT
                    bd 06 02 01 01 02 01 02    --       elementaryMessageIDs [29] SEQUENCE OF INTEGER
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.messageID", "29")
        .show("camel.elementaryMessageIDs", "2")
        .show_all("camel.Integer4", &["1", "2"]);
}

// ── PromptAndCollectUserInformation ─────────────────────────────────────────

#[test]
fn prompt_and_collect_with_every_member() {
    let arg = PromptAndCollectUserInformationArg {
        disconnect_from_ip_forbidden: Some(false),
        information_to_send: Some(InformationToSend::Tone(Tone {
            tone_id: 1,
            duration: Some(5),
        })),
        call_segment_id: Some(1),
        request_announcement_started_notification: Some(true),
        ..PromptAndCollectUserInformationArg::new(CollectedInfo::CollectedDigits(CollectedDigits {
            minimum_nb_of_digits: Some(1),
            end_of_reply_digit: Some(vec![0x0c].into()),
            cancel_digit: Some(vec![0x0b].into()),
            start_digit: Some(vec![0x00].into()),
            first_digit_time_out: Some(5),
            inter_digit_time_out: Some(3),
            error_treatment: Some(ErrorTreatment::RepeatPrompt),
            interruptable_ann_ind: Some(false),
            voice_information: Some(true),
            voice_back: Some(true),
            ..CollectedDigits::new(4)
        }))
    };
    let ber = known_answer(
        &arg,
        "
        30 39                                  -- 37 + 3 + 10 + 3 + 4 = 57
           a0 23                               -- collectedInfo [0] EXPLICIT, constructed
              a0 21                            --   collectedDigits [0], 11 members of 3 octets
                 80 01 01                      --     minimumNbOfDigits 1
                 81 01 04                      --     maximumNbOfDigits 4
                 82 01 0c                      --     endOfReplyDigit '#'
                 83 01 0b                      --     cancelDigit '*'
                 84 01 00                      --     startDigit '0'
                 85 01 05                      --     firstDigitTimeOut 5 s
                 86 01 03                      --     interDigitTimeOut 3 s
                 87 01 02                      --     errorTreatment repeatPrompt(2)
                 88 01 00                      --     interruptableAnnInd FALSE
                 89 01 ff                      --     voiceInformation TRUE
                 8a 01 ff                      --     voiceBack TRUE
           81 01 00                            -- disconnectFromIPForbidden FALSE
           a2 08 a1 06 80 01 01 81 01 05       -- informationToSend [2] EXPLICIT { tone [1] }
           84 01 01                            -- callSegmentID [4] 1
           9f 33 01 ff                         -- requestAnnouncementStartedNotification [51] TRUE
        ",
    );
    let Some(d) = dissect(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("camel.collectedInfo", "0")
        .present("camel.collectedDigits_element")
        .show("camel.minimumNbOfDigits", "1")
        .show("camel.maximumNbOfDigits", "4")
        .hex("camel.endOfReplyDigit", "0c")
        .hex("camel.cancelDigit", "0b")
        .hex("camel.startDigit", "00")
        .show("camel.firstDigitTimeOut", "5")
        .show("camel.interDigitTimeOut", "3")
        .show("camel.errorTreatment", "2")
        .show("camel.interruptableAnnInd", "False")
        .show("camel.voiceInformation", "True")
        .show("camel.voiceBack", "True")
        .show("camel.disconnectFromIPForbidden", "False")
        .show("camel.informationToSend", "1")
        .show("camel.toneID", "1")
        .show("camel.toneDuration", "5")
        .show("camel.callSegmentID", "1")
        .show("camel.requestAnnouncementStartedNotification", "True");
}

#[test]
fn prompt_and_collect_result_carries_the_digits() {
    // ReceivedInformationArg ::= CHOICE { digitsResponse [0] Digits }, sent as
    // the result of the operation.
    let ber = known_answer(
        &PromptAndCollectUserInformationRes::DigitsResponse(vector("00 21 43").into()),
        "80 03 00 21 43",
    );
    let Some(d) = dissect(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&ber),
        Carrier::Result,
    ) else {
        return;
    };
    d.present("camel.returnResult_element")
        .show("camel.ReceivedInformationArg", "0")
        .hex("camel.digitsResponse", "002143");
}

#[test]
fn explicit_wrappers_are_always_emitted_constructed() {
    // What this crate emitted before 2.0.0: the CHOICE-typed members as
    // primitive `80`, with the inner encoding as opaque content. X.690 8.14.2
    // requires the constructed form for an explicit tag.
    //
    // rasn itself does not check the bit on an explicit wrapper, so these
    // decode; what matters is that they are never produced. The encodings
    // above pin `A0`.
    let lenient: PlayAnnouncementArg =
        gsm_cap::decode(&vector("30 0a 80 08 a1 06 80 01 01 81 01 05")).unwrap();
    assert_eq!(
        gsm_cap::encode(&lenient).unwrap(),
        vector("30 0a a0 08 a1 06 80 01 01 81 01 05")
    );
}

// ── Cancel ──────────────────────────────────────────────────────────────────

#[test]
fn cancel_alternatives() {
    let ber = known_answer(
        &CancelArg::InvokeId(Integer::from(5)),
        "80 01 05                              -- invokeID [0] 5",
    );
    if let Some(d) = dissect(op_codes::CANCEL, Some(&ber), Carrier::Continue) {
        d.show("camel.CancelArg", "0").show("camel.invokeID", "5");
    }

    let ber = known_answer(
        &CancelArg::AllRequests(()),
        "81 00                                 -- allRequests [1] NULL",
    );
    if let Some(d) = dissect(op_codes::CANCEL, Some(&ber), Carrier::Continue) {
        d.show("camel.CancelArg", "1")
            .present("camel.allRequests_element");
    }

    let ber = known_answer(
        &CancelArg::CallSegmentToCancel(CallSegmentToCancel {
            invoke_id: Some(5),
            call_segment_id: Some(1),
        }),
        "
        a2 06                                  -- callSegmentToCancel [2]
           80 01 05                            --   invokeID [0] 5
           81 01 01                            --   callSegmentID [1] 1
        ",
    );
    if let Some(d) = dissect(op_codes::CANCEL, Some(&ber), Carrier::Continue) {
        d.show("camel.CancelArg", "2")
            .present("camel.callSegmentToCancel_element")
            .show("camel.invokeID", "5")
            .show("camel.callSegmentID", "1");
    }
}
