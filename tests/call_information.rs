//! EstablishTemporaryConnection (op 17), DisconnectForwardConnection (op 18),
//! ResetTimer (op 33), CallInformationReport (op 44) and
//! CallInformationRequest (op 45): 3GPP TS 29.078 V18.0.0 clause 6.1.1.
//!
//! Vectors are assembled by hand from the ASN.1 (see `tests/bcsm_events.rs`
//! for the tag octet rules). A member of a CHOICE type is EXPLICIT, so the
//! legID [3] members and requestedInformationValue [1] carry a constructed
//! wrapper around the alternative.

mod common;

use common::{dissect, known_answer, vector, Carrier};
use gsm_cap::op_codes;
use gsm_cap::operations::{
    CallInformationReportArg, CallInformationRequestArg, EstablishTemporaryConnectionArg,
    ResetTimerArg,
};
use gsm_cap::types::{
    ReceivingSideId, RequestedInformation, RequestedInformationType, RequestedInformationValue,
    SendingSideId, TimerId, LEG2,
};

// ── EstablishTemporaryConnection ────────────────────────────────────────────

#[test]
fn establish_temporary_connection_to_an_assisting_ip() {
    let arg = EstablishTemporaryConnectionArg {
        original_called_party_id: Some(vector("04 10 51 55 10 24").into()),
        calling_party_number: Some(vector("04 13 51 55 10 10").into()),
        ..EstablishTemporaryConnectionArg::new(vector("00 04 10 51 55 10 30").into())
    };
    let ber = known_answer(
        &arg,
        "
        30 1b                                  -- 9 + 9 + 9 = 27
           80 07 00 04 10 51 55 10 30          -- assistingSSPIPRoutingAddress [0] Digits
           9f 34 06 04 10 51 55 10 24          -- originalCalledPartyID [52]
           9f 35 06 04 13 51 55 10 10          -- callingPartyNumber [53]
        ",
    );
    let Some(d) = dissect(
        op_codes::ESTABLISH_TEMPORARY_CONNECTION,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.present("camel.EstablishTemporaryConnectionArg_element")
        .hex("camel.assistingSSPIPRoutingAddress", "00041051551030")
        .hex("camel.originalCalledPartyID", "041051551024")
        .hex("camel.callingPartyNumber", "041351551010");
}

#[test]
fn establish_temporary_connection_decodes_its_own_bytes() {
    let arg = EstablishTemporaryConnectionArg::new(vector("00 04 10 51 55 10 30").into());
    let ber = known_answer(&arg, "30 09 80 07 00 04 10 51 55 10 30");
    let back: EstablishTemporaryConnectionArg = gsm_cap::decode(&ber).expect("decodes");
    assert_eq!(back, arg);
}

// ── DisconnectForwardConnection ─────────────────────────────────────────────

#[test]
fn disconnect_forward_connection_has_no_argument() {
    let Some(d) = dissect(
        op_codes::DISCONNECT_FORWARD_CONNECTION,
        None,
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("camel.local", "18");
}

// ── ResetTimer ──────────────────────────────────────────────────────────────

#[test]
fn reset_timer_of_tssf_by_default() {
    let ber = known_answer(
        &ResetTimerArg::new(30),
        "30 03 81 01 1e                        -- timervalue [1] 30, timerID left to its DEFAULT tssf",
    );
    let Some(d) = dissect(op_codes::RESET_TIMER, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.present("camel.ResetTimerArg_element")
        .show("camel.timervalue", "30");
}

#[test]
fn reset_timer_naming_tssf() {
    let arg = ResetTimerArg {
        timer_id: Some(TimerId::Tssf),
        call_segment_id: Some(1),
        ..ResetTimerArg::new(120)
    };
    let ber = known_answer(
        &arg,
        "
        30 09
           80 01 00                            -- timerID [0] tssf
           81 01 78                            -- timervalue [1] 120
           83 01 01                            -- callSegmentID [3] 1
        ",
    );
    let Some(d) = dissect(op_codes::RESET_TIMER, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.timerID", "0")
        .show("camel.timervalue", "120")
        .show("camel.callSegmentID", "1");
}

// ── CallInformationRequest / Report ─────────────────────────────────────────

#[test]
fn call_information_request_for_every_item_on_leg_2() {
    let arg = CallInformationRequestArg {
        leg_id: Some(SendingSideId::leg(LEG2)),
        ..CallInformationRequestArg::new(vec![
            RequestedInformationType::CallAttemptElapsedTime,
            RequestedInformationType::CallStopTime,
            RequestedInformationType::CallConnectedElapsedTime,
            RequestedInformationType::ReleaseCause,
        ])
    };
    let ber = known_answer(
        &arg,
        "
        30 13                                  -- 14 + 5 = 19
           a0 0c                               -- requestedInformationTypeList [0]
              0a 01 00                         --   callAttemptElapsedTime
              0a 01 01                         --   callStopTime
              0a 01 02                         --   callConnectedElapsedTime
              0a 01 1e                         --   releaseCause (30)
           a3 03 80 01 02                      -- legID [3] { sendingSideID [0] leg2 }
        ",
    );
    let Some(d) = dissect(
        op_codes::CALL_INFORMATION_REQUEST,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.present("camel.CallInformationRequestArg_element")
        .show_all("camel.RequestedInformationType", &["0", "1", "2", "30"]);
}

#[test]
fn call_information_report_of_connected_time_and_release_cause() {
    let arg = CallInformationReportArg {
        leg_id: Some(ReceivingSideId::leg(LEG2)),
        ..CallInformationReportArg::new(vec![
            RequestedInformation {
                requested_information_type: RequestedInformationType::CallConnectedElapsedTime,
                requested_information_value:
                    RequestedInformationValue::CallConnectedElapsedTimeValue(600),
            },
            RequestedInformation {
                requested_information_type: RequestedInformationType::ReleaseCause,
                requested_information_value: RequestedInformationValue::ReleaseCauseValue(
                    vector("80 90").into(),
                ),
            },
        ])
    };
    let ber = known_answer(
        &arg,
        "
        30 1d                                  -- 24 + 5 = 29
           a0 16                               -- requestedInformationList [0]
              30 09                            --   RequestedInformation
                 80 01 02                      --     type [0] callConnectedElapsedTime
                 a1 04 82 02 02 58             --     value [1] { [2] 600 (100 ms units) }
              30 09
                 80 01 1e                      --     type [0] releaseCause
                 a1 04 9e 02 80 90             --     value [1] { [30] Cause: normal clearing }
           a3 03 81 01 02                      -- legID [3] { receivingSideID [1] leg2 }
        ",
    );
    let back: CallInformationReportArg = gsm_cap::decode(&ber).expect("decodes");
    assert_eq!(back, arg);
    let Some(d) = dissect(
        op_codes::CALL_INFORMATION_REPORT,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.present("camel.CallInformationReportArg_element")
        .show("camel.callConnectedElapsedTimeValue", "600")
        .hex("camel.releaseCauseValue", "8090");
}
