//! Operation codes, against 3GPP TS 29.078 V18.0.0 clause 5.3 and against the
//! names Wireshark's CAMEL dissector gives the same values.

mod common;

use common::{dissect_unchecked, Carrier};
use gsm_cap::op_codes;

/// `(constant, value in clause 5.3, operation name in clause 5.3)`.
const TABLE: &[(i64, i64, &str)] = &[
    (op_codes::INITIAL_DP, 0, "initialDP"),
    (op_codes::CONNECT_TO_RESOURCE, 19, "connectToResource"),
    (op_codes::CONNECT, 20, "connect"),
    (op_codes::RELEASE_CALL, 22, "releaseCall"),
    (
        op_codes::REQUEST_REPORT_BCSM_EVENT,
        23,
        "requestReportBCSMEvent",
    ),
    (op_codes::EVENT_REPORT_BCSM, 24, "eventReportBCSM"),
    (op_codes::CONTINUE, 31, "continue"),
    (
        op_codes::FURNISH_CHARGING_INFORMATION,
        34,
        "furnishChargingInformation",
    ),
    (op_codes::APPLY_CHARGING, 35, "applyCharging"),
    (op_codes::APPLY_CHARGING_REPORT, 36, "applyChargingReport"),
    (op_codes::PLAY_ANNOUNCEMENT, 47, "playAnnouncement"),
    (
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        48,
        "promptAndCollectUserInformation",
    ),
    (
        op_codes::SPECIALIZED_RESOURCE_REPORT,
        49,
        "specializedResourceReport",
    ),
    (op_codes::CANCEL, 53, "cancel"),
    (op_codes::ACTIVITY_TEST, 55, "activityTest"),
    (op_codes::INITIAL_DP_SMS, 60, "initialDPSMS"),
    (op_codes::CONNECT_SMS, 62, "connectSMS"),
    (
        op_codes::REQUEST_REPORT_SMS_EVENT,
        63,
        "requestReportSMSEvent",
    ),
    (op_codes::EVENT_REPORT_SMS, 64, "eventReportSMS"),
    (op_codes::CONTINUE_SMS, 65, "continueSMS"),
    (op_codes::RELEASE_SMS, 66, "releaseSMS"),
];

#[test]
fn every_code_matches_the_specification() {
    for &(constant, value, name) in TABLE {
        assert_eq!(constant, value, "{name}");
        assert_eq!(op_codes::operation_name(constant), Some(name));
    }
}

#[test]
fn codes_this_crate_does_not_model_have_no_name() {
    // 61 furnishChargingInformationSMS and 67 resetTimerSMS exist in the
    // specification but not here; 61 used to be reported as connectSMS.
    assert_eq!(op_codes::operation_name(61), None);
    assert_eq!(op_codes::operation_name(67), None);
    assert_eq!(op_codes::operation_name(999), None);
}

#[test]
fn wireshark_gives_every_code_the_same_name() {
    for &(constant, _, name) in TABLE {
        // No argument is sent, so the frame may be incomplete for operations
        // that need one. Only the operation code line is read here.
        let Some(d) = dissect_unchecked(constant, None, Carrier::Continue) else {
            return;
        };
        let label = &d
            .fields
            .iter()
            .find(|f| f.name == "camel.local")
            .expect("operation code field")
            .showname;
        assert_eq!(label, &format!("local: {name} ({constant})"));
    }
}
