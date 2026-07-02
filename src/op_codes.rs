//! CAP operation codes (local operation values used in TCAP Invoke components),
//! 3GPP TS 29.078.

/// Call-control and specialised-resource operations.
pub const INITIAL_DP: i64 = 0;
pub const CONNECT_TO_RESOURCE: i64 = 19;
pub const CONNECT: i64 = 20;
pub const RELEASE_CALL: i64 = 22;
pub const REQUEST_REPORT_BCSM_EVENT: i64 = 23;
pub const EVENT_REPORT_BCSM: i64 = 24;
pub const CONTINUE: i64 = 31;
pub const FURNISH_CHARGING_INFORMATION: i64 = 34;
pub const APPLY_CHARGING: i64 = 35;
pub const APPLY_CHARGING_REPORT: i64 = 36;
pub const PLAY_ANNOUNCEMENT: i64 = 47;
pub const PROMPT_AND_COLLECT_USER_INFORMATION: i64 = 48;
pub const SPECIALIZED_RESOURCE_REPORT: i64 = 49;
pub const CANCEL: i64 = 53;
pub const ACTIVITY_TEST: i64 = 55;

/// CAMEL-for-SMS operations (CAP v3+).
pub const INITIAL_DP_SMS: i64 = 60;
pub const CONNECT_SMS: i64 = 61;
pub const RELEASE_SMS: i64 = 62;
pub const REQUEST_REPORT_SMS_EVENT: i64 = 63;
pub const EVENT_REPORT_SMS: i64 = 64;
pub const CONTINUE_SMS: i64 = 65;

/// The name of a well-known CAP operation code, if any.
pub fn operation_name(code: i64) -> Option<&'static str> {
    Some(match code {
        INITIAL_DP => "initialDP",
        CONNECT_TO_RESOURCE => "connectToResource",
        CONNECT => "connect",
        RELEASE_CALL => "releaseCall",
        REQUEST_REPORT_BCSM_EVENT => "requestReportBCSMEvent",
        EVENT_REPORT_BCSM => "eventReportBCSM",
        CONTINUE => "continue",
        FURNISH_CHARGING_INFORMATION => "furnishChargingInformation",
        APPLY_CHARGING => "applyCharging",
        APPLY_CHARGING_REPORT => "applyChargingReport",
        PLAY_ANNOUNCEMENT => "playAnnouncement",
        PROMPT_AND_COLLECT_USER_INFORMATION => "promptAndCollectUserInformation",
        SPECIALIZED_RESOURCE_REPORT => "specializedResourceReport",
        CANCEL => "cancel",
        ACTIVITY_TEST => "activityTest",
        INITIAL_DP_SMS => "initialDPSMS",
        CONNECT_SMS => "connectSMS",
        RELEASE_SMS => "releaseSMS",
        REQUEST_REPORT_SMS_EVENT => "requestReportSMSEvent",
        EVENT_REPORT_SMS => "eventReportSMS",
        CONTINUE_SMS => "continueSMS",
        _ => return None,
    })
}
