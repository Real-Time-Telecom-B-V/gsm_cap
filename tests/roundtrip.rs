//! BER round-trip tests for CAP operations. All values are synthetic — no real
//! subscriber data.

use rasn::types::Integer;

use gsm_cap::op_codes;
use gsm_cap::operations::{
    ApplyChargingArg, ConnectArg, EventReportBcsmArg, InitialDpArg, InitialDpSmsArg,
    ReleaseCallArg, RequestReportBcsmEventArg,
};
use gsm_cap::types::{BcsmEvent, EventTypeBcsm, EventTypeSms, MonitorMode};

fn round_trip<T: rasn::Decode + rasn::Encode + std::fmt::Debug + PartialEq>(v: &T) {
    let ber = gsm_cap::encode(v).expect("encode");
    let back: T = gsm_cap::decode(&ber).expect("decode");
    assert_eq!(v, &back);
}

#[test]
fn initial_dp_round_trip() {
    let idp = InitialDpArg {
        service_key: Integer::from(42),
        called_party_number: Some(vec![0x03, 0x55, 0x01, 0x00].into()), // synthetic
        calling_party_number: Some(vec![0x03, 0x55, 0x01, 0x99].into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: None,
        imsi: Some(vec![0x00, 0x10, 0x19, 0x00, 0x00].into()), // fictional IMSI TBCD
        location_information: None,
        call_reference_number: Some(vec![0xDE, 0xAD].into()),
        msc_address: Some(vec![0x91, 0x55, 0x01].into()),
        called_party_bcd_number: None,
        time_and_timezone: None,
    };
    round_trip(&idp);
}

#[test]
fn connect_round_trip() {
    let c = ConnectArg {
        destination_routing_address: vec![vec![0x03, 0x55, 0x01, 0x23].into()],
        original_called_party_id: None,
        calling_partys_category: None,
        redirecting_party_id: None,
        generic_numbers: None,
    };
    round_trip(&c);
}

#[test]
fn release_call_round_trip() {
    round_trip(&ReleaseCallArg {
        cause: vec![0x90, 0x03].into(),
    });
}

#[test]
fn request_report_bcsm_round_trip() {
    let r = RequestReportBcsmEventArg {
        bcsm_events: vec![
            BcsmEvent {
                event_type_bcsm: EventTypeBcsm::OAnswer,
                monitor_mode: MonitorMode::NotifyAndContinue,
                leg_id: None,
            },
            BcsmEvent {
                event_type_bcsm: EventTypeBcsm::ODisconnect,
                monitor_mode: MonitorMode::Interrupted,
                leg_id: Some(vec![0x01].into()),
            },
        ],
    };
    round_trip(&r);
}

#[test]
fn event_report_bcsm_round_trip() {
    round_trip(&EventReportBcsmArg {
        event_type_bcsm: EventTypeBcsm::OAnswer,
        leg_id: Some(vec![0x02].into()),
        misc_call_info: None,
    });
}

#[test]
fn apply_charging_round_trip() {
    round_trip(&ApplyChargingArg {
        ach_billing_charging_characteristics: vec![0x00, 0x01, 0x02].into(),
        party_to_charge: Some(vec![0x02].into()),
    });
}

#[test]
fn initial_dp_sms_round_trip() {
    let s = InitialDpSmsArg {
        service_key: Integer::from(7),
        destination_subscriber_number: Some(vec![0x91, 0x55, 0x01].into()),
        calling_party_number: Some(vec![0x91, 0x55, 0x01, 0x88].into()),
        event_type_sms: Some(EventTypeSms::OSmsSubmission),
        imsi: None,
        location_information_msc: None,
        smsc_address: Some(vec![0x91, 0x55, 0x01, 0x00].into()),
        time_and_timezone: None,
        tp_short_message_specific_info: None,
        tp_protocol_identifier: None,
        tp_data_coding_scheme: None,
        tp_validity_period: None,
        sms_reference_number: None,
        msc_address: None,
        sgsn_number: None,
        ms_classmark2: None,
    };
    round_trip(&s);
}

#[test]
fn operation_names() {
    assert_eq!(
        op_codes::operation_name(op_codes::INITIAL_DP),
        Some("initialDP")
    );
    assert_eq!(op_codes::operation_name(op_codes::CONNECT), Some("connect"));
    assert_eq!(
        op_codes::operation_name(op_codes::INITIAL_DP_SMS),
        Some("initialDPSMS")
    );
    assert_eq!(op_codes::operation_name(999), None);
}
