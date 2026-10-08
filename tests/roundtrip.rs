//! BER round-trip tests for CAP operations: what this crate encodes, it
//! decodes back to the same value.
//!
//! A round-trip says nothing about whether the bytes are the ones the
//! specification asks for (a mistake shared by the encoder and the decoder
//! passes it). That is what the hand-assembled vectors and the Wireshark
//! dissections in the sibling test files are for. All values are synthetic.

use rasn::types::Integer;

use gsm_cap::operations::{
    ApplyChargingArg, ConnectArg, EventReportBcsmArg, InitialDpArg, InitialDpSmsArg,
    ReleaseCallArg, RequestReportBcsmEventArg,
};
use gsm_cap::types::{
    BcsmEvent, EventTypeBcsm, EventTypeSms, LegId, MonitorMode, ReceivingSideId, SendingSideId,
    LEG1, LEG2,
};

fn round_trip<T: rasn::Decode + rasn::Encode + std::fmt::Debug + PartialEq>(v: &T) {
    let ber = gsm_cap::encode(v).expect("encode");
    let back: T = gsm_cap::decode(&ber).expect("decode");
    assert_eq!(v, &back);
}

#[test]
fn initial_dp_round_trip() {
    round_trip(&InitialDpArg {
        called_party_number: Some(vec![0x03, 0x55, 0x01, 0x00].into()),
        calling_party_number: Some(vec![0x03, 0x55, 0x01, 0x99].into()),
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        imsi: Some(vec![0x00, 0x10, 0x19, 0x00, 0x00].into()),
        call_reference_number: Some(vec![0xDE, 0xAD].into()),
        msc_address: Some(vec![0x91, 0x55, 0x01].into()),
        ..InitialDpArg::new(Integer::from(42))
    });
}

#[test]
fn connect_round_trip() {
    round_trip(&ConnectArg::new(vec![0x03, 0x55, 0x01, 0x23].into()));
}

#[test]
fn release_call_round_trip() {
    round_trip(&ReleaseCallArg(vec![0x90, 0x03].into()));
}

#[test]
fn request_report_bcsm_round_trip() {
    round_trip(&RequestReportBcsmEventArg::new(vec![
        BcsmEvent::new(EventTypeBcsm::OAnswer, MonitorMode::NotifyAndContinue),
        BcsmEvent {
            leg_id: Some(LegId::sending(LEG1)),
            ..BcsmEvent::new(EventTypeBcsm::ODisconnect, MonitorMode::Interrupted)
        },
    ]));
}

#[test]
fn event_report_bcsm_round_trip() {
    round_trip(&EventReportBcsmArg {
        leg_id: Some(ReceivingSideId::leg(LEG2)),
        ..EventReportBcsmArg::new(EventTypeBcsm::OAnswer)
    });
}

#[test]
fn apply_charging_round_trip() {
    round_trip(&ApplyChargingArg {
        party_to_charge: Some(SendingSideId::leg(LEG1)),
        ..ApplyChargingArg::new(vec![0xa0, 0x04, 0x80, 0x02, 0x0b, 0xb8].into())
    });
}

#[test]
fn initial_dp_sms_round_trip() {
    round_trip(&InitialDpSmsArg {
        destination_subscriber_number: Some(vec![0x91, 0x55, 0x01].into()),
        calling_party_number: Some(vec![0x91, 0x55, 0x01, 0x88].into()),
        event_type_sms: Some(EventTypeSms::OSmsSubmission),
        smsc_address: Some(vec![0x91, 0x55, 0x01, 0x00].into()),
        ..InitialDpSmsArg::new(Integer::from(7))
    });
}
