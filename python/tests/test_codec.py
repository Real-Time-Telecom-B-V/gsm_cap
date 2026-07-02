"""Codec parity / round-trip tests for the gsm_cap wheel.

These exercise the same Rust `rasn` BER codec the crate ships, through the Python
surface: each CAP operation argument must ``encode()`` to BER and ``decode()``
back to the same fields. All values are SYNTHETIC — fictional ``+1-555-01xx``
numbers, made-up keys/IMSI; nothing here is captured traffic.
"""

from __future__ import annotations

import pytest

import gsm_cap


def test_operation_codes_and_names() -> None:
    assert gsm_cap.INITIAL_DP == 0
    assert gsm_cap.CONNECT == 20
    assert gsm_cap.RELEASE_CALL == 22
    assert gsm_cap.INITIAL_DP_SMS == 60
    assert gsm_cap.operation_name(gsm_cap.INITIAL_DP) == "initialDP"
    assert gsm_cap.operation_name(gsm_cap.CONNECT) == "connect"
    assert gsm_cap.operation_name(gsm_cap.INITIAL_DP_SMS) == "initialDPSMS"
    assert gsm_cap.operation_name(999) is None


def test_event_type_bcsm_wire_values() -> None:
    # The enum's integer value is the on-wire ASN.1 ENUMERATED encoding.
    assert int(gsm_cap.EventTypeBcsm.CollectedInfo) == 2
    assert int(gsm_cap.EventTypeBcsm.OAnswer) == 7
    assert int(gsm_cap.EventTypeBcsm.TAbandon) == 18


def test_monitor_mode_wire_values() -> None:
    assert int(gsm_cap.MonitorMode.Interrupted) == 0
    assert int(gsm_cap.MonitorMode.NotifyAndContinue) == 1
    assert int(gsm_cap.MonitorMode.Transparent) == 2


def test_event_type_sms_wire_values() -> None:
    assert int(gsm_cap.EventTypeSms.SmsCollectedInfo) == 1
    assert int(gsm_cap.EventTypeSms.OSmsSubmission) == 3
    assert int(gsm_cap.EventTypeSms.TSmsDelivery) == 13


def test_initial_dp_round_trip() -> None:
    idp = gsm_cap.InitialDpArg(
        42,
        called_party_number=bytes([0x03, 0x55, 0x01, 0x23]),
        calling_party_number=bytes([0x03, 0x55, 0x01, 0x99]),
        event_type_bcsm=gsm_cap.EventTypeBcsm.CollectedInfo,
        imsi=bytes([0x00, 0x10, 0x19, 0x00, 0x00]),
        call_reference_number=bytes([0xDE, 0xAD]),
        msc_address=bytes([0x91, 0x55, 0x01]),
    )
    wire = idp.encode()
    assert isinstance(wire, bytes)
    back = gsm_cap.InitialDpArg.decode(wire)
    assert back.service_key == 42
    assert back.called_party_number == bytes([0x03, 0x55, 0x01, 0x23])
    assert back.calling_party_number == bytes([0x03, 0x55, 0x01, 0x99])
    assert back.event_type_bcsm == gsm_cap.EventTypeBcsm.CollectedInfo
    assert back.imsi == bytes([0x00, 0x10, 0x19, 0x00, 0x00])
    assert back.call_reference_number == bytes([0xDE, 0xAD])
    assert back.msc_address == bytes([0x91, 0x55, 0x01])
    # re-encoding reproduces the exact bytes
    assert back.encode() == wire


def test_initial_dp_minimal() -> None:
    idp = gsm_cap.InitialDpArg(1)
    back = gsm_cap.InitialDpArg.decode(idp.encode())
    assert back.service_key == 1
    assert back.called_party_number is None
    assert back.event_type_bcsm is None


def test_connect_round_trip() -> None:
    c = gsm_cap.ConnectArg([bytes([0x03, 0x55, 0x01, 0x23])])
    back = gsm_cap.ConnectArg.decode(c.encode())
    assert back.destination_routing_address == [bytes([0x03, 0x55, 0x01, 0x23])]
    assert back.encode() == c.encode()


def test_connect_multiple_addresses() -> None:
    addrs = [bytes([0x03, 0x55, 0x01, 0x01]), bytes([0x03, 0x55, 0x01, 0x02])]
    c = gsm_cap.ConnectArg(addrs)
    back = gsm_cap.ConnectArg.decode(c.encode())
    assert back.destination_routing_address == addrs


def test_release_call_round_trip() -> None:
    rel = gsm_cap.ReleaseCallArg(bytes([0x90, 0x03]))
    back = gsm_cap.ReleaseCallArg.decode(rel.encode())
    assert back.cause == bytes([0x90, 0x03])


def test_request_report_bcsm_round_trip() -> None:
    r = gsm_cap.RequestReportBcsmEventArg(
        [
            gsm_cap.BcsmEvent(
                gsm_cap.EventTypeBcsm.OAnswer,
                gsm_cap.MonitorMode.NotifyAndContinue,
            ),
            gsm_cap.BcsmEvent(
                gsm_cap.EventTypeBcsm.ODisconnect,
                gsm_cap.MonitorMode.Interrupted,
                leg_id=bytes([0x01]),
            ),
        ]
    )
    back = gsm_cap.RequestReportBcsmEventArg.decode(r.encode())
    assert len(back.bcsm_events) == 2
    assert back.bcsm_events[0].event_type_bcsm == gsm_cap.EventTypeBcsm.OAnswer
    assert back.bcsm_events[0].monitor_mode == gsm_cap.MonitorMode.NotifyAndContinue
    assert back.bcsm_events[1].event_type_bcsm == gsm_cap.EventTypeBcsm.ODisconnect
    assert back.bcsm_events[1].leg_id == bytes([0x01])


def test_event_report_bcsm_round_trip() -> None:
    e = gsm_cap.EventReportBcsmArg(
        gsm_cap.EventTypeBcsm.OAnswer, leg_id=bytes([0x02])
    )
    back = gsm_cap.EventReportBcsmArg.decode(e.encode())
    assert back.event_type_bcsm == gsm_cap.EventTypeBcsm.OAnswer
    assert back.leg_id == bytes([0x02])
    assert back.misc_call_info is None


def test_apply_charging_round_trip() -> None:
    a = gsm_cap.ApplyChargingArg(
        bytes([0x00, 0x01, 0x02]), party_to_charge=bytes([0x02])
    )
    back = gsm_cap.ApplyChargingArg.decode(a.encode())
    assert back.ach_billing_charging_characteristics == bytes([0x00, 0x01, 0x02])
    assert back.party_to_charge == bytes([0x02])


def test_initial_dp_sms_round_trip() -> None:
    s = gsm_cap.InitialDpSmsArg(
        7,
        destination_subscriber_number=bytes([0x91, 0x55, 0x01]),
        calling_party_number=bytes([0x91, 0x55, 0x01, 0x88]),
        event_type_sms=gsm_cap.EventTypeSms.OSmsSubmission,
        smsc_address=bytes([0x91, 0x55, 0x01, 0x00]),
    )
    back = gsm_cap.InitialDpSmsArg.decode(s.encode())
    assert back.service_key == 7
    assert back.destination_subscriber_number == bytes([0x91, 0x55, 0x01])
    assert back.calling_party_number == bytes([0x91, 0x55, 0x01, 0x88])
    assert back.event_type_sms == gsm_cap.EventTypeSms.OSmsSubmission
    assert back.smsc_address == bytes([0x91, 0x55, 0x01, 0x00])


def test_application_context_helpers() -> None:
    # CAP v3 gsmSSF-scfGeneric = 0.4.0.0.1.21.3.4
    assert gsm_cap.cap_gsmssf_scf_generic(3) == [0, 4, 0, 0, 1, 21, 3, 4]
    # CAP v4 differs from v3 (module 23 vs 21).
    assert gsm_cap.cap_gsmssf_scf_generic(4) != gsm_cap.cap_gsmssf_scf_generic(3)
    # SMS AC id is 50.
    assert gsm_cap.cap_sms_ac(3)[-1] == 50


def test_decode_rejects_garbage() -> None:
    with pytest.raises(gsm_cap.CapCodecError):
        gsm_cap.InitialDpArg.decode(b"\xff\xff\xff\xff")


def test_decode_rejects_truncated() -> None:
    good = gsm_cap.ReleaseCallArg(bytes([0x90, 0x03])).encode()
    with pytest.raises(gsm_cap.CapCodecError):
        gsm_cap.ReleaseCallArg.decode(good[:1])
