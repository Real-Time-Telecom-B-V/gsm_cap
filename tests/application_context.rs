//! Application-context names: one test per constant.
//!
//! Each value is checked three ways:
//!
//! 1. the arcs, against the object identifier assignments in the
//!    specifications (see `src/application_context.rs` for the editions);
//! 2. the BER content octets, derived by hand from X.690 8.19: the first two
//!    arcs `0.4` share one octet (`0 * 40 + 4 = 0x04`), every later arc below
//!    128 is one octet, so `0.4.0.0.1.21.3.4` is `04 00 00 01 15 03 04`;
//! 3. Wireshark, which registers these contexts by name in its CAMEL
//!    dissector and prints `itu-t.4.0...` for a value it does not know.

mod common;

use common::{dissect, Carrier};
use gsm_cap::application_context as ac;
use gsm_cap::op_codes;

/// `(arcs, BER content octets, name Wireshark registers)`.
fn check(arcs: &[u32; 8], content: [u8; 7], wireshark_name: &str) {
    let oid = ac::object_identifier(arcs);
    let ber = rasn::ber::encode(&oid).unwrap();
    // OBJECT IDENTIFIER: universal tag 6, length 7.
    let mut expected = vec![0x06, 0x07];
    expected.extend_from_slice(&content);
    assert_eq!(ber, expected, "BER of {arcs:?}");

    let Some(d) = dissect(op_codes::ACTIVITY_TEST, None, Carrier::Begin(&oid)) else {
        return;
    };
    let dotted = arcs.map(|a| a.to_string()).join(".");
    d.show("tcap.aarq_application_context_name", &dotted);
    let label = &d
        .fields
        .iter()
        .find(|f| f.name == "tcap.aarq_application_context_name")
        .expect("application context field")
        .showname;
    assert!(
        label.ends_with(&format!("({wireshark_name})")),
        "Wireshark names {dotted} as {label:?}, expected {wireshark_name}"
    );
}

#[test]
fn cap_v1_gsmssf_to_gsmscf() {
    check(
        &ac::CAP_V1_GSMSSF_TO_GSMSCF,
        [0x04, 0x00, 0x00, 0x01, 0x00, 0x32, 0x00],
        "CAP-v1-gsmSSF-to-gsmSCF-AC",
    );
}

#[test]
fn cap_v2_gsmssf_to_gsmscf() {
    check(
        &ac::CAP_V2_GSMSSF_TO_GSMSCF,
        [0x04, 0x00, 0x00, 0x01, 0x00, 0x32, 0x01],
        "CAP-v2-gsmSSF-to-gsmSCF-AC",
    );
}

#[test]
fn cap_v2_assist_gsmssf_to_gsmscf() {
    check(
        &ac::CAP_V2_ASSIST_GSMSSF_TO_GSMSCF,
        [0x04, 0x00, 0x00, 0x01, 0x00, 0x33, 0x01],
        "CAP-v2-assist-gsmSSF-to-gsmSCF-AC",
    );
}

#[test]
fn cap_v2_gsmsrf_to_gsmscf() {
    check(
        &ac::CAP_V2_GSMSRF_TO_GSMSCF,
        [0x04, 0x00, 0x00, 0x01, 0x00, 0x34, 0x01],
        "CAP-v2-gsmSRF-to-gsmSCF-AC",
    );
}

#[test]
fn cap_v3_gsmssf_scf_generic() {
    check(
        &ac::CAP_V3_GSMSSF_SCF_GENERIC,
        [0x04, 0x00, 0x00, 0x01, 0x15, 0x03, 0x04],
        "capssf-scfGenericAC",
    );
}

#[test]
fn cap_v3_gsmssf_scf_assist_handoff() {
    check(
        &ac::CAP_V3_GSMSSF_SCF_ASSIST_HANDOFF,
        [0x04, 0x00, 0x00, 0x01, 0x15, 0x03, 0x06],
        "capssf-scfAssistHandoffAC",
    );
}

#[test]
fn cap_v3_gsmsrf_gsmscf() {
    check(
        &ac::CAP_V3_GSMSRF_GSMSCF,
        [0x04, 0x00, 0x00, 0x01, 0x14, 0x03, 0x0e],
        "gsmSRF-gsmSCF-ac",
    );
}

#[test]
fn cap_v3_gprsssf_gsmscf() {
    check(
        &ac::CAP_V3_GPRSSSF_GSMSCF,
        [0x04, 0x00, 0x00, 0x01, 0x15, 0x03, 0x32],
        "cap3-gprssf-scfAC",
    );
}

#[test]
fn cap_v3_gsmscf_gprsssf() {
    check(
        &ac::CAP_V3_GSMSCF_GPRSSSF,
        [0x04, 0x00, 0x00, 0x01, 0x15, 0x03, 0x33],
        "cap3-gsmscf-gprsssfAC",
    );
}

#[test]
fn cap_v3_sms() {
    check(
        &ac::CAP_V3_SMS,
        [0x04, 0x00, 0x00, 0x01, 0x15, 0x03, 0x3d],
        "cap3-sms-AC",
    );
}

#[test]
fn cap_v4_gsmssf_scf_generic() {
    check(
        &ac::CAP_V4_GSMSSF_SCF_GENERIC,
        [0x04, 0x00, 0x00, 0x01, 0x17, 0x03, 0x04],
        "capssf-scfGenericAC",
    );
}

#[test]
fn cap_v4_gsmssf_scf_assist_handoff() {
    check(
        &ac::CAP_V4_GSMSSF_SCF_ASSIST_HANDOFF,
        [0x04, 0x00, 0x00, 0x01, 0x17, 0x03, 0x06],
        "capssf-scfAssistHandoffAC",
    );
}

#[test]
fn cap_v4_scf_gsmssf_generic() {
    check(
        &ac::CAP_V4_SCF_GSMSSF_GENERIC,
        [0x04, 0x00, 0x00, 0x01, 0x17, 0x03, 0x08],
        "capscf-ssfGenericAC",
    );
}

#[test]
fn cap_v4_gsmsrf_gsmscf() {
    check(
        &ac::CAP_V4_GSMSRF_GSMSCF,
        [0x04, 0x00, 0x00, 0x01, 0x16, 0x03, 0x0e],
        "gsmSRF-gsmSCF-ac",
    );
}

#[test]
fn cap_v4_sms() {
    check(
        &ac::CAP_V4_SMS,
        [0x04, 0x00, 0x00, 0x01, 0x17, 0x03, 0x3d],
        "cap4-sms-AC",
    );
}
