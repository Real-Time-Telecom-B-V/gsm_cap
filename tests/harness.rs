//! The Wireshark harness itself: it must accept what is right, reject what is
//! wrong, and report fields rather than a bare "no crash".
//!
//! All values are synthetic.

mod common;

use common::{dissect, dissect_unchecked, Carrier};
use gsm_cap::op_codes;
use gsm_cap::operations::ReleaseCallArg;

#[test]
fn release_call_is_dissected_as_a_bare_cause() {
    // Cause, ITU-T Q.850 as carried in ISUP (Q.763 3.12): 0x80 = no extension,
    // coding standard ITU-T, location "user"; 0x90 = no extension, cause 16
    // (normal call clearing).
    let ber = gsm_cap::encode(&ReleaseCallArg(vec![0x80, 0x90].into())).unwrap();
    // ReleaseCallArg ::= Cause, an OCTET STRING: universal tag 4, length 2.
    assert_eq!(ber, [0x04, 0x02, 0x80, 0x90]);

    let Some(d) = dissect(op_codes::RELEASE_CALL, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.hex("camel.allCallSegments", "8090")
        .show("camel.cause_indicator", "16");
}

#[test]
fn harness_rejects_a_release_call_wrapped_in_a_sequence() {
    // What this crate emitted before 1.2.0: SEQUENCE { OCTET STRING }. If the
    // harness let this through it would be worthless as an oracle.
    let wrapped = [0x30, 0x04, 0x04, 0x02, 0x80, 0x90];
    let Some(d) = dissect_unchecked(op_codes::RELEASE_CALL, Some(&wrapped), Carrier::Continue)
    else {
        return;
    };
    assert!(
        !d.problems().is_empty(),
        "Wireshark should reject a SEQUENCE-wrapped releaseCall\n{}",
        d.summary()
    );
    assert!(d.values("camel.allCallSegments").is_empty());
}

#[test]
fn harness_rejects_an_unknown_operation_code() {
    let Some(d) = dissect_unchecked(250, None, Carrier::Continue) else {
        return;
    };
    assert!(!d.problems().is_empty(), "{}", d.summary());
}

#[test]
fn operations_without_an_argument_are_recognised() {
    // continue, activityTest and continueSMS carry no argument (TS 29.078
    // clauses 6.1.1 and 7.1): the Invoke ends after the operation code.
    for operation in [
        op_codes::CONTINUE,
        op_codes::ACTIVITY_TEST,
        op_codes::CONTINUE_SMS,
    ] {
        let Some(d) = dissect(operation, None, Carrier::Continue) else {
            return;
        };
        d.show("camel.local", &operation.to_string());
    }
}
