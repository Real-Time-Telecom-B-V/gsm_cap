//! Full-stack CAMEL integration benchmark: **CAP → TCAP → SCCP** end to end.
//!
//! This is the headline benchmark. It assembles the classic CAMEL prepaid-call
//! exchange as it would go on the wire and measures the whole path at volume —
//! "spam a lot of InitialDP + Connect, then TCAP, then SCCP":
//!
//! * **InitialDP** (gsmSSF → gsmSCF): the SSF reports a triggered call. The CAP
//!   `InitialDpArg` is encoded (this crate), wrapped in a TCAP `Invoke` inside a
//!   `Begin` transaction (`tcap`), and carried in an SCCP `UnitData` (UDT) with
//!   GT + SSN addresses (`sccp`) → full wire bytes.
//! * **Connect** (gsmSCF → gsmSSF): the SCP routes the call. The CAP `ConnectArg`
//!   rides a TCAP `Invoke` inside a `Continue` (the dialogue is already open),
//!   again in an SCCP UDT.
//!
//! Two directions are benched at volume:
//!   * **encode** — CAP arg → TCAP component/transaction → SCCP UDT → bytes.
//!   * **decode** — SCCP UDT bytes → TCAP transaction → TCAP Invoke parameter →
//!     CAP arg.
//!
//! All values are **synthetic** (fictional `+1-555-01xx` GT digits, made-up keys /
//! IMSI); nothing here is captured traffic. Throughput is reported per full
//! stack message (`Throughput::Elements(1)`), i.e. messages/sec.
//!
//! `tcap` and `sccp` are git dev-dependencies. If either cannot be resolved this
//! bench won't build; the `codec` bench (gsm_cap only) still does.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rasn::types::{Any, Integer};

use gsm_cap::operations::{ConnectArg, InitialDpArg};
use gsm_cap::types::EventTypeBcsm;
use gsm_cap::{application_context, op_codes};

use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use tcap::{Begin, Component, Continue, Invoke, OperationCode, TcapMessage};

// ── Synthetic CAP fixtures ───────────────────────────────────────────────────

fn sample_initial_dp() -> InitialDpArg {
    InitialDpArg {
        service_key: Integer::from(42),
        called_party_number: Some(vec![0x03, 0x55, 0x01, 0x23].into()),
        calling_party_number: Some(vec![0x03, 0x55, 0x01, 0x99].into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: None,
        imsi: Some(vec![0x00, 0x10, 0x19, 0x00, 0x00].into()),
        location_information: None,
        call_reference_number: Some(vec![0xDE, 0xAD, 0xBE, 0xEF].into()),
        msc_address: Some(vec![0x91, 0x55, 0x01, 0x00].into()),
        called_party_bcd_number: None,
        time_and_timezone: None,
    }
}

fn sample_connect() -> ConnectArg {
    ConnectArg {
        destination_routing_address: vec![vec![0x03, 0x55, 0x01, 0x23].into()],
        original_called_party_id: None,
        calling_partys_category: None,
        redirecting_party_id: None,
        generic_numbers: None,
    }
}

// ── SCCP addressing (synthetic GT digits, CAMEL SSNs) ────────────────────────

/// gsmSSF-side address: an E.164 GT (`+1-555-01xx`) at the CAP subsystem.
fn ssf_address() -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,  // E.164
        encoding_scheme: 1, // BCD odd
        nature_of_address: 4,
        digits: "15550100123".to_string(),
    };
    SccpAddress::with_gt(gt, Some(SubsystemNumber::Cap))
}

/// gsmSCF-side address: another synthetic E.164 GT at the CAP subsystem.
fn scf_address() -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: "15550199001".to_string(),
    };
    SccpAddress::with_gt(gt, Some(SubsystemNumber::Cap))
}

// ── Full-stack encode: CAP → TCAP → SCCP → wire bytes ────────────────────────

/// Encode an InitialDP as a full CAP→TCAP(Begin)→SCCP(UDT) message.
///
/// gsmSSF → gsmSCF: the SSF opens the dialogue, so it's a TCAP `Begin` from SSF
/// (called = SCF, calling = SSF).
fn encode_initial_dp_stack(idp: &InitialDpArg) -> Vec<u8> {
    // 1. CAP: encode the operation argument to BER.
    let cap_ber = gsm_cap::encode(idp).expect("cap encode");

    // 2. TCAP: wrap in an Invoke(initialDP) inside a Begin transaction.
    let invoke = Invoke {
        invoke_id: 1,
        linked_id: None,
        operation_code: OperationCode::Local(op_codes::INITIAL_DP),
        parameter: Some(Any::new(cap_ber)),
    };
    let begin = Begin {
        otid: vec![0x00, 0x00, 0x10, 0x01].into(),
        dialogue_portion: None,
        components: Some(vec![Component::Invoke(invoke)]),
    };
    let tcap_bytes = tcap::encode(&TcapMessage::Begin(begin)).expect("tcap encode");

    // 3. SCCP: carry the TCAP payload in a UDT (SSF → SCF).
    let udt = UnitData::new(scf_address(), ssf_address(), tcap_bytes);
    udt.encode().expect("sccp encode")
}

/// Encode a Connect as a full CAP→TCAP(Continue)→SCCP(UDT) message.
///
/// gsmSCF → gsmSSF: the dialogue is already open, so it's a TCAP `Continue`
/// (called = SSF, calling = SCF).
fn encode_connect_stack(connect: &ConnectArg) -> Vec<u8> {
    let cap_ber = gsm_cap::encode(connect).expect("cap encode");

    let invoke = Invoke {
        invoke_id: 2,
        linked_id: None,
        operation_code: OperationCode::Local(op_codes::CONNECT),
        parameter: Some(Any::new(cap_ber)),
    };
    let cont = Continue {
        otid: vec![0x00, 0x00, 0x20, 0x02].into(),
        dtid: vec![0x00, 0x00, 0x10, 0x01].into(),
        dialogue_portion: None,
        components: Some(vec![Component::Invoke(invoke)]),
    };
    let tcap_bytes = tcap::encode(&TcapMessage::Continue(cont)).expect("tcap encode");

    let udt = UnitData::new(ssf_address(), scf_address(), tcap_bytes);
    udt.encode().expect("sccp encode")
}

// ── Full-stack decode: wire bytes → SCCP → TCAP → CAP ────────────────────────

/// Peel an InitialDP back out of a full stack message: SCCP UDT → TCAP Begin →
/// Invoke parameter → CAP `InitialDpArg`.
fn decode_initial_dp_stack(wire: &[u8]) -> InitialDpArg {
    let udt = UnitData::decode(wire).expect("sccp decode");
    let tcap_msg = tcap::decode(&udt.data).expect("tcap decode");
    let components = match tcap_msg {
        TcapMessage::Begin(b) => b.components.expect("components"),
        other => panic!("expected Begin, got {other}"),
    };
    let param = match &components[0] {
        Component::Invoke(inv) => inv.parameter.as_ref().expect("parameter"),
        other => panic!("expected Invoke, got {other}"),
    };
    gsm_cap::decode::<InitialDpArg>(param.as_bytes()).expect("cap decode")
}

/// Peel a Connect back out of a full stack message: SCCP UDT → TCAP Continue →
/// Invoke parameter → CAP `ConnectArg`.
fn decode_connect_stack(wire: &[u8]) -> ConnectArg {
    let udt = UnitData::decode(wire).expect("sccp decode");
    let tcap_msg = tcap::decode(&udt.data).expect("tcap decode");
    let components = match tcap_msg {
        TcapMessage::Continue(c) => c.components.expect("components"),
        other => panic!("expected Continue, got {other}"),
    };
    let param = match &components[0] {
        Component::Invoke(inv) => inv.parameter.as_ref().expect("parameter"),
        other => panic!("expected Invoke, got {other}"),
    };
    gsm_cap::decode::<ConnectArg>(param.as_bytes()).expect("cap decode")
}

fn bench_integration(c: &mut Criterion) {
    let idp = sample_initial_dp();
    let connect = sample_connect();

    // Sanity: the stack round-trips before we time it, and the AC helper is wired
    // (the dialogue would carry cap_gsmssf_scf_generic(CAP_V4) in a real setup).
    let idp_wire = encode_initial_dp_stack(&idp);
    let connect_wire = encode_connect_stack(&connect);
    assert_eq!(decode_initial_dp_stack(&idp_wire), idp);
    assert_eq!(decode_connect_stack(&connect_wire), connect);
    let _ac = application_context::cap_gsmssf_scf_generic(application_context::CAP_V4);

    let mut g = c.benchmark_group("integration");
    // One full stack message per iteration → messages/sec.
    g.throughput(Throughput::Elements(1));

    // InitialDP: gsmSSF → gsmSCF (Begin).
    g.bench_function("initial_dp/encode_stack", |b| {
        b.iter_batched(
            || idp.clone(),
            |v| encode_initial_dp_stack(&v),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("initial_dp/decode_stack", |b| {
        b.iter(|| decode_initial_dp_stack(&idp_wire))
    });

    // Connect: gsmSCF → gsmSSF (Continue).
    g.bench_function("connect/encode_stack", |b| {
        b.iter_batched(
            || connect.clone(),
            |v| encode_connect_stack(&v),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("connect/decode_stack", |b| {
        b.iter(|| decode_connect_stack(&connect_wire))
    });

    // A combined "one InitialDP + one Connect" exchange, encode both directions —
    // the realistic per-call CAMEL signalling burst.
    g.bench_function("call_exchange/encode_both", |b| {
        b.iter_batched(
            || (idp.clone(), connect.clone()),
            |(a, b2)| {
                let w1 = encode_initial_dp_stack(&a);
                let w2 = encode_connect_stack(&b2);
                (w1, w2)
            },
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

criterion_group!(benches, bench_integration);
criterion_main!(benches);
