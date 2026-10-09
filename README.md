# gsm_cap

[![crates.io](https://img.shields.io/crates/v/gsm_cap.svg)](https://crates.io/crates/gsm_cap)
[![docs.rs](https://docs.rs/gsm_cap/badge.svg)](https://docs.rs/gsm_cap)
[![CI](https://github.com/Real-Time-Telecom-B-V/gsm_cap/actions/workflows/ci.yml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/gsm_cap/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A **CAMEL Application Part (CAP)** operation codec — 3GPP TS 29.078. BER
encode/decode of the gsmSSF ↔ gsmSCF operations that drive CAMEL Intelligent
Network services: prepaid call control, service triggering, charging, and
CAMEL‑for‑SMS. It ships as **both** a Rust crate (`cargo add gsm_cap`) and a
Rust-backed Python wheel (`pip install gsm_cap`), built from one source tree and
one version.

CAP rides on TCAP over SCCP; this crate is the **operation layer** — the
argument/result types (via [`rasn`](https://crates.io/crates/rasn) ASN.1 BER) and
the operation codes. A consumer wraps a CAP argument in a TCAP Invoke with the
matching operation code; the dialogue (application context, transaction IDs) is
the TCAP layer's job.

```rust
use gsm_cap::operations::EventReportBcsmArg;
use gsm_cap::types::{EventTypeBcsm, MiscCallInfo, ReceivingSideId, LEG2};

// gsmSSF → gsmSCF: the called party answered.
let report = EventReportBcsmArg {
    leg_id: Some(ReceivingSideId::leg(LEG2)),
    misc_call_info: Some(MiscCallInfo::notification()),
    ..EventReportBcsmArg::new(EventTypeBcsm::OAnswer)
};
let ber = gsm_cap::encode(&report).unwrap();
let back: EventReportBcsmArg = gsm_cap::decode(&ber).unwrap();
assert_eq!(report, back);
```

```python
import gsm_cap

# gsmSSF → gsmSCF: an InitialDP for a triggered call (synthetic bytes).
idp = gsm_cap.InitialDpArg(
    42,  # service key
    called_party_number=bytes([0x03, 0x55, 0x01, 0x23]),
    event_type_bcsm=gsm_cap.EventTypeBcsm.CollectedInfo,
)
ber = idp.encode()                              # bytes (BER)
back = gsm_cap.InitialDpArg.decode(ber)         # -> InitialDpArg
```

The `initialDP` operation (gsmSSF → gsmSCF, sent when a call hits a detection
point) and the rest are in [`operations`](src/operations.rs); the files under
[`tests/`](tests) are worked examples, each with the bytes it must produce.

## Coverage

Call control (InitialDP, Connect, ReleaseCall, ConnectToResource, Cancel), event
reporting (RequestReportBCSMEvent, EventReportBCSM), charging (ApplyCharging,
ApplyChargingReport, FurnishChargingInformation), specialised resources
(PlayAnnouncement, PromptAndCollectUserInformation), and CAMEL‑for‑SMS
(InitialDPSMS, ConnectSMS, ReleaseSMS, RequestReportSMSEvent, EventReportSMS) —
plus the [`op_codes`](src/op_codes.rs) with `operation_name()` and the
[`application_context`](src/application_context.rs) names for CAP phases 1 to 4.

Every argument is modelled with all the members the ASN.1 gives it through
Release 18. The charging operations carry an OCTET STRING whose content is
itself BER; the types for that content are here too, in the phase 3 and the
phase 4 form where the two differ.

Not covered yet: ContinueWithArgument, ResetTimer, EstablishTemporaryConnection,
DisconnectForwardConnection (with and without argument), AssistRequestInstructions,
CallInformationRequest / Report, SendChargingInformation, CallGap,
CollectInformation, the SpecializedResourceReport argument, the phase 4 call
party handling operations (InitiateCallAttempt, SplitLeg, MoveLeg, DisconnectLeg,
EntityReleased, PlayTone), FurnishChargingInformationSMS, ResetTimerSMS, the GPRS
operations, and the error codes and parameters.

The **Python surface** covers the call-control set (InitialDP, Connect,
ReleaseCall, RequestReportBCSMEvent, EventReportBCSM, ApplyCharging) plus
CAMEL-for-SMS (InitialDPSMS), the shared enums
(`EventTypeBcsm` / `MonitorMode` / `EventTypeSms`), the operation codes, and the
application-context helpers. Each operation type has `.encode() -> bytes` and a
`decode(bytes)` classmethod, and exposes a subset of the members of its Rust
type. Result types and the specialised-resource operations are Rust-only for
now.

## Conformance

The types follow the ASN.1 of 3GPP TS 29.078 V18.0.0 and, for the MAP types CAP
imports, TS 29.002 V18.0.0. A round-trip through one codec cannot show that an
encoding is the specified one, because a mistake shared by its encoder and its
decoder passes. So every argument is checked two more ways:

* against a **byte vector assembled by hand** from the ASN.1, with the
  derivation written next to the bytes, in both directions (encode gives exactly
  those bytes, those bytes decode to exactly that value);
* against **Wireshark**: the test harness in [`tests/common`](tests/common/mod.rs)
  wraps the encoding in TCAP, SCCP (SSN 146) and M3UA, runs `tshark`, and asserts
  the decoded fields by name and value, plus the absence of any malformed,
  unknown or error marker.

The Wireshark half needs `tshark` and `text2pcap` on the path and is skipped
with a `SKIP` line when they are missing; the byte vectors always run. Set
`GSM_CAP_REQUIRE_TSHARK=1` to make a missing tool a failure.

`gsm_cap::decode` fails on a member that is present but cannot be decoded. `rasn`
on its own reports such a member as absent when it sits behind an explicit tag.

## Performance

Single-core, `cargo bench` ([`benches/codec.rs`](benches/codec.rs)); the codec is
`rasn` BER pack/unpack of the CAP argument types, no I/O. Indicative numbers (all
fixtures synthetic):

| Operation | Encode | Decode |
|---|---|---|
| InitialDP (several optional fields) | ~360 ns (~2.8 M/s) | ~790 ns (~1.3 M/s) |
| Connect (one routing address) | ~125 ns (~8.0 M/s) | ~235 ns (~4.3 M/s) |
| EventReportBCSM (O-Answer) | ~120 ns (~8.3 M/s) | ~245 ns (~4.1 M/s) |

Decode includes the pass that checks no member was dropped (one extra encode).

### Full-stack integration benchmark (CAP → TCAP → SCCP)

[`benches/integration.rs`](benches/integration.rs) assembles the classic CAMEL
prepaid-call exchange **the way it goes on the wire** and measures the whole path
end to end — encode a CAP argument, wrap it in a TCAP `Invoke` inside a
`Begin`/`Continue` transaction, carry that in an SCCP `UnitData` (UDT) with GT +
SSN addresses — then decode it all back:

* **InitialDP** (gsmSSF → gsmSCF, TCAP `Begin`)
* **Connect** (gsmSCF → gsmSSF, TCAP `Continue`)

using the sibling [`tcap`](https://github.com/Real-Time-Telecom-B-V/tcap) and
[`sccp`](https://github.com/Real-Time-Telecom-B-V/sccp) codecs (git dev-deps).
Indicative full-stack throughput (per whole message):

| Full-stack path | Encode | Decode |
|---|---|---|
| InitialDP CAP→TCAP→SCCP | ~830 ns (~1.2 M msg/s) | ~1.3 µs (~0.77 M msg/s) |
| Connect CAP→TCAP→SCCP | ~645 ns (~1.55 M msg/s) | ~610 ns (~1.64 M msg/s) |
| One call's InitialDP + Connect (encode both) | ~1.6 µs (~620 K exchanges/s) | — |

A counting-allocator [leak check](examples/leak_check.rs)
(`./scripts/mem_leak_test.sh`) hammers encode/decode across the call-control and
SMS operations and asserts **live bytes stay flat** (Δ 0 over millions of
cycles). Both benches and the leak check run in CI.

The Python wheel is the same Rust code behind PyO3; per-call overhead is the
Python↔Rust boundary, not the codec. The module is `gil_used = false`, so it
loads on free-threaded ("no-GIL") CPython 3.13t / 3.14t.

## Install

```bash
cargo add gsm_cap        # Rust crate (zero pyo3 in the default build)
pip install gsm_cap      # Rust-backed Python wheel
```

## Development

```bash
cargo test                              # unit + integration + doctests; the
                                        # Wireshark checks run when tshark is installed
GSM_CAP_REQUIRE_TSHARK=1 cargo test     # fail instead of skipping without tshark
cargo test --features python            # + the PyO3 binding face
cargo clippy --all-targets -- -D warnings
cargo clippy --features python --lib -- -D warnings
cargo bench --no-run                    # incl. the CAP→TCAP→SCCP integration bench
./scripts/mem_leak_test.sh              # live-bytes leak check (PASS/FAIL)
cargo deny check                        # advisories, licenses, sources

# Python wheel
maturin develop && pytest python/tests -q
```

## License

MIT — see [LICENSE](LICENSE). Part of the SS7 stack (rides on TCAP; peer of the
MAP layer).
