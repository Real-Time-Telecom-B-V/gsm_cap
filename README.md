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
use gsm_cap::operations::ReleaseCallArg;

// gsmSCF → gsmSSF: release the call with a Q.850 cause (synthetic bytes).
let rel = ReleaseCallArg { cause: vec![0x90, 0x03].into() };
let ber = gsm_cap::encode(&rel).unwrap();
let back: ReleaseCallArg = gsm_cap::decode(&ber).unwrap();
assert_eq!(rel, back);
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
point) and the rest are in [`operations`](src/operations.rs); see
[`tests/roundtrip.rs`](tests/roundtrip.rs) for worked examples.

## Coverage

Call control (InitialDP, Connect, ReleaseCall, ConnectToResource, Cancel), event
reporting (RequestReportBCSMEvent, EventReportBCSM), charging (ApplyCharging,
ApplyChargingReport, FurnishChargingInformation), specialised resources
(PlayAnnouncement, PromptAndCollectUserInformation), and CAMEL‑for‑SMS
(InitialDPSMS, ConnectSMS, ReleaseSMS, RequestReportSMSEvent, EventReportSMS) —
plus the [`op_codes`](src/op_codes.rs) with `operation_name()` and the
[`application_context`](src/application_context.rs) OID helpers.

The **Python surface** covers the call-control set (InitialDP, Connect,
ReleaseCall, RequestReportBCSMEvent, EventReportBCSM, ApplyCharging) plus
CAMEL-for-SMS (InitialDPSMS), the shared enums
(`EventTypeBcsm` / `MonitorMode` / `EventTypeSms`), the operation codes, and the
application-context helpers. Each operation type has `.encode() -> bytes` and a
`decode(bytes)` classmethod. Result types and the specialised-resource
operations are Rust-only for now.

## Performance

Single-core, `cargo bench` ([`benches/codec.rs`](benches/codec.rs)); the codec is
`rasn` BER pack/unpack of the CAP argument types, no I/O. Indicative numbers (all
fixtures synthetic):

| Operation | Encode | Decode |
|---|---|---|
| InitialDP (several optional fields) | ~247 ns (~4.0 M/s) | ~221 ns (~4.5 M/s) |
| Connect (one routing address) | ~93 ns (~10.8 M/s) | ~88 ns (~11.4 M/s) |
| EventReportBCSM (O-Answer) | ~61 ns (~16.3 M/s) | ~65 ns (~15.5 M/s) |

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
| InitialDP CAP→TCAP→SCCP | ~723 ns (~1.38 M msg/s) | ~489 ns (~2.05 M msg/s) |
| Connect CAP→TCAP→SCCP | ~614 ns (~1.63 M msg/s) | ~389 ns (~2.57 M msg/s) |
| One call's InitialDP + Connect (encode both) | ~1.56 µs (~639 K exchanges/s) | — |

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
cargo test                              # unit + integration + doctests
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
