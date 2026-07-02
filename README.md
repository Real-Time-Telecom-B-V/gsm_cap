# cap

[![CI](https://github.com/Real-Time-Telecom-B-V/cap/actions/workflows/ci.yml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/cap/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A **CAMEL Application Part (CAP)** operation codec — 3GPP TS 29.078. BER
encode/decode of the gsmSSF ↔ gsmSCF operations that drive CAMEL Intelligent
Network services: prepaid call control, service triggering, charging, and
CAMEL‑for‑SMS.

CAP rides on TCAP over SCCP; this crate is the **operation layer** — the
argument/result types (via [`rasn`](https://crates.io/crates/rasn) ASN.1 BER) and
the operation codes. A consumer wraps a CAP argument in a TCAP Invoke with the
matching operation code; the dialogue (application context, transaction IDs) is
the TCAP layer's job.

```rust
use cap::operations::ReleaseCallArg;

// gsmSCF → gsmSSF: release the call with a Q.850 cause (synthetic bytes).
let rel = ReleaseCallArg { cause: vec![0x90, 0x03].into() };
let ber = cap::encode(&rel).unwrap();
let back: ReleaseCallArg = cap::decode(&ber).unwrap();
assert_eq!(rel, back);
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
plus the [`op_codes`](src/op_codes.rs) with `operation_name()`.

More: [`docs/OVERVIEW.md`](docs/OVERVIEW.md).

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo deny check
```

## License

MIT — see [LICENSE](LICENSE). Part of the SS7 stack (rides on TCAP; peer of the
MAP layer).
