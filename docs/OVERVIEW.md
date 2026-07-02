# cap — overview

A **CAMEL Application Part (CAP)** operation codec (3GPP TS 29.078). It provides
the argument/result types for the gsmSSF ↔ gsmSCF operations and their operation
codes; the ASN.1 BER encode/decode is done by [`rasn`](https://crates.io/crates/rasn).

## Where CAP sits

```
  gsmSCF  ◀── CAP operations ──▶  gsmSSF        (this crate: the operation layer)
                    │
                   TCAP           (transactions + dialogue; wraps CAP invokes)
                    │
                   SCCP           (GT/SSN addressing)
                    │
               MTP3 / M3UA        (transport)
```

CAP is a peer of MAP: both are TCAP application parts. This crate is the CAP
counterpart to the MAP (`gsm_map`) operation layer — same shape (rasn types +
operation codes), different operations.

## Modules

| Path | Contents |
|---|---|
| `src/types.rs` | Common CAP types: `ServiceKey`, the address aliases (Q.763 / BCD / TBCD `OCTET STRING`s), `LocationInformation`, and the `EventTypeBcsm` / `MonitorMode` / `BcsmEvent` / `EventTypeSms` / `SmsEvent` enums & structs. |
| `src/operations.rs` | The operation arguments/results (`InitialDpArg`, `ConnectArg`, `ReleaseCallArg`, `RequestReportBcsmEventArg`, `EventReportBcsmArg`, `ApplyChargingArg`, `PlayAnnouncementArg`, `PromptAndCollectUserInformation*`, and the SMS set), each deriving `rasn` BER `Encode`/`Decode`. |
| `src/op_codes.rs` | The operation-code constants + `operation_name()`. |
| `src/lib.rs` | `encode` / `decode` helpers (BER) + re-exports; `CapError`. |

## Usage shape

1. Build a CAP argument (e.g. `InitialDpArg`).
2. `cap::encode(&arg)` → BER bytes.
3. Put the bytes in a TCAP Invoke component with the matching `op_codes::*` value;
   the TCAP layer handles the dialogue (application context, transaction IDs) and
   SCCP addressing.
4. On receipt, read the operation code, then `cap::decode::<TheArg>(bytes)`.

## Scope

This crate is the CAP **operation codec** only — deliberately transport- and
TCAP-independent, so it is a pure, portable, testable building block. Dialogue
negotiation, transaction state, and routing belong to the TCAP/SCCP layers above
the transport.
