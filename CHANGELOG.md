# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [1.2.0]

### Fixed
- `ReleaseCallArg` now encodes as a bare `Cause` (OCTET STRING), not a
  `SEQUENCE`. It was a named-field struct, which emitted an extra SEQUENCE
  wrapper that a conforming peer / dissector rejects as malformed (Wireshark:
  "This field lies beyond the end of the known sequence definition"). It is now
  a `#[rasn(delegate)]` newtype, matching `inap`'s `ReleaseCallArg` and CAP
  (TS 29.078), where the releaseCall argument is a bare `CauseValue`. Round-trip
  tests missed it because encode and decode shared the wrapper; a byte-level test
  now pins the bare `04 02 …` encoding. Construction changes from
  `ReleaseCallArg { cause }` to `ReleaseCallArg(cause)`.

## [1.1.0]

### Changed
- Re-export the shared IN/CS-2 leaf IEs from the `inap` crate to remove the
  duplicated definitions. `EventTypeBcsm`, `MonitorMode`, `BcsmEvent`,
  `ConnectToResourceArg`, `PlayAnnouncementArg`,
  `PromptAndCollectUserInformationArg` / `…Res` and the `CalledPartyNumber` /
  `CallingPartyNumber` / `Cause` aliases now live in `inap` (the canonical home)
  and are re-exported at their existing paths. No API or wire change: same type
  names, fields, tags and BER output.

## [1.0.0]

First release — the CAMEL Application Part (CAP) operation codec (3GPP TS 29.078).

### Added
- Call control: `InitialDpArg`, `ConnectArg`, `ReleaseCallArg`,
  `ConnectToResourceArg`, `CancelArg`.
- Event reporting: `RequestReportBcsmEventArg`, `EventReportBcsmArg` (+ the
  `EventTypeBcsm` / `MonitorMode` / `BcsmEvent` types).
- Charging: `ApplyChargingArg`, `ApplyChargingReportArg`,
  `FurnishChargingInformationArg`.
- Specialised resources: `PlayAnnouncementArg`,
  `PromptAndCollectUserInformationArg` / `…Res`.
- CAMEL-for-SMS: `InitialDpSmsArg`, `ConnectSmsArg`, `ReleaseSmsArg`,
  `RequestReportSmsEventArg`, `EventReportSmsArg` (+ `EventTypeSms` / `SmsEvent`).
- `op_codes` constants + `operation_name()`; `encode`/`decode` BER helpers;
  `CapError`.
- BER round-trip tests over synthetic values.
