# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

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
