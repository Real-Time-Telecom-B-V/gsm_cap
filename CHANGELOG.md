# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [3.0.0] - 2026-10-10

The `inap` dependency moves from 1 to 2, so that a consumer on `inap` 2 no
longer gets two copies of it in its graph. `gsm_cap` re-exports `inap` types,
which makes this a major bump. No encoding changed: every hand-assembled vector
and every Wireshark field assertion of 2.0.0 holds unmodified.

Code that names these types through `gsm_cap` only compiles as before. What to
change if your crate also depends on `inap` directly:

### Changed

- **`inap = "2"`.** `types::MonitorMode` is the enum of `inap` 2. Same variants,
  same values, but a different type from the `MonitorMode` of `inap` 1: move
  your own `inap` dependency to 2 in the same step.
- **`operations::PromptAndCollectUserInformationRes` is defined in this crate**
  and no longer re-exported from `inap`. `inap` 2 gave its type the
  `iA5Response [1]` alternative of Q.1218, which TS 29.078 does not have: in CAP
  `ReceivedInformationArg` is `CHOICE { digitsResponse [0] Digits }` (clause
  6.2). The type here keeps that one alternative, `DigitsResponse`, with the
  same octets as before (`80 03 00 21 43`), and a result under `[1]` is still
  refused. It is no longer interchangeable with the `inap` type of that name.
- `types::CalledPartyNumber`, `CallingPartyNumber` and `Cause` are unchanged:
  aliases of `OctetString` in both versions of `inap`.
- The test harness and the integration bench build their TCAP framing with
  `tcap` 2 (a dev-dependency, not part of the published crate).

## [2.0.0]

Wire-format corrections. Until this release the suite tested encode against
decode only, and a mistake the two share passes that test. Every argument is now
checked against a byte vector assembled by hand from the ASN.1 of 3GPP TS 29.078
V18.0.0 (and TS 29.002 V18.0.0 for the imported MAP types) and against
Wireshark's CAMEL dissector, with the decoded fields asserted.

**Several encodings of 1.x were not interoperable**: a conforming peer rejects
them, and this crate could not decode what a conforming peer sends. They are
listed one by one below. Anything that stored or exchanged 1.x encodings of
these arguments has to be regenerated.

Most public struct shapes changed. The mechanical part of an upgrade: build
arguments with the new `new(..)` constructors and struct update syntax, replace
raw `OctetString` legs with `LegId` / `SendingSideId` / `ReceivingSideId`, and
handle `Option` from the application-context helpers.

### Fixed
- **EventReportBCSM**: `legID` was a primitive `[2]` and `miscCallInfo` a
  primitive `[3]`. The ASN.1 has `eventSpecificInformationBCSM [2]`, `legID [3]
  ReceivingSideID` (a CHOICE, so an explicit constructed wrapper: `A3 03 81 01
  02`) and `miscCallInfo [4]` (a SEQUENCE). Not interoperable before: Wireshark
  reported the argument as malformed.
- **RequestReportBCSMEvent**: `BCSMEvent.legID` was a primitive `[2]`; it is
  `[2] LegID`, explicit (`A2 03 80 01 02`). Not interoperable before whenever a
  leg was given, which a disconnect event always does.
- **Connect**: `originalCalledPartyID` was on `[4]` (it is `[6]`),
  `callingPartysCategory` on `[6]` (`[28]`), `redirectingPartyID` on `[7]`
  (`[29]`) and `genericNumbers` on `[11]` as a SEQUENCE OF (`[14]`, a SET OF).
  Not interoperable before whenever any optional member was set; `[6]` was
  read by a peer as the original called party.
- **ApplyCharging**: `partyToCharge` was a primitive `[2]`; it is `[2]
  SendingSideID`, explicit (`A2 03 80 01 01`). Not interoperable before
  whenever it was set.
- **ApplyChargingReport** and **FurnishChargingInformation**: the argument was
  wrapped in a SEQUENCE. Both are a bare OCTET STRING holding the BER encoding
  of a CAMEL-CallResult / CAMEL-FCIBillingChargingCharacteristics value. Not
  interoperable before, in every case.
- **ReleaseSMS**: the argument was wrapped in a SEQUENCE; it is a bare
  `RPCause` OCTET STRING. Not interoperable before, in every case.
- **InitialDPSMS**: every member from `sMSCAddress` on was one tag too low
  (`sMSCAddress` on `[6]`, which is `locationInformationGPRS`, through
  `ms-Classmark2` on `[16]`, which is `sgsn-Number`). Not interoperable before
  whenever any of those was set.
- **EventReportSMS**: `eventSpecificInformationSMS` and `miscCallInfo` were
  opaque primitive OCTET STRINGs; they are an explicit CHOICE on `[1]` and a
  SEQUENCE on `[2]`. Not interoperable before whenever either was set.
- **PlayAnnouncement** and **PromptAndCollectUserInformation**:
  `informationToSend` and `collectedInfo` were primitive OCTET STRINGs. Both
  are CHOICEs, so `[0]` / `[2]` are explicit constructed wrappers (`A0`, not
  `80`). Not conformant before (X.690 8.14.2); a lenient decoder such as
  Wireshark's tolerated it.
- **LocationInformation** (in InitialDP and InitialDPSMS):
  `cellGlobalIdOrServiceAreaIdOrLAI` was a primitive `[3]`; it is an explicit
  CHOICE (`A3 09 80 07 ...`). `msc-Number` was on `[8]`; it is `[6]`, and `[8]`
  is `currentLocationRetrieved`. Not interoperable before whenever either was
  set.
- **Operation codes**: `CONNECT_SMS` was 61 and `RELEASE_SMS` 62. They are 62
  and 66; 61 is furnishChargingInformationSMS. A ConnectSMS was sent as another
  operation.
- **Application contexts**: the gsmSRF context was given as `...21.3.10` /
  `...23.3.10`; it is `0.4.0.0.1.20.3.14` (phase 3) and `0.4.0.0.1.22.3.14`
  (phase 4). The SMS context was given as `...21.3.50`, which is the gprsSSF
  context; it is `0.4.0.0.1.21.3.61` (phase 3) and `0.4.0.0.1.23.3.61` (phase
  4). Phases 1 and 2 returned the call-control context for every helper; the
  phase 2 assist and gsmSRF contexts are `0.4.0.0.1.0.51.1` and
  `0.4.0.0.1.0.52.1`. A dialogue opened with the old values is refused.
- **Decoding**: a member present on the wire whose content could not be decoded
  was returned as absent when it sat behind an explicit tag, which in CAP is
  every CHOICE-typed member. `decode` now fails instead. The cause is in
  `rasn` 0.28; the guard is in this crate and costs one extra encode per
  decode.
- **InitialDP** could not be decoded as real equipment sends it. `rasn` refuses
  a member it does not know, and `bearerCapability`, `subscriberState`,
  `ext-basicServiceCode`, `iPSSPCapabilities` and others were not modelled.

### Added
- Every member of every argument through Release 18, including `Extensions`,
  the event-specific information of all detection points, the phase 4 criteria
  (`MidCallControlInfo`, change of position), `InitialDPArgExtension`,
  `ServiceInteractionIndicatorsTwo`, `LocationInformationGPRS`.
- The CAMEL types carried inside the charging OCTET STRINGs:
  `CamelAChBillingChargingCharacteristics` (phase 4, `audibleIndicator`) and
  `CamelAChBillingChargingCharacteristicsV3` (phase 3, `tone`), which differ on
  the wire; `CamelCallResult`; `CamelFciBillingChargingCharacteristics`.
- `new(..)` constructors on the arguments with a mandatory member.
- Application-context constants for all fifteen contexts and helpers for the
  gprsSSF and gsmSCF-initiated contexts.
- `CancelArg::CallSegmentToCancel`.
- Python: `BcsmEvent(sending_side_id=..., receiving_side_id=...,
  application_timer=...)`, `EventReportBcsmArg(receiving_side_id=...,
  message_type=...)`, `ApplyChargingArg.time_duration(...)`,
  `cap_gsmsrf_scf()`.

### Changed
- `EventTypeBcsm`, `BcsmEvent`, `ConnectToResourceArg`, `PlayAnnouncementArg`
  and `PromptAndCollectUserInformationArg` are defined in this crate from TS
  29.078 instead of being re-exported from `inap`: CAP has more event types and
  members than INAP CS-1, and the re-exported definitions carried the tagging
  mistakes listed above. `MonitorMode`, the PromptAndCollectUserInformation
  result and the address aliases are still re-exported.
- `application_context::cap_*` return `Option<ObjectIdentifier>`; `None` for a
  phase that has no such context. An unknown phase no longer falls back to
  phase 3.
- `decode` requires `T: Encode` as well as `Decode`.
- `PlayAnnouncementArg::request_announcement_complete` is
  `request_announcement_complete_notification`, the ASN.1 name.
- Python: `BcsmEvent.leg_id`, `EventReportBcsmArg.leg_id` and
  `EventReportBcsmArg.misc_call_info` are replaced by the members above; the
  application-context helpers return `None` instead of a wrong value.

### Known limits
- Checked against Wireshark 4.6, whose CAP module is the Release 7 one. Three
  later additions have no independent decoder and are pinned by byte vectors
  only: `collectedInfoSpecificInfo` in `DpSpecificInfoAlt`,
  `userCSGInformation` in `LocationInformationGPRS`, and a
  `DpSpecificCriteriaAlt` without `changeOfPositionControlInfo`.
- `releaseCall` with extensions (the `[2]` alternative added in Release 6) is
  not modelled.
- A member added by a release after 18 is refused, not skipped.

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
