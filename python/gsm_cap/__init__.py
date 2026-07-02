"""gsm_cap — Rust-backed CAMEL Application Part (CAP) operation codec for Python.

CAP (3GPP TS 29.078) is the ASN.1 operation set that drives CAMEL Intelligent
Network services — prepaid call control, service triggering, charging, and
CAMEL-for-SMS — between the gsmSSF and the gsmSCF. This package exposes the same
BER codec the Rust crate (``cargo add gsm_cap``) ships, from one source tree /
one version.

The wire work (rasn BER encode/decode of the CAP argument types) runs in Rust;
Python just builds and inspects operation arguments. Each operation type has an
``.encode() -> bytes`` method and a ``decode(bytes)`` classmethod. Values are
carried as ``bytes`` in their respective ITU-T / 3GPP wire formats.

Covered: the call-control set (InitialDP, Connect, ReleaseCall,
RequestReportBCSMEvent, EventReportBCSM, ApplyCharging) plus CAMEL-for-SMS
(InitialDPSMS), the shared enums, the operation codes, and the
application-context OID helpers. CAP rides on TCAP over SCCP; wrapping these
arguments in a TCAP Invoke is the caller's job.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._gsm_cap import (
    APPLY_CHARGING,
    CONNECT,
    CONNECT_SMS,
    EVENT_REPORT_BCSM,
    INITIAL_DP,
    INITIAL_DP_SMS,
    RELEASE_CALL,
    REQUEST_REPORT_BCSM_EVENT,
    ApplyChargingArg,
    BcsmEvent,
    CapCodecError,
    ConnectArg,
    EventReportBcsmArg,
    EventTypeBcsm,
    EventTypeSms,
    InitialDpArg,
    InitialDpSmsArg,
    MonitorMode,
    ReleaseCallArg,
    RequestReportBcsmEventArg,
    cap_gsmssf_scf_generic,
    cap_sms_ac,
    operation_name,
)

try:
    __version__ = version("gsm_cap")
except PackageNotFoundError:  # running from a source checkout without an installed dist
    __version__ = "0.0.0+unknown"

__all__ = [
    # operation arguments
    "InitialDpArg",
    "ConnectArg",
    "ReleaseCallArg",
    "RequestReportBcsmEventArg",
    "EventReportBcsmArg",
    "ApplyChargingArg",
    "InitialDpSmsArg",
    # shared types / enums
    "BcsmEvent",
    "EventTypeBcsm",
    "MonitorMode",
    "EventTypeSms",
    # error
    "CapCodecError",
    # helpers
    "operation_name",
    "cap_gsmssf_scf_generic",
    "cap_sms_ac",
    # operation codes
    "INITIAL_DP",
    "CONNECT",
    "RELEASE_CALL",
    "REQUEST_REPORT_BCSM_EVENT",
    "EVENT_REPORT_BCSM",
    "APPLY_CHARGING",
    "INITIAL_DP_SMS",
    "CONNECT_SMS",
    "__version__",
]
