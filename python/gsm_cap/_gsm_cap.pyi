"""Type stubs for the Rust-backed ``gsm_cap._gsm_cap`` extension module.

CAMEL Application Part (CAP) operation codec, 3GPP TS 29.078. Each operation
argument is built from keyword fields (``bytes`` in their ITU-T / 3GPP wire
format), encoded with ``.encode() -> bytes``, and recovered with the
``decode(bytes)`` classmethod.
"""

from __future__ import annotations

from typing import Optional

# ── Operation codes (3GPP TS 29.078) ─────────────────────────────────────────
INITIAL_DP: int
CONNECT: int
RELEASE_CALL: int
REQUEST_REPORT_BCSM_EVENT: int
EVENT_REPORT_BCSM: int
APPLY_CHARGING: int
INITIAL_DP_SMS: int
CONNECT_SMS: int

class CapCodecError(Exception):
    """CAP operation encode/decode error (3GPP TS 29.078)."""

class EventTypeBcsm:
    """EventTypeBCSM — Basic Call State Model detection-point events.

    A PyO3 enum: members compare equal to their on-wire ASN.1 ENUMERATED integer
    (``int(...)`` yields the wire value), but it is not a Python ``enum.IntEnum``.
    """

    CollectedInfo: EventTypeBcsm
    AnalysedInformation: EventTypeBcsm
    RouteSelectFailure: EventTypeBcsm
    OCalledPartyBusy: EventTypeBcsm
    ONoAnswer: EventTypeBcsm
    OAnswer: EventTypeBcsm
    OMidCall: EventTypeBcsm
    ODisconnect: EventTypeBcsm
    OAbandon: EventTypeBcsm
    TermAttemptAuthorized: EventTypeBcsm
    TBusy: EventTypeBcsm
    TNoAnswer: EventTypeBcsm
    TAnswer: EventTypeBcsm
    TMidCall: EventTypeBcsm
    TDisconnect: EventTypeBcsm
    TAbandon: EventTypeBcsm
    OTermSeized: EventTypeBcsm
    CallAccepted: EventTypeBcsm
    OChangeOfPosition: EventTypeBcsm
    TChangeOfPosition: EventTypeBcsm
    OServiceChange: EventTypeBcsm
    TServiceChange: EventTypeBcsm
    def __int__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class MonitorMode:
    """MonitorMode — how a detection point should be reported."""

    Interrupted: MonitorMode
    NotifyAndContinue: MonitorMode
    Transparent: MonitorMode
    def __int__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class EventTypeSms:
    """EventTypeSMS — SMS detection-point events."""

    SmsCollectedInfo: EventTypeSms
    OSmsFailure: EventTypeSms
    OSmsSubmission: EventTypeSms
    SmsDeliveryRequested: EventTypeSms
    TSmsFailure: EventTypeSms
    TSmsDelivery: EventTypeSms
    def __int__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class BcsmEvent:
    """One event detection-point configuration entry.

    ``legID`` is a CHOICE on the wire: pass the one-octet leg (``b"\\x01"`` or
    ``b"\\x02"``) as ``sending_side_id`` (what a gsmSCF uses) or as
    ``receiving_side_id``, never both (``ValueError``). ``application_timer``
    is the no-answer timer in seconds.
    """

    event_type_bcsm: EventTypeBcsm
    monitor_mode: MonitorMode
    sending_side_id: Optional[bytes]
    receiving_side_id: Optional[bytes]
    application_timer: Optional[int]
    def __init__(
        self,
        event_type_bcsm: EventTypeBcsm,
        monitor_mode: MonitorMode,
        *,
        sending_side_id: Optional[bytes] = ...,
        receiving_side_id: Optional[bytes] = ...,
        application_timer: Optional[int] = ...,
    ) -> None: ...

class InitialDpArg:
    """InitialDP argument (op 0) — gsmSSF → gsmSCF."""

    service_key: int
    called_party_number: Optional[bytes]
    calling_party_number: Optional[bytes]
    event_type_bcsm: Optional[EventTypeBcsm]
    imsi: Optional[bytes]
    call_reference_number: Optional[bytes]
    msc_address: Optional[bytes]
    def __init__(
        self,
        service_key: int,
        *,
        called_party_number: Optional[bytes] = ...,
        calling_party_number: Optional[bytes] = ...,
        event_type_bcsm: Optional[EventTypeBcsm] = ...,
        imsi: Optional[bytes] = ...,
        call_reference_number: Optional[bytes] = ...,
        msc_address: Optional[bytes] = ...,
    ) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> InitialDpArg: ...

class ConnectArg:
    """Connect argument (op 20) — gsmSCF → gsmSSF."""

    destination_routing_address: list[bytes]
    def __init__(self, destination_routing_address: list[bytes]) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> ConnectArg: ...

class ReleaseCallArg:
    """ReleaseCall argument (op 22) — gsmSCF → gsmSSF, Q.850 cause."""

    cause: bytes
    def __init__(self, cause: bytes) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> ReleaseCallArg: ...

class RequestReportBcsmEventArg:
    """RequestReportBCSMEvent argument (op 23) — gsmSCF → gsmSSF."""

    bcsm_events: list[BcsmEvent]
    def __init__(self, bcsm_events: list[BcsmEvent]) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> RequestReportBcsmEventArg: ...

class EventReportBcsmArg:
    """EventReportBCSM argument (op 24) — gsmSSF → gsmSCF.

    ``receiving_side_id`` is the one-octet leg the event concerns.
    ``message_type`` is 0 (request) or 1 (notification); ``None`` leaves
    ``miscCallInfo`` out, which means request.
    """

    event_type_bcsm: EventTypeBcsm
    receiving_side_id: Optional[bytes]
    message_type: Optional[int]
    def __init__(
        self,
        event_type_bcsm: EventTypeBcsm,
        *,
        receiving_side_id: Optional[bytes] = ...,
        message_type: Optional[int] = ...,
    ) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> EventReportBcsmArg: ...

class ApplyChargingArg:
    """ApplyCharging argument (op 35) — gsmSCF → gsmSSF.

    ``ach_billing_charging_characteristics`` is the BER encoding of a
    CAMEL-AChBillingChargingCharacteristics value; :meth:`time_duration` builds
    it. ``party_to_charge`` is the one-octet leg, sent as ``sendingSideID``.
    """

    ach_billing_charging_characteristics: bytes
    party_to_charge: Optional[bytes]
    def __init__(
        self,
        ach_billing_charging_characteristics: bytes,
        *,
        party_to_charge: Optional[bytes] = ...,
    ) -> None: ...
    @staticmethod
    def time_duration(
        max_call_period_duration: int,
        *,
        cap_version: int,
        release_if_duration_exceeded: Optional[bool] = ...,
        tariff_switch_interval: Optional[int] = ...,
        tone: Optional[bool] = ...,
        party_to_charge: Optional[bytes] = ...,
    ) -> ApplyChargingArg:
        """Time-duration charging for a CAP phase 3 or phase 4 dialogue.

        ``max_call_period_duration`` is in 100 ms units. The warning tone is
        encoded differently in the two phases, hence ``cap_version``.
        """
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> ApplyChargingArg: ...

class InitialDpSmsArg:
    """InitialDPSMS argument (op 60) — gsmSSF → gsmSCF (CAMEL-for-SMS)."""

    service_key: int
    destination_subscriber_number: Optional[bytes]
    calling_party_number: Optional[bytes]
    event_type_sms: Optional[EventTypeSms]
    imsi: Optional[bytes]
    smsc_address: Optional[bytes]
    def __init__(
        self,
        service_key: int,
        *,
        destination_subscriber_number: Optional[bytes] = ...,
        calling_party_number: Optional[bytes] = ...,
        event_type_sms: Optional[EventTypeSms] = ...,
        imsi: Optional[bytes] = ...,
        smsc_address: Optional[bytes] = ...,
    ) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> InitialDpSmsArg: ...

def operation_name(code: int) -> Optional[str]:
    """Name of a well-known CAP operation code (e.g. ``0 -> "initialDP"``)."""

def cap_gsmssf_scf_generic(version: int) -> Optional[list[int]]:
    """gsmSSF-scfGenericAC application-context OID arcs for a CAP phase (1..=4).

    ``None`` for a phase that does not exist.
    """

def cap_sms_ac(version: int) -> Optional[list[int]]:
    """SMS control application-context OID arcs (CAP phase 3 or 4).

    ``None`` for phases 1 and 2, which have no SMS control.
    """

def cap_gsmsrf_scf(version: int) -> Optional[list[int]]:
    """gsmSRF-gsmSCF application-context OID arcs (CAP phase 2, 3 or 4).

    ``None`` for phase 1, which has no such context.
    """
