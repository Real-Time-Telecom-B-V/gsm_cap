//! PyO3 bindings — `pip install gsm_cap` gives a Rust-backed wheel exposing the
//! **same** CAMEL Application Part (CAP) operation codec the crate ships.
//!
//! Compiled only with `--features python`; the default crate build is pyo3-free, so
//! `cargo add gsm_cap` / crates.io consumers pull zero pyo3. Two entry points share
//! one `add_contents()`:
//! * `#[pymodule] fn _gsm_cap` — the standalone wheel (maturin `module-name`).
//! * `pub fn register(py, parent)` — mount `gsm_cap` as a submodule of another
//!   extension, so a host (e.g. a TCAP stack) can expose gsm_cap without a second
//!   shared object.
//!
//! The Python surface mirrors the Rust one: each call-control / SMS operation type
//! is a pyclass with `.encode() -> bytes` and a `decode(bytes)` classmethod, both
//! backed by the crate's `rasn` BER codec. The shared enums
//! (`EventTypeBcsm` / `MonitorMode` / `EventTypeSms`), the `op_codes` (+
//! `operation_name`), and the application-context OID helpers are exposed too.
//!
//! Coverage: the call-control set (InitialDP, Connect, ReleaseCall,
//! RequestReportBCSMEvent, EventReportBCSM, ApplyCharging) plus CAMEL-for-SMS
//! (InitialDPSMS). Result types and the specialised-resource ops are Rust-only for
//! now (see `operations` / the README).

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use rasn::types::Integer;

use crate::application_context as ac;
use crate::op_codes;
use crate::operations::{
    ApplyChargingArg, ConnectArg, EventReportBcsmArg, InitialDpArg, InitialDpSmsArg,
    ReleaseCallArg, RequestReportBcsmEventArg,
};
use crate::types::{BcsmEvent, EventTypeBcsm, EventTypeSms, MonitorMode};
use crate::CapError;

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    gsm_cap,
    CapCodecError,
    PyException,
    "CAP operation encode/decode error (3GPP TS 29.078)."
);

fn cap_err(e: CapError) -> PyErr {
    CapCodecError::new_err(e.to_string())
}

/// `Vec<u8>` → owned Python `bytes`.
fn to_pybytes<'py>(py: Python<'py>, v: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, v)
}

// ── Shared enums ─────────────────────────────────────────────────────────────

/// EventTypeBCSM — Basic Call State Model detection-point events. Integer values
/// are the on-wire ASN.1 ENUMERATED encoding (`OAnswer == 7`).
#[pyclass(
    name = "EventTypeBcsm",
    module = "gsm_cap._gsm_cap",
    eq,
    eq_int,
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyEventTypeBcsm {
    CollectedInfo = 2,
    AnalysedInformation = 3,
    RouteSelectFailure = 4,
    OCalledPartyBusy = 5,
    ONoAnswer = 6,
    OAnswer = 7,
    ODisconnect = 9,
    OAbandon = 10,
    TermAttemptAuthorized = 12,
    TBusy = 13,
    TNoAnswer = 14,
    TAnswer = 15,
    TDisconnect = 17,
    TAbandon = 18,
}

impl PyEventTypeBcsm {
    fn to_core(self) -> EventTypeBcsm {
        match self {
            PyEventTypeBcsm::CollectedInfo => EventTypeBcsm::CollectedInfo,
            PyEventTypeBcsm::AnalysedInformation => EventTypeBcsm::AnalysedInformation,
            PyEventTypeBcsm::RouteSelectFailure => EventTypeBcsm::RouteSelectFailure,
            PyEventTypeBcsm::OCalledPartyBusy => EventTypeBcsm::OCalledPartyBusy,
            PyEventTypeBcsm::ONoAnswer => EventTypeBcsm::ONoAnswer,
            PyEventTypeBcsm::OAnswer => EventTypeBcsm::OAnswer,
            PyEventTypeBcsm::ODisconnect => EventTypeBcsm::ODisconnect,
            PyEventTypeBcsm::OAbandon => EventTypeBcsm::OAbandon,
            PyEventTypeBcsm::TermAttemptAuthorized => EventTypeBcsm::TermAttemptAuthorized,
            PyEventTypeBcsm::TBusy => EventTypeBcsm::TBusy,
            PyEventTypeBcsm::TNoAnswer => EventTypeBcsm::TNoAnswer,
            PyEventTypeBcsm::TAnswer => EventTypeBcsm::TAnswer,
            PyEventTypeBcsm::TDisconnect => EventTypeBcsm::TDisconnect,
            PyEventTypeBcsm::TAbandon => EventTypeBcsm::TAbandon,
        }
    }

    fn from_core(e: EventTypeBcsm) -> Self {
        match e {
            EventTypeBcsm::CollectedInfo => PyEventTypeBcsm::CollectedInfo,
            EventTypeBcsm::AnalysedInformation => PyEventTypeBcsm::AnalysedInformation,
            EventTypeBcsm::RouteSelectFailure => PyEventTypeBcsm::RouteSelectFailure,
            EventTypeBcsm::OCalledPartyBusy => PyEventTypeBcsm::OCalledPartyBusy,
            EventTypeBcsm::ONoAnswer => PyEventTypeBcsm::ONoAnswer,
            EventTypeBcsm::OAnswer => PyEventTypeBcsm::OAnswer,
            EventTypeBcsm::ODisconnect => PyEventTypeBcsm::ODisconnect,
            EventTypeBcsm::OAbandon => PyEventTypeBcsm::OAbandon,
            EventTypeBcsm::TermAttemptAuthorized => PyEventTypeBcsm::TermAttemptAuthorized,
            EventTypeBcsm::TBusy => PyEventTypeBcsm::TBusy,
            EventTypeBcsm::TNoAnswer => PyEventTypeBcsm::TNoAnswer,
            EventTypeBcsm::TAnswer => PyEventTypeBcsm::TAnswer,
            EventTypeBcsm::TDisconnect => PyEventTypeBcsm::TDisconnect,
            EventTypeBcsm::TAbandon => PyEventTypeBcsm::TAbandon,
        }
    }
}

/// MonitorMode — how a detection point should be reported.
#[pyclass(
    name = "MonitorMode",
    module = "gsm_cap._gsm_cap",
    eq,
    eq_int,
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyMonitorMode {
    Interrupted = 0,
    NotifyAndContinue = 1,
    Transparent = 2,
}

impl PyMonitorMode {
    fn to_core(self) -> MonitorMode {
        match self {
            PyMonitorMode::Interrupted => MonitorMode::Interrupted,
            PyMonitorMode::NotifyAndContinue => MonitorMode::NotifyAndContinue,
            PyMonitorMode::Transparent => MonitorMode::Transparent,
        }
    }
}

/// EventTypeSMS — SMS detection-point events.
#[pyclass(
    name = "EventTypeSms",
    module = "gsm_cap._gsm_cap",
    eq,
    eq_int,
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyEventTypeSms {
    SmsCollectedInfo = 1,
    OSmsFailure = 2,
    OSmsSubmission = 3,
    SmsDeliveryRequested = 11,
    TSmsFailure = 12,
    TSmsDelivery = 13,
}

impl PyEventTypeSms {
    fn to_core(self) -> EventTypeSms {
        match self {
            PyEventTypeSms::SmsCollectedInfo => EventTypeSms::SmsCollectedInfo,
            PyEventTypeSms::OSmsFailure => EventTypeSms::OSmsFailure,
            PyEventTypeSms::OSmsSubmission => EventTypeSms::OSmsSubmission,
            PyEventTypeSms::SmsDeliveryRequested => EventTypeSms::SmsDeliveryRequested,
            PyEventTypeSms::TSmsFailure => EventTypeSms::TSmsFailure,
            PyEventTypeSms::TSmsDelivery => EventTypeSms::TSmsDelivery,
        }
    }

    fn from_core(e: EventTypeSms) -> Self {
        match e {
            EventTypeSms::SmsCollectedInfo => PyEventTypeSms::SmsCollectedInfo,
            EventTypeSms::OSmsFailure => PyEventTypeSms::OSmsFailure,
            EventTypeSms::OSmsSubmission => PyEventTypeSms::OSmsSubmission,
            EventTypeSms::SmsDeliveryRequested => PyEventTypeSms::SmsDeliveryRequested,
            EventTypeSms::TSmsFailure => PyEventTypeSms::TSmsFailure,
            EventTypeSms::TSmsDelivery => PyEventTypeSms::TSmsDelivery,
        }
    }
}

/// BCSMEvent — one event detection-point configuration entry for
/// [`PyRequestReportBcsmEventArg`].
#[pyclass(name = "BcsmEvent", module = "gsm_cap._gsm_cap", from_py_object)]
#[derive(Clone)]
pub struct PyBcsmEvent {
    #[pyo3(get)]
    pub event_type_bcsm: PyEventTypeBcsm,
    #[pyo3(get)]
    pub monitor_mode: PyMonitorMode,
    leg_id: Option<Vec<u8>>,
}

#[pymethods]
impl PyBcsmEvent {
    #[new]
    #[pyo3(signature = (event_type_bcsm, monitor_mode, *, leg_id = None))]
    fn new(
        event_type_bcsm: PyEventTypeBcsm,
        monitor_mode: PyMonitorMode,
        leg_id: Option<Vec<u8>>,
    ) -> Self {
        Self {
            event_type_bcsm,
            monitor_mode,
            leg_id,
        }
    }

    #[getter]
    fn leg_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.leg_id.as_ref().map(|v| to_pybytes(py, v))
    }

    fn __repr__(&self) -> String {
        format!(
            "BcsmEvent(event_type_bcsm={:?}, monitor_mode={:?})",
            self.event_type_bcsm as i64, self.monitor_mode as i64
        )
    }
}

impl PyBcsmEvent {
    fn to_core(&self) -> BcsmEvent {
        BcsmEvent {
            event_type_bcsm: self.event_type_bcsm.to_core(),
            monitor_mode: self.monitor_mode.to_core(),
            leg_id: self.leg_id.clone().map(Into::into),
        }
    }
}

// ── InitialDP (op 0) ─────────────────────────────────────────────────────────

/// InitialDP argument — gsmSSF → gsmSCF, sent when a call hits a detection point.
/// Address / octet-string fields are `bytes` in their respective ITU-T / 3GPP
/// wire formats; all but `service_key` are optional.
#[pyclass(
    name = "InitialDpArg",
    module = "gsm_cap._gsm_cap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyInitialDpArg {
    #[pyo3(get)]
    pub service_key: i64,
    called_party_number: Option<Vec<u8>>,
    calling_party_number: Option<Vec<u8>>,
    event_type_bcsm: Option<PyEventTypeBcsm>,
    imsi: Option<Vec<u8>>,
    call_reference_number: Option<Vec<u8>>,
    msc_address: Option<Vec<u8>>,
}

#[pymethods]
impl PyInitialDpArg {
    #[new]
    #[pyo3(signature = (
        service_key,
        *,
        called_party_number = None,
        calling_party_number = None,
        event_type_bcsm = None,
        imsi = None,
        call_reference_number = None,
        msc_address = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        service_key: i64,
        called_party_number: Option<Vec<u8>>,
        calling_party_number: Option<Vec<u8>>,
        event_type_bcsm: Option<PyEventTypeBcsm>,
        imsi: Option<Vec<u8>>,
        call_reference_number: Option<Vec<u8>>,
        msc_address: Option<Vec<u8>>,
    ) -> Self {
        Self {
            service_key,
            called_party_number,
            calling_party_number,
            event_type_bcsm,
            imsi,
            call_reference_number,
            msc_address,
        }
    }

    #[getter]
    fn called_party_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.called_party_number.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn calling_party_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.calling_party_number
            .as_ref()
            .map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn event_type_bcsm(&self) -> Option<PyEventTypeBcsm> {
        self.event_type_bcsm
    }
    #[getter]
    fn imsi<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.imsi.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn call_reference_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.call_reference_number
            .as_ref()
            .map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn msc_address<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.msc_address.as_ref().map(|v| to_pybytes(py, v))
    }

    /// Encode the InitialDP argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = crate::encode(&self.to_core()).map_err(cap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an InitialDP argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: InitialDpArg = crate::decode(data).map_err(cap_err)?;
        Ok(Self::from_core(&core))
    }

    fn __repr__(&self) -> String {
        format!("InitialDpArg(service_key={})", self.service_key)
    }
}

impl PyInitialDpArg {
    fn to_core(&self) -> InitialDpArg {
        InitialDpArg {
            service_key: Integer::from(self.service_key),
            called_party_number: self.called_party_number.clone().map(Into::into),
            calling_party_number: self.calling_party_number.clone().map(Into::into),
            calling_partys_category: None,
            original_called_party_id: None,
            event_type_bcsm: self.event_type_bcsm.map(|e| e.to_core()),
            redirecting_party_id: None,
            imsi: self.imsi.clone().map(Into::into),
            location_information: None,
            call_reference_number: self.call_reference_number.clone().map(Into::into),
            msc_address: self.msc_address.clone().map(Into::into),
            called_party_bcd_number: None,
            time_and_timezone: None,
        }
    }

    fn from_core(c: &InitialDpArg) -> Self {
        Self {
            service_key: i64_from(&c.service_key),
            called_party_number: c.called_party_number.as_ref().map(|b| b.to_vec()),
            calling_party_number: c.calling_party_number.as_ref().map(|b| b.to_vec()),
            event_type_bcsm: c.event_type_bcsm.map(PyEventTypeBcsm::from_core),
            imsi: c.imsi.as_ref().map(|b| b.to_vec()),
            call_reference_number: c.call_reference_number.as_ref().map(|b| b.to_vec()),
            msc_address: c.msc_address.as_ref().map(|b| b.to_vec()),
        }
    }
}

// ── Connect (op 20) ──────────────────────────────────────────────────────────

/// Connect argument — gsmSCF → gsmSSF, route the call to one or more destination
/// addresses (`destination_routing_address`, a list of `bytes`).
#[pyclass(name = "ConnectArg", module = "gsm_cap._gsm_cap", skip_from_py_object)]
#[derive(Clone)]
pub struct PyConnectArg {
    destination_routing_address: Vec<Vec<u8>>,
}

#[pymethods]
impl PyConnectArg {
    #[new]
    fn new(destination_routing_address: Vec<Vec<u8>>) -> Self {
        Self {
            destination_routing_address,
        }
    }

    #[getter]
    fn destination_routing_address<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.destination_routing_address
            .iter()
            .map(|v| to_pybytes(py, v))
            .collect()
    }

    /// Encode the Connect argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = crate::encode(&self.to_core()).map_err(cap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode a Connect argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: ConnectArg = crate::decode(data).map_err(cap_err)?;
        Ok(Self {
            destination_routing_address: core
                .destination_routing_address
                .iter()
                .map(|b| b.to_vec())
                .collect(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "ConnectArg(destination_routing_address=[{} addr])",
            self.destination_routing_address.len()
        )
    }
}

impl PyConnectArg {
    fn to_core(&self) -> ConnectArg {
        ConnectArg {
            destination_routing_address: self
                .destination_routing_address
                .iter()
                .map(|v| v.clone().into())
                .collect(),
            original_called_party_id: None,
            calling_partys_category: None,
            redirecting_party_id: None,
            generic_numbers: None,
        }
    }
}

// ── ReleaseCall (op 22) ──────────────────────────────────────────────────────

/// ReleaseCall argument — gsmSCF → gsmSSF, release the call with a Q.850 cause.
#[pyclass(
    name = "ReleaseCallArg",
    module = "gsm_cap._gsm_cap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyReleaseCallArg {
    cause: Vec<u8>,
}

#[pymethods]
impl PyReleaseCallArg {
    #[new]
    fn new(cause: Vec<u8>) -> Self {
        Self { cause }
    }

    #[getter]
    fn cause<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        to_pybytes(py, &self.cause)
    }

    /// Encode the ReleaseCall argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = ReleaseCallArg {
            cause: self.cause.clone().into(),
        };
        let bytes = crate::encode(&core).map_err(cap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode a ReleaseCall argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: ReleaseCallArg = crate::decode(data).map_err(cap_err)?;
        Ok(Self {
            cause: core.cause.to_vec(),
        })
    }

    fn __repr__(&self) -> String {
        format!("ReleaseCallArg(cause={} bytes)", self.cause.len())
    }
}

// ── RequestReportBCSMEvent (op 23) ──────────────────────────────────────────

/// RequestReportBCSMEvent argument — gsmSCF → gsmSSF, arm a set of BCSM event
/// detection points (`bcsm_events`, a list of :class:`BcsmEvent`).
#[pyclass(
    name = "RequestReportBcsmEventArg",
    module = "gsm_cap._gsm_cap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyRequestReportBcsmEventArg {
    bcsm_events: Vec<PyBcsmEvent>,
}

#[pymethods]
impl PyRequestReportBcsmEventArg {
    #[new]
    fn new(bcsm_events: Vec<PyBcsmEvent>) -> Self {
        Self { bcsm_events }
    }

    #[getter]
    fn bcsm_events(&self) -> Vec<PyBcsmEvent> {
        self.bcsm_events.clone()
    }

    /// Encode the RequestReportBCSMEvent argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = RequestReportBcsmEventArg {
            bcsm_events: self.bcsm_events.iter().map(|e| e.to_core()).collect(),
        };
        let bytes = crate::encode(&core).map_err(cap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode a RequestReportBCSMEvent argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: RequestReportBcsmEventArg = crate::decode(data).map_err(cap_err)?;
        Ok(Self {
            bcsm_events: core
                .bcsm_events
                .iter()
                .map(|e| PyBcsmEvent {
                    event_type_bcsm: PyEventTypeBcsm::from_core(e.event_type_bcsm),
                    monitor_mode: match e.monitor_mode {
                        MonitorMode::Interrupted => PyMonitorMode::Interrupted,
                        MonitorMode::NotifyAndContinue => PyMonitorMode::NotifyAndContinue,
                        MonitorMode::Transparent => PyMonitorMode::Transparent,
                    },
                    leg_id: e.leg_id.as_ref().map(|b| b.to_vec()),
                })
                .collect(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "RequestReportBcsmEventArg(bcsm_events=[{} events])",
            self.bcsm_events.len()
        )
    }
}

// ── EventReportBCSM (op 24) ──────────────────────────────────────────────────

/// EventReportBCSM argument — gsmSSF → gsmSCF, report a BCSM event.
#[pyclass(
    name = "EventReportBcsmArg",
    module = "gsm_cap._gsm_cap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyEventReportBcsmArg {
    #[pyo3(get)]
    pub event_type_bcsm: PyEventTypeBcsm,
    leg_id: Option<Vec<u8>>,
    misc_call_info: Option<Vec<u8>>,
}

#[pymethods]
impl PyEventReportBcsmArg {
    #[new]
    #[pyo3(signature = (event_type_bcsm, *, leg_id = None, misc_call_info = None))]
    fn new(
        event_type_bcsm: PyEventTypeBcsm,
        leg_id: Option<Vec<u8>>,
        misc_call_info: Option<Vec<u8>>,
    ) -> Self {
        Self {
            event_type_bcsm,
            leg_id,
            misc_call_info,
        }
    }

    #[getter]
    fn leg_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.leg_id.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn misc_call_info<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.misc_call_info.as_ref().map(|v| to_pybytes(py, v))
    }

    /// Encode the EventReportBCSM argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = EventReportBcsmArg {
            event_type_bcsm: self.event_type_bcsm.to_core(),
            leg_id: self.leg_id.clone().map(Into::into),
            misc_call_info: self.misc_call_info.clone().map(Into::into),
        };
        let bytes = crate::encode(&core).map_err(cap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an EventReportBCSM argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: EventReportBcsmArg = crate::decode(data).map_err(cap_err)?;
        Ok(Self {
            event_type_bcsm: PyEventTypeBcsm::from_core(core.event_type_bcsm),
            leg_id: core.leg_id.as_ref().map(|b| b.to_vec()),
            misc_call_info: core.misc_call_info.as_ref().map(|b| b.to_vec()),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "EventReportBcsmArg(event_type_bcsm={})",
            self.event_type_bcsm as i64
        )
    }
}

// ── ApplyCharging (op 35) ────────────────────────────────────────────────────

/// ApplyCharging argument — gsmSCF → gsmSSF, install charging characteristics.
#[pyclass(
    name = "ApplyChargingArg",
    module = "gsm_cap._gsm_cap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyApplyChargingArg {
    ach_billing_charging_characteristics: Vec<u8>,
    party_to_charge: Option<Vec<u8>>,
}

#[pymethods]
impl PyApplyChargingArg {
    #[new]
    #[pyo3(signature = (ach_billing_charging_characteristics, *, party_to_charge = None))]
    fn new(
        ach_billing_charging_characteristics: Vec<u8>,
        party_to_charge: Option<Vec<u8>>,
    ) -> Self {
        Self {
            ach_billing_charging_characteristics,
            party_to_charge,
        }
    }

    #[getter]
    fn ach_billing_charging_characteristics<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        to_pybytes(py, &self.ach_billing_charging_characteristics)
    }
    #[getter]
    fn party_to_charge<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.party_to_charge.as_ref().map(|v| to_pybytes(py, v))
    }

    /// Encode the ApplyCharging argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = ApplyChargingArg {
            ach_billing_charging_characteristics: self
                .ach_billing_charging_characteristics
                .clone()
                .into(),
            party_to_charge: self.party_to_charge.clone().map(Into::into),
        };
        let bytes = crate::encode(&core).map_err(cap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an ApplyCharging argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: ApplyChargingArg = crate::decode(data).map_err(cap_err)?;
        Ok(Self {
            ach_billing_charging_characteristics: core
                .ach_billing_charging_characteristics
                .to_vec(),
            party_to_charge: core.party_to_charge.as_ref().map(|b| b.to_vec()),
        })
    }

    fn __repr__(&self) -> String {
        "ApplyChargingArg(..)".to_string()
    }
}

// ── InitialDPSMS (op 60) ─────────────────────────────────────────────────────

/// InitialDPSMS argument — gsmSSF → gsmSCF for CAMEL-for-SMS (CAP v3+): a
/// triggered MO/MT short message reported to the SCP.
#[pyclass(
    name = "InitialDpSmsArg",
    module = "gsm_cap._gsm_cap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyInitialDpSmsArg {
    #[pyo3(get)]
    pub service_key: i64,
    destination_subscriber_number: Option<Vec<u8>>,
    calling_party_number: Option<Vec<u8>>,
    event_type_sms: Option<PyEventTypeSms>,
    imsi: Option<Vec<u8>>,
    smsc_address: Option<Vec<u8>>,
}

#[pymethods]
impl PyInitialDpSmsArg {
    #[new]
    #[pyo3(signature = (
        service_key,
        *,
        destination_subscriber_number = None,
        calling_party_number = None,
        event_type_sms = None,
        imsi = None,
        smsc_address = None,
    ))]
    fn new(
        service_key: i64,
        destination_subscriber_number: Option<Vec<u8>>,
        calling_party_number: Option<Vec<u8>>,
        event_type_sms: Option<PyEventTypeSms>,
        imsi: Option<Vec<u8>>,
        smsc_address: Option<Vec<u8>>,
    ) -> Self {
        Self {
            service_key,
            destination_subscriber_number,
            calling_party_number,
            event_type_sms,
            imsi,
            smsc_address,
        }
    }

    #[getter]
    fn destination_subscriber_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.destination_subscriber_number
            .as_ref()
            .map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn calling_party_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.calling_party_number
            .as_ref()
            .map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn event_type_sms(&self) -> Option<PyEventTypeSms> {
        self.event_type_sms
    }
    #[getter]
    fn imsi<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.imsi.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn smsc_address<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.smsc_address.as_ref().map(|v| to_pybytes(py, v))
    }

    /// Encode the InitialDPSMS argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = crate::encode(&self.to_core()).map_err(cap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an InitialDPSMS argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: InitialDpSmsArg = crate::decode(data).map_err(cap_err)?;
        Ok(Self {
            service_key: i64_from(&core.service_key),
            destination_subscriber_number: core
                .destination_subscriber_number
                .as_ref()
                .map(|b| b.to_vec()),
            calling_party_number: core.calling_party_number.as_ref().map(|b| b.to_vec()),
            event_type_sms: core.event_type_sms.map(PyEventTypeSms::from_core),
            imsi: core.imsi.as_ref().map(|b| b.to_vec()),
            smsc_address: core.smsc_address.as_ref().map(|b| b.to_vec()),
        })
    }

    fn __repr__(&self) -> String {
        format!("InitialDpSmsArg(service_key={})", self.service_key)
    }
}

impl PyInitialDpSmsArg {
    fn to_core(&self) -> InitialDpSmsArg {
        InitialDpSmsArg {
            service_key: Integer::from(self.service_key),
            destination_subscriber_number: self
                .destination_subscriber_number
                .clone()
                .map(Into::into),
            calling_party_number: self.calling_party_number.clone().map(Into::into),
            event_type_sms: self.event_type_sms.map(|e| e.to_core()),
            imsi: self.imsi.clone().map(Into::into),
            location_information_msc: None,
            smsc_address: self.smsc_address.clone().map(Into::into),
            time_and_timezone: None,
            tp_short_message_specific_info: None,
            tp_protocol_identifier: None,
            tp_data_coding_scheme: None,
            tp_validity_period: None,
            sms_reference_number: None,
            msc_address: None,
            sgsn_number: None,
            ms_classmark2: None,
        }
    }
}

// ── op_codes + application contexts (module-level fns) ───────────────────────

/// The name of a well-known CAP operation code, if any (e.g. `0 -> "initialDP"`).
#[pyfunction]
fn operation_name(code: i64) -> Option<&'static str> {
    op_codes::operation_name(code)
}

/// CAP application-context OID as a tuple of arcs — gsmSSF-scfGenericAC
/// (call control) for the given phase (1..=4).
#[pyfunction]
fn cap_gsmssf_scf_generic(version: u32) -> Vec<u32> {
    ac::cap_gsmssf_scf_generic(version)
        .iter()
        .copied()
        .collect()
}

/// CAP application-context OID as a tuple of arcs — cap-sms-AC (SMS control).
#[pyfunction]
fn cap_sms_ac(version: u32) -> Vec<u32> {
    ac::cap_sms_ac(version).iter().copied().collect()
}

// ── i64 <- Integer helper ────────────────────────────────────────────────────
fn i64_from(v: &Integer) -> i64 {
    // ServiceKey is a small non-negative INTEGER in practice; fall back to 0 on
    // the (never-hit, synthetic-data) overflow path rather than panic.
    i64::try_from(v).unwrap_or(0)
}

// ── Module wiring ────────────────────────────────────────────────────────────
fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("CapCodecError", m.py().get_type::<CapCodecError>())?;

    // Enums.
    m.add_class::<PyEventTypeBcsm>()?;
    m.add_class::<PyMonitorMode>()?;
    m.add_class::<PyEventTypeSms>()?;
    m.add_class::<PyBcsmEvent>()?;

    // Operation arguments.
    m.add_class::<PyInitialDpArg>()?;
    m.add_class::<PyConnectArg>()?;
    m.add_class::<PyReleaseCallArg>()?;
    m.add_class::<PyRequestReportBcsmEventArg>()?;
    m.add_class::<PyEventReportBcsmArg>()?;
    m.add_class::<PyApplyChargingArg>()?;
    m.add_class::<PyInitialDpSmsArg>()?;

    // Helpers.
    m.add_function(wrap_pyfunction!(operation_name, m)?)?;
    m.add_function(wrap_pyfunction!(cap_gsmssf_scf_generic, m)?)?;
    m.add_function(wrap_pyfunction!(cap_sms_ac, m)?)?;

    // Operation codes (3GPP TS 29.078).
    m.add("INITIAL_DP", op_codes::INITIAL_DP)?;
    m.add("CONNECT", op_codes::CONNECT)?;
    m.add("RELEASE_CALL", op_codes::RELEASE_CALL)?;
    m.add(
        "REQUEST_REPORT_BCSM_EVENT",
        op_codes::REQUEST_REPORT_BCSM_EVENT,
    )?;
    m.add("EVENT_REPORT_BCSM", op_codes::EVENT_REPORT_BCSM)?;
    m.add("APPLY_CHARGING", op_codes::APPLY_CHARGING)?;
    m.add("INITIAL_DP_SMS", op_codes::INITIAL_DP_SMS)?;
    m.add("CONNECT_SMS", op_codes::CONNECT_SMS)?;

    Ok(())
}

/// Standalone wheel entry point (maturin `module-name = "gsm_cap._gsm_cap"`).
#[pymodule]
fn _gsm_cap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Embedding entry point: build a `gsm_cap` submodule and attach it to `parent`,
/// so a host extension can expose gsm_cap without a second shared object.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "gsm_cap")?;
    add_contents(&m)?;
    parent.setattr("gsm_cap", &m)?;
    Ok(())
}
