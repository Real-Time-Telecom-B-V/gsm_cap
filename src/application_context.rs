//! CAP application-context names.
//!
//! An application context names the operation set and CAMEL phase a TCAP
//! dialogue uses; it travels in the AARQ / AARE of the dialogue portion.
//!
//! Sources, one per phase, each read from the published ASN.1:
//!
//! * phase 1: GSM 09.78 V5.7.0 (Release 1996), clause 6.
//! * phase 2: GSM 09.78 V7.1.0 (Release 1998), clause 6.
//! * phase 3: 3GPP TS 29.078 V3.16.0 (Release 1999), clause 5.6
//!   (`CAP-object-identifiers`).
//! * phase 4: 3GPP TS 29.078 V18.0.0 (Release 18), clause 5.6.
//!
//! Phases 1 and 2 hang off the GSM application-context arc, one arc per
//! context plus a version arc:
//!
//! ```text
//!   {itu-t(0) identified-organization(4) etsi(0) mobileDomain(0)
//!    gsm-Network(1) ac(0) <context> <version>}
//! ```
//!
//! Phases 3 and 4 hang off four CAP roots under `umts-network(1)`, and which
//! root a context uses is not uniform:
//!
//! ```text
//!   id-CAP3   = 0.4.0.0.1.20     id-CAP3OE = 0.4.0.0.1.21
//!   id-CAP    = 0.4.0.0.1.22     id-CAPOE  = 0.4.0.0.1.23     (phase 4)
//!   application contexts sit under <root> ac(3)
//! ```
//!
//! The gsmSRF context is `{id-ac 14}` (roots 20 and 22), every other context
//! is under the `OE` roots (21 and 23). The GPRS contexts kept their phase 3
//! value in phase 4.
//!
//! Wireshark's CAMEL dissector registers the same fifteen values, which is the
//! second source the tests check against.

use rasn::types::ObjectIdentifier;

/// CAP phase 1.
pub const CAP_V1: u32 = 1;
/// CAP phase 2.
pub const CAP_V2: u32 = 2;
/// CAP phase 3.
pub const CAP_V3: u32 = 3;
/// CAP phase 4.
pub const CAP_V4: u32 = 4;

/// `CAP-v1-gsmSSF-to-gsmSCF-AC`.
pub const CAP_V1_GSMSSF_TO_GSMSCF: [u32; 8] = [0, 4, 0, 0, 1, 0, 50, 0];
/// `CAP-v2-gsmSSF-to-gsmSCF-AC`.
pub const CAP_V2_GSMSSF_TO_GSMSCF: [u32; 8] = [0, 4, 0, 0, 1, 0, 50, 1];
/// `CAP-v2-assist-gsmSSF-to-gsmSCF-AC`.
pub const CAP_V2_ASSIST_GSMSSF_TO_GSMSCF: [u32; 8] = [0, 4, 0, 0, 1, 0, 51, 1];
/// `CAP-v2-gsmSRF-to-gsmSCF-AC`.
pub const CAP_V2_GSMSRF_TO_GSMSCF: [u32; 8] = [0, 4, 0, 0, 1, 0, 52, 1];

/// Phase 3 `id-ac-CAP-gsmSSF-scfGenericAC`, `{id-acE 4}`.
pub const CAP_V3_GSMSSF_SCF_GENERIC: [u32; 8] = [0, 4, 0, 0, 1, 21, 3, 4];
/// Phase 3 `id-ac-CAP-gsmSSF-scfAssistHandoffAC`, `{id-acE 6}`.
pub const CAP_V3_GSMSSF_SCF_ASSIST_HANDOFF: [u32; 8] = [0, 4, 0, 0, 1, 21, 3, 6];
/// Phase 3 `id-ac-gsmSRF-gsmSCF`, `{id-ac 14}`.
pub const CAP_V3_GSMSRF_GSMSCF: [u32; 8] = [0, 4, 0, 0, 1, 20, 3, 14];
/// `id-ac-CAP-gprsSSF-gsmSCF-AC`, `{id-acE 50}` in phase 3 and unchanged
/// (`{id-ac3E 50}`) in phase 4.
pub const CAP_V3_GPRSSSF_GSMSCF: [u32; 8] = [0, 4, 0, 0, 1, 21, 3, 50];
/// `id-ac-CAP-gsmSCF-gprsSSF-AC`, `{id-acE 51}` in phase 3 and unchanged
/// (`{id-ac3E 51}`) in phase 4.
pub const CAP_V3_GSMSCF_GPRSSSF: [u32; 8] = [0, 4, 0, 0, 1, 21, 3, 51];
/// `id-ac-cap3-sms-AC`, `{id-acE 61}` in phase 3 (`{id-ac3E 61}` in phase 4).
pub const CAP_V3_SMS: [u32; 8] = [0, 4, 0, 0, 1, 21, 3, 61];

/// Phase 4 `id-ac-CAP-gsmSSF-scfGenericAC`, `{id-acE 4}`.
pub const CAP_V4_GSMSSF_SCF_GENERIC: [u32; 8] = [0, 4, 0, 0, 1, 23, 3, 4];
/// Phase 4 `id-ac-CAP-gsmSSF-scfAssistHandoffAC`, `{id-acE 6}`.
pub const CAP_V4_GSMSSF_SCF_ASSIST_HANDOFF: [u32; 8] = [0, 4, 0, 0, 1, 23, 3, 6];
/// Phase 4 `id-ac-CAP-scf-gsmSSFGenericAC`, `{id-acE 8}`: the dialogue the
/// gsmSCF opens towards the gsmSSF (InitiateCallAttempt).
pub const CAP_V4_SCF_GSMSSF_GENERIC: [u32; 8] = [0, 4, 0, 0, 1, 23, 3, 8];
/// Phase 4 `id-ac-gsmSRF-gsmSCF`, `{id-ac 14}`.
pub const CAP_V4_GSMSRF_GSMSCF: [u32; 8] = [0, 4, 0, 0, 1, 22, 3, 14];
/// Phase 4 `id-ac-cap4-sms-AC`, `{id-acE 61}`.
pub const CAP_V4_SMS: [u32; 8] = [0, 4, 0, 0, 1, 23, 3, 61];

/// The object identifier for a set of arcs from this module.
pub fn object_identifier(arcs: &[u32]) -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(arcs.to_vec().into())
}

/// gsmSSF to gsmSCF call control. Defined for every phase.
pub fn cap_gsmssf_scf_generic(version: u32) -> Option<ObjectIdentifier> {
    let arcs = match version {
        CAP_V1 => &CAP_V1_GSMSSF_TO_GSMSCF,
        CAP_V2 => &CAP_V2_GSMSSF_TO_GSMSCF,
        CAP_V3 => &CAP_V3_GSMSSF_SCF_GENERIC,
        CAP_V4 => &CAP_V4_GSMSSF_SCF_GENERIC,
        _ => return None,
    };
    Some(object_identifier(arcs))
}

/// Assisting gsmSSF to gsmSCF (assist and hand-off). Phase 1 has no such
/// context.
pub fn cap_gsmssf_scf_assist_handoff(version: u32) -> Option<ObjectIdentifier> {
    let arcs = match version {
        CAP_V2 => &CAP_V2_ASSIST_GSMSSF_TO_GSMSCF,
        CAP_V3 => &CAP_V3_GSMSSF_SCF_ASSIST_HANDOFF,
        CAP_V4 => &CAP_V4_GSMSSF_SCF_ASSIST_HANDOFF,
        _ => return None,
    };
    Some(object_identifier(arcs))
}

/// gsmSCF to gsmSSF call control, for a dialogue the gsmSCF opens. Phase 4
/// only.
pub fn cap_scf_gsmssf_generic(version: u32) -> Option<ObjectIdentifier> {
    match version {
        CAP_V4 => Some(object_identifier(&CAP_V4_SCF_GSMSSF_GENERIC)),
        _ => None,
    }
}

/// gsmSRF to gsmSCF (specialised resources). Phase 1 has no such context.
pub fn cap_gsmsrf_scf(version: u32) -> Option<ObjectIdentifier> {
    let arcs = match version {
        CAP_V2 => &CAP_V2_GSMSRF_TO_GSMSCF,
        CAP_V3 => &CAP_V3_GSMSRF_GSMSCF,
        CAP_V4 => &CAP_V4_GSMSRF_GSMSCF,
        _ => return None,
    };
    Some(object_identifier(arcs))
}

/// SMS control. CAMEL control of SMS starts with phase 3.
pub fn cap_sms_ac(version: u32) -> Option<ObjectIdentifier> {
    let arcs = match version {
        CAP_V3 => &CAP_V3_SMS,
        CAP_V4 => &CAP_V4_SMS,
        _ => return None,
    };
    Some(object_identifier(arcs))
}

/// gprsSSF to gsmSCF. Starts with phase 3; phase 4 kept the phase 3 value.
pub fn cap_gprsssf_gsmscf(version: u32) -> Option<ObjectIdentifier> {
    match version {
        CAP_V3 | CAP_V4 => Some(object_identifier(&CAP_V3_GPRSSSF_GSMSCF)),
        _ => None,
    }
}

/// gsmSCF to gprsSSF. Starts with phase 3; phase 4 kept the phase 3 value.
pub fn cap_gsmscf_gprsssf(version: u32) -> Option<ObjectIdentifier> {
    match version {
        CAP_V3 | CAP_V4 => Some(object_identifier(&CAP_V3_GSMSCF_GPRSSSF)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arcs(oid: Option<ObjectIdentifier>) -> Option<Vec<u32>> {
        oid.map(|o| o.iter().copied().collect())
    }

    #[test]
    fn generic_context_per_phase() {
        assert_eq!(
            arcs(cap_gsmssf_scf_generic(CAP_V1)),
            Some(vec![0, 4, 0, 0, 1, 0, 50, 0])
        );
        assert_eq!(
            arcs(cap_gsmssf_scf_generic(CAP_V2)),
            Some(vec![0, 4, 0, 0, 1, 0, 50, 1])
        );
        assert_eq!(
            arcs(cap_gsmssf_scf_generic(CAP_V3)),
            Some(vec![0, 4, 0, 0, 1, 21, 3, 4])
        );
        assert_eq!(
            arcs(cap_gsmssf_scf_generic(CAP_V4)),
            Some(vec![0, 4, 0, 0, 1, 23, 3, 4])
        );
        assert_eq!(cap_gsmssf_scf_generic(0), None);
        assert_eq!(cap_gsmssf_scf_generic(5), None);
    }

    #[test]
    fn assist_handoff_context_per_phase() {
        assert_eq!(cap_gsmssf_scf_assist_handoff(CAP_V1), None);
        assert_eq!(
            arcs(cap_gsmssf_scf_assist_handoff(CAP_V2)),
            Some(vec![0, 4, 0, 0, 1, 0, 51, 1])
        );
        assert_eq!(
            arcs(cap_gsmssf_scf_assist_handoff(CAP_V3)),
            Some(vec![0, 4, 0, 0, 1, 21, 3, 6])
        );
        assert_eq!(
            arcs(cap_gsmssf_scf_assist_handoff(CAP_V4)),
            Some(vec![0, 4, 0, 0, 1, 23, 3, 6])
        );
    }

    #[test]
    fn gsmsrf_context_sits_under_the_non_oe_roots() {
        assert_eq!(cap_gsmsrf_scf(CAP_V1), None);
        assert_eq!(
            arcs(cap_gsmsrf_scf(CAP_V2)),
            Some(vec![0, 4, 0, 0, 1, 0, 52, 1])
        );
        // {id-ac 14}: roots cap3(20) and cap4(22), not 21 and 23.
        assert_eq!(
            arcs(cap_gsmsrf_scf(CAP_V3)),
            Some(vec![0, 4, 0, 0, 1, 20, 3, 14])
        );
        assert_eq!(
            arcs(cap_gsmsrf_scf(CAP_V4)),
            Some(vec![0, 4, 0, 0, 1, 22, 3, 14])
        );
    }

    #[test]
    fn sms_context_is_61_and_gprs_is_50() {
        assert_eq!(cap_sms_ac(CAP_V1), None);
        assert_eq!(cap_sms_ac(CAP_V2), None);
        assert_eq!(
            arcs(cap_sms_ac(CAP_V3)),
            Some(vec![0, 4, 0, 0, 1, 21, 3, 61])
        );
        assert_eq!(
            arcs(cap_sms_ac(CAP_V4)),
            Some(vec![0, 4, 0, 0, 1, 23, 3, 61])
        );
        // 0.4.0.0.1.21.3.50, which this crate used to hand out as the SMS
        // context, is the gprsSSF one.
        assert_eq!(
            arcs(cap_gprsssf_gsmscf(CAP_V3)),
            Some(vec![0, 4, 0, 0, 1, 21, 3, 50])
        );
        assert_eq!(cap_gprsssf_gsmscf(CAP_V4), cap_gprsssf_gsmscf(CAP_V3));
        assert_eq!(
            arcs(cap_gsmscf_gprsssf(CAP_V4)),
            Some(vec![0, 4, 0, 0, 1, 21, 3, 51])
        );
        assert_eq!(cap_gprsssf_gsmscf(CAP_V2), None);
    }

    #[test]
    fn scf_initiated_context_is_phase_4_only() {
        assert_eq!(cap_scf_gsmssf_generic(CAP_V3), None);
        assert_eq!(
            arcs(cap_scf_gsmssf_generic(CAP_V4)),
            Some(vec![0, 4, 0, 0, 1, 23, 3, 8])
        );
    }
}
