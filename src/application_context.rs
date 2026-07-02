//! CAP Application Context OIDs — 3GPP TS 29.078.
//!
//! An application context identifies the CAP operation set + phase used in a
//! TCAP dialogue. OID structure:
//!
//! ```text
//!   CAP v1/v2: 0.4.0.0.1.0.50.<version>   (under the MAP AC space)
//!   CAP v3:    0.4.0.0.1.21.3.<ac_id>      (module 21)
//!   CAP v4:    0.4.0.0.1.23.3.<ac_id>      (module 23)
//! ```
//! AC ids: 4 = gsmSSF-scfGeneric, 6 = assistHandoff, 10 = gsmSRF, 50 = sms.

use rasn::types::ObjectIdentifier;

/// CAP phase 1.
pub const CAP_V1: u32 = 1;
/// CAP phase 2.
pub const CAP_V2: u32 = 2;
/// CAP phase 3.
pub const CAP_V3: u32 = 3;
/// CAP phase 4.
pub const CAP_V4: u32 = 4;

fn cap_ac(version: u32, ac_id: u32) -> ObjectIdentifier {
    let components: Vec<u32> = match version {
        1 => vec![0, 4, 0, 0, 1, 0, 50, 0],     // CAP v1
        2 => vec![0, 4, 0, 0, 1, 0, 50, 1],     // CAP v2
        3 => vec![0, 4, 0, 0, 1, 21, 3, ac_id], // CAP v3
        4 => vec![0, 4, 0, 0, 1, 23, 3, ac_id], // CAP v4
        _ => vec![0, 4, 0, 0, 1, 21, 3, ac_id], // default to v3
    };
    ObjectIdentifier::new_unchecked(components.into())
}

/// gsmSSF-scfGenericAC — gsmSSF ↔ gsmSCF call control.
pub fn cap_gsmssf_scf_generic(version: u32) -> ObjectIdentifier {
    cap_ac(version, 4)
}
/// gsmSSF-scfAssistHandoffAC.
pub fn cap_gsmssf_scf_assist_handoff(version: u32) -> ObjectIdentifier {
    cap_ac(version, 6)
}
/// gsmSRF-gsmSCF-AC — specialised resources.
pub fn cap_gsmsrf_scf(version: u32) -> ObjectIdentifier {
    cap_ac(version, 10)
}
/// cap-sms-AC — SMS control.
pub fn cap_sms_ac(version: u32) -> ObjectIdentifier {
    cap_ac(version, 50)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_distinct() {
        assert_ne!(
            cap_gsmssf_scf_generic(CAP_V3),
            cap_gsmssf_scf_generic(CAP_V4)
        );
        assert_ne!(cap_gsmssf_scf_generic(CAP_V3), cap_gsmsrf_scf(CAP_V3));
    }

    #[test]
    fn v3_generic_oid_shape() {
        // CAP v3 gsmSSF-scfGeneric = 0.4.0.0.1.21.3.4
        let oid = cap_gsmssf_scf_generic(CAP_V3);
        assert_eq!(
            oid.iter().copied().collect::<Vec<u32>>(),
            vec![0, 4, 0, 0, 1, 21, 3, 4]
        );
    }
}
