//! Connect (op 20), 3GPP TS 29.078 V18.0.0 clause 6.1.1.
//!
//! Vectors are assembled by hand from the ASN.1 (see `tests/bcsm_events.rs`
//! for the tag octet rules). Values are synthetic: numbers in the fictional
//! `+1 555 01xx` range.

mod common;

use common::{dissect, known_answer, vector, Carrier};
use gsm_cap::op_codes;
use gsm_cap::operations::ConnectArg;
use gsm_cap::types::{
    BackwardServiceInteractionInd, BothwayThroughConnectionInd, Code, ConnectedNumberTreatmentInd,
    ExtensionField, ForwardServiceInteractionInd, GenericNumbers, LegId,
    ServiceInteractionIndicatorsTwo, LEG2,
};
use rasn::types::{Any, Integer};

#[test]
fn connect_to_a_translated_number() {
    // The usual answer to InitialDP: one destination and nothing else.
    //   destinationRoutingAddress [0] SEQUENCE SIZE (1) OF CalledPartyNumber
    //   CalledPartyNumber (Q.763 3.9): 04 = even, international; 10 = ISDN
    //   numbering plan; digits 1 5 5 5 0 1 0 2 as 51 55 10 20.
    let arg = ConnectArg::new(vector("04 10 51 55 10 20").into());
    let ber = known_answer(
        &arg,
        "
        30 0a
           a0 08                               -- destinationRoutingAddress [0]
              04 06 04 10 51 55 10 20          --   CalledPartyNumber, universal OCTET STRING
        ",
    );
    let Some(d) = dissect(op_codes::CONNECT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("camel.destinationRoutingAddress", "1")
        .hex("camel.CalledPartyNumber", "041051551020");
}

fn every_member() -> ConnectArg {
    ConnectArg {
        alerting_pattern: Some(vector("00 00 01").into()),
        original_called_party_id: Some(vector("04 10 51 55 10 00").into()),
        extensions: Some(vec![ExtensionField {
            extension_type: Code::Local(Integer::from(1)),
            criticality: None,
            value: Any::new(vec![0x01, 0x01, 0xff]),
        }]),
        carrier: Some(vector("01 21 43 65").into()),
        calling_partys_category: Some(vec![0x0a].into()),
        redirecting_party_id: Some(vector("04 10 51 55 10 10").into()),
        redirection_information: Some(vector("13 61").into()),
        generic_numbers: Some(GenericNumbers::from_vec(vec![vector(
            "06 04 10 51 55 10 30",
        )
        .into()])),
        service_interaction_indicators_two: Some(ServiceInteractionIndicatorsTwo {
            forward_service_interaction_ind: Some(ForwardServiceInteractionInd {
                conference_treatment_indicator: Some(vec![0x01].into()),
                call_diversion_treatment_indicator: Some(vec![0x02].into()),
                calling_party_restriction_indicator: None,
            }),
            backward_service_interaction_ind: Some(BackwardServiceInteractionInd {
                conference_treatment_indicator: Some(vec![0x01].into()),
                call_completion_treatment_indicator: None,
            }),
            bothway_through_connection_ind: Some(BothwayThroughConnectionInd::BothwayPathRequired),
            connected_number_treatment_ind: Some(
                ConnectedNumberTreatmentInd::PresentationRestricted,
            ),
            non_cug_call: Some(()),
            hold_treatment_indicator: Some(vec![0x01].into()),
            cw_treatment_indicator: Some(vec![0x01].into()),
            ect_treatment_indicator: Some(vec![0x01].into()),
        }),
        charge_number: Some(vector("03 10 51 55 10 40").into()),
        leg_to_be_connected: Some(LegId::sending(LEG2)),
        cug_interlock: Some(vector("00 01 00 01").into()),
        cug_outgoing_access: Some(()),
        suppression_of_announcement: Some(()),
        o_csi_applicable: Some(()),
        na_oli_info: Some(vec![0x3d].into()),
        bor_interrogation_requested: Some(()),
        suppress_n_csi: Some(()),
        ..ConnectArg::new(vector("04 10 51 55 10 20").into())
    }
}

/// Members in ASN.1 order, which is not tag order: [28] [29] [30] precede
/// [14]. Member sizes: 10 5 8 12 6 3 8 4 11 35 8 5 7 3 3 3 4 3 3 = 141 (0x8d),
/// so the outer length needs the long form `81 8d`.
const EVERY_MEMBER: &str = "
    30 81 8d
       a0 08 04 06 04 10 51 55 10 20           -- destinationRoutingAddress [0]
       81 03 00 00 01                          -- alertingPattern [1]
       86 06 04 10 51 55 10 00                 -- originalCalledPartyID [6], 15550100
       aa 0a                                   -- extensions [10]
          30 08 02 01 01 a1 03 01 01 ff        --   { type local 1, value [1] EXPLICIT BOOLEAN }
       8b 04 01 21 43 65                       -- carrier [11]
       9c 01 0a                                -- callingPartysCategory [28]: ordinary subscriber
       9d 06 04 10 51 55 10 10                 -- redirectingPartyID [29], 15550101
       9e 02 13 61                             -- redirectionInformation [30]
       ae 09 04 07 06 04 10 51 55 10 30        -- genericNumbers [14] SET OF { OCTET STRING }
       af 21                                   -- serviceInteractionIndicatorsTwo [15]
          a0 06 81 01 01 82 01 02              --   forwardServiceInteractionInd [0]
          a1 03 81 01 01                       --   backwardServiceInteractionInd [1]
          82 01 00                             --   bothwayThroughConnectionInd [2]
          84 01 01                             --   connectedNumberTreatmentInd [4]
          8d 00                                --   nonCUGCall [13] NULL
          9f 32 01 01                          --   holdTreatmentIndicator [50]
          9f 33 01 01                          --   cwTreatmentIndicator [51]
          9f 34 01 01                          --   ectTreatmentIndicator [52]
       93 06 03 10 51 55 10 40                 -- chargeNumber [19]
       b5 03 80 01 02                          -- legToBeConnected [21] EXPLICIT { sendingSideID leg2 }
       9f 1f 04 00 01 00 01                    -- cug-Interlock [31]
       9f 20 00                                -- cug-OutgoingAccess [32] NULL
       9f 37 00                                -- suppressionOfAnnouncement [55] NULL
       9f 38 00                                -- oCSIApplicable [56] NULL
       9f 39 01 3d                             -- naOliInfo [57]
       9f 3a 00                                -- bor-InterrogationRequested [58] NULL
       9f 3b 00                                -- suppress-N-CSI [59] NULL
";

#[test]
fn connect_with_every_member() {
    let ber = known_answer(&every_member(), EVERY_MEMBER);
    let Some(d) = dissect(op_codes::CONNECT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.hex("camel.CalledPartyNumber", "041051551020")
        .hex("camel.alertingPattern", "000001")
        .hex("camel.originalCalledPartyID", "041051551000")
        .show("camel.extensions", "1")
        .show("camel.extension_code_local", "1")
        .hex("camel.carrier", "01214365")
        .hex("camel.callingPartysCategory", "0a")
        .hex("camel.redirectingPartyID", "041051551010")
        .hex("camel.redirectionInformation", "1361")
        .show("camel.genericNumbers", "1")
        .hex("camel.GenericNumber", "06041051551030")
        .present("camel.serviceInteractionIndicatorsTwo_element")
        .present("camel.forwardServiceInteractionInd_element")
        .present("camel.backwardServiceInteractionInd_element")
        // Forward and backward indicators both carry one.
        .hex_all("camel.conferenceTreatmentIndicator", &["01", "01"])
        .hex("camel.callDiversionTreatmentIndicator", "02")
        .show("camel.bothwayThroughConnectionInd", "0")
        .show("camel.connectedNumberTreatmentInd", "1")
        .present("camel.nonCUGCall_element")
        .hex("camel.holdTreatmentIndicator", "01")
        .hex("camel.cwTreatmentIndicator", "01")
        .hex("camel.ectTreatmentIndicator", "01")
        .hex("camel.chargeNumber", "031051551040")
        .show("camel.legToBeConnected", "0")
        .hex("inap.sendingSideID", "02")
        .hex("camel.cug_Interlock", "00010001")
        .present("camel.cug_OutgoingAccess_element")
        .present("camel.suppressionOfAnnouncement_element")
        .present("camel.oCSIApplicable_element")
        .hex("camel.naOliInfo", "3d")
        .present("camel.bor_InterrogationRequested_element")
        .present("camel.suppress_N_CSI_element");
}

#[test]
fn connect_rejects_the_tags_this_crate_used_to_emit() {
    // Before 2.0.0: originalCalledPartyID on [4], callingPartysCategory on
    // [6], redirectingPartyID on [7], genericNumbers on [11]. Read with the
    // real tags, [6] would be taken for originalCalledPartyID, so the bytes
    // must be refused as a whole.
    let old = vector(
        "30 23 a0 07 04 05 03 10 55 01 23 84 05 03 10 55 01 00 86 01 0a
               87 05 03 10 55 01 01 ab 07 04 05 06 03 10 55 01",
    );
    assert!(gsm_cap::decode::<ConnectArg>(&old).is_err());
}
