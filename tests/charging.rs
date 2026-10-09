//! ApplyCharging (op 35), ApplyChargingReport (op 36) and
//! FurnishChargingInformation (op 34), 3GPP TS 29.078 V18.0.0 clauses 5.1 and
//! 6.1.1, with the phase 3 form of the charging characteristics from V3.16.0.
//!
//! All three carry an OCTET STRING whose content is itself BER: the vectors
//! show the outer and the inner encoding. They are assembled by hand from the
//! ASN.1 (see `tests/bcsm_events.rs` for the tag octet rules).

mod common;

use common::{dissect, known_answer, vector, Carrier, Dissection};
use gsm_cap::application_context as ac;
use gsm_cap::op_codes;
use gsm_cap::operations::{
    ApplyChargingArg, ApplyChargingReportArg, FurnishChargingInformationArg,
};
use gsm_cap::types::{
    AChChargingAddress, AppendFreeFormatData, AudibleIndicator, Burst, BurstList,
    CamelAChBillingChargingCharacteristics, CamelAChBillingChargingCharacteristicsV3,
    CamelCallResult, CamelFciBillingChargingCharacteristics, FciBccCamelSequence1, LegId,
    ReceivingSideId, SendingSideId, TimeDurationCharging, TimeDurationChargingResult,
    TimeDurationChargingV3, TimeIfTariffSwitch, TimeInformation, LEG1, LEG2,
};

/// Wireshark picks the phase 3 or the phase 4 definition of the charging
/// characteristics from the application context of the dialogue, so the
/// argument is dissected in a Begin that names one.
fn on_context(operation: i64, ber: &[u8], arcs: &[u32; 8]) -> Option<Dissection> {
    let context = ac::object_identifier(arcs);
    dissect(operation, Some(ber), Carrier::Begin(&context))
}

// ── ApplyCharging ───────────────────────────────────────────────────────────

#[test]
fn apply_charging_phase_4() {
    let characteristics =
        CamelAChBillingChargingCharacteristics::TimeDurationCharging(TimeDurationCharging {
            release_if_duration_exceeded: Some(true),
            tariff_switch_interval: Some(300),
            audible_indicator: Some(AudibleIndicator::Tone(true)),
            ..TimeDurationCharging::new(3000)
        });
    // The content of the OCTET STRING, on its own.
    known_answer(
        &characteristics,
        "
        a0 10                                  -- timeDurationCharging [0], 4 + 3 + 4 + 5
           80 02 0b b8                         --   maxCallPeriodDuration 3000 (300 s)
           81 01 ff                            --   releaseIfdurationExceeded TRUE
           82 02 01 2c                         --   tariffSwitchInterval 300 s
           a3 03 01 01 ff                      --   audibleIndicator [3] EXPLICIT { tone BOOLEAN TRUE }
        ",
    );

    let arg = ApplyChargingArg {
        party_to_charge: Some(SendingSideId::leg(LEG1)),
        ..ApplyChargingArg::with_characteristics(&characteristics).unwrap()
    };
    let ber = known_answer(
        &arg,
        "
        30 19                                  -- 20 + 5 = 25
           80 12                               -- aChBillingChargingCharacteristics [0], an
                                               --   OCTET STRING: primitive, content is BER
              a0 10 80 02 0b b8 81 01 ff 82 02 01 2c a3 03 01 01 ff
           a2 03 80 01 01                      -- partyToCharge [2] EXPLICIT { sendingSideID [0] leg1 }
        ",
    );
    assert_eq!(
        arg.characteristics::<CamelAChBillingChargingCharacteristics>()
            .unwrap(),
        characteristics
    );

    let Some(d) = on_context(
        op_codes::APPLY_CHARGING,
        &ber,
        &ac::CAP_V4_GSMSSF_SCF_GENERIC,
    ) else {
        return;
    };
    d.present("camel.ApplyChargingArg_element")
        .hex(
            "camel.aChBillingChargingCharacteristics",
            "a01080020bb88101ff8202012ca3030101ff",
        )
        .present("camel.timeDurationCharging_element")
        .show("camel.maxCallPeriodDuration", "3000")
        .show("camel.releaseIfdurationExceeded", "True")
        .show("camel.timeDurationCharging_tariffSwitchInterval", "300")
        // Alternative 0 of AudibleIndicator, the tone BOOLEAN.
        .show("camel.audibleIndicator", "0")
        .show("camel.audibleIndicatorTone", "True")
        .show("camel.partyToCharge", "0")
        .hex("camel.sendingSideID", "01");
}

#[test]
fn apply_charging_phase_4_burst_list_and_charging_address() {
    let characteristics =
        CamelAChBillingChargingCharacteristics::TimeDurationCharging(TimeDurationCharging {
            audible_indicator: Some(AudibleIndicator::BurstList(BurstList {
                warning_period: Some(30),
                bursts: Burst {
                    number_of_bursts: Some(1),
                    burst_interval: Some(2),
                    number_of_tones_in_burst: Some(3),
                    tone_duration: Some(2),
                    tone_interval: Some(2),
                },
            })),
            ..TimeDurationCharging::new(3000)
        });
    let arg = ApplyChargingArg {
        a_ch_charging_address: Some(AChChargingAddress::SrfConnection(1)),
        ..ApplyChargingArg::with_characteristics(&characteristics).unwrap()
    };
    let ber = known_answer(
        &arg,
        "
        30 27                                  -- 32 + 7 = 39
           80 1e                               -- aChBillingChargingCharacteristics [0]
              a0 1c                            --   timeDurationCharging [0], 4 + 24
                 80 02 0b b8                   --     maxCallPeriodDuration 3000
                 a3 16                         --     audibleIndicator [3] EXPLICIT
                    a1 14                      --       burstList [1], 3 + 17
                       80 01 1e                --         warningPeriod 30 s
                       a1 0f                   --         bursts [1]
                          80 01 01             --           numberOfBursts 1
                          81 01 02             --           burstInterval 2
                          82 01 03             --           numberOfTonesInBurst 3
                          83 01 02             --           toneDuration 2
                          84 01 02             --           toneInterval 2
           bf 32 04                            -- aChChargingAddress [50] EXPLICIT (a CHOICE)
              9f 32 01 01                      --   srfConnection [50] CallSegmentID 1
        ",
    );
    let Some(d) = on_context(
        op_codes::APPLY_CHARGING,
        &ber,
        &ac::CAP_V4_GSMSSF_SCF_GENERIC,
    ) else {
        return;
    };
    d.show("camel.audibleIndicator", "1")
        .present("camel.burstList_element")
        .show("camel.warningPeriod", "30")
        .present("camel.bursts_element")
        .show("camel.numberOfBursts", "1")
        .show("camel.burstInterval", "2")
        .show("camel.numberOfTonesInBurst", "3")
        .show("camel.burstToneDuration", "2")
        .show("camel.toneInterval", "2")
        .show("camel.aChChargingAddress", "50")
        .show("camel.srfConnection", "1");

    // The other alternative of aChChargingAddress: legID [2], itself a CHOICE
    // and so explicit inside the explicit [50].
    known_answer(
        &ApplyChargingArg {
            a_ch_charging_address: Some(AChChargingAddress::LegId(LegId::sending(LEG2))),
            ..ApplyChargingArg::new(vector("a0 04 80 02 0b b8").into())
        },
        "
        30 10
           80 06 a0 04 80 02 0b b8
           bf 32 05                            -- aChChargingAddress [50] EXPLICIT
              a2 03                            --   legID [2] EXPLICIT
                 80 01 02                      --     sendingSideID [0] leg2
        ",
    );
}

#[test]
fn apply_charging_phase_3() {
    let characteristics =
        CamelAChBillingChargingCharacteristicsV3::TimeDurationCharging(TimeDurationChargingV3 {
            release_if_duration_exceeded: Some(true),
            tone: Some(true),
            ..TimeDurationChargingV3::new(3000)
        });
    let arg = ApplyChargingArg {
        party_to_charge: Some(SendingSideId::leg(LEG1)),
        ..ApplyChargingArg::with_characteristics(&characteristics).unwrap()
    };
    let ber = known_answer(
        &arg,
        "
        30 13                                  -- 14 + 5 = 19
           80 0c                               -- aChBillingChargingCharacteristics [0]
              a0 0a                            --   timeDurationCharging [0], 4 + 3 + 3
                 80 02 0b b8                   --     maxCallPeriodDuration 3000
                 81 01 ff                      --     releaseIfdurationExceeded TRUE
                 83 01 ff                      --     tone [3] BOOLEAN TRUE, primitive in phase 3
           a2 03 80 01 01                      -- partyToCharge: sendingSideID leg1
        ",
    );
    assert_eq!(
        arg.characteristics::<CamelAChBillingChargingCharacteristicsV3>()
            .unwrap(),
        characteristics
    );
    // The phase 4 reading of the same octets must fail: [3] is not explicit.
    assert!(arg
        .characteristics::<CamelAChBillingChargingCharacteristics>()
        .is_err());

    let Some(d) = on_context(
        op_codes::APPLY_CHARGING,
        &ber,
        &ac::CAP_V3_GSMSSF_SCF_GENERIC,
    ) else {
        return;
    };
    d.show("camel.maxCallPeriodDuration", "3000")
        .show("camel.releaseIfdurationExceeded", "True")
        // On the phase 3 context Wireshark reads [3] as the plain BOOLEAN.
        .show("camel.audibleIndicatorTone", "True")
        .absent("camel.audibleIndicator")
        .show("camel.partyToCharge", "0")
        .hex("camel.sendingSideID", "01");
}

#[test]
fn apply_charging_rejects_a_primitive_party_to_charge() {
    // Before 2.0.0: partyToCharge as `82 01 01`. SendingSideID is a CHOICE,
    // so [2] wraps `80 01 01`.
    let old = vector("30 0b 80 06 a0 04 80 02 0b b8 82 01 01");
    assert!(gsm_cap::decode::<ApplyChargingArg>(&old).is_err());
}

// ── ApplyChargingReport ─────────────────────────────────────────────────────

#[test]
fn apply_charging_report_is_a_bare_octet_string() {
    let result = CamelCallResult::TimeDurationChargingResult(TimeDurationChargingResult {
        leg_active: Some(false),
        call_leg_released_at_tcp_expiry: Some(()),
        a_ch_charging_address: Some(AChChargingAddress::LegId(LegId::receiving(LEG1))),
        ..TimeDurationChargingResult::new(
            ReceivingSideId::leg(LEG1),
            TimeInformation::TimeIfNoTariffSwitch(300),
        )
    });
    let arg = ApplyChargingReportArg::from_call_result(&result).unwrap();
    let ber = known_answer(
        &arg,
        "
        04 19                                  -- ApplyChargingReportArg ::= CallResult: a
                                               --   universal OCTET STRING, no SEQUENCE
           a0 17                               -- timeDurationChargingResult [0], 5 + 6 + 3 + 2 + 7
              a0 03 81 01 01                   --   partyToCharge [0] EXPLICIT { receivingSideID [1] leg1 }
              a1 04 80 02 01 2c                --   timeInformation [1] EXPLICIT
                                               --     { timeIfNoTariffSwitch [0] 300 = 30 s }
              82 01 00                         --   legActive [2] FALSE
              83 00                            --   callLegReleasedAtTcpExpiry [3] NULL
              a5 05 a2 03 81 01 01             --   aChChargingAddress [5] EXPLICIT { legID [2]
                                               --     EXPLICIT { receivingSideID [1] leg1 } }
        ",
    );
    assert_eq!(arg.call_result().unwrap(), result);

    let Some(d) = on_context(
        op_codes::APPLY_CHARGING_REPORT,
        &ber,
        &ac::CAP_V4_GSMSSF_SCF_GENERIC,
    ) else {
        return;
    };
    d.hex(
        "camel.ApplyChargingReportArg",
        "a017a003810101a1048002012c8201008300a505a203810101",
    )
    .present("camel.timeDurationChargingResult_element")
    .show("camel.timeDurationChargingResultpartyToCharge", "1")
    .hex("camel.receivingSideID", "01")
    .show("camel.timeInformation", "0")
    .show("camel.timeIfNoTariffSwitch", "300")
    .show("camel.legActive", "False")
    .present("camel.callLegReleasedAtTcpExpiry_element")
    .show("camel.aChChargingAddress", "2")
    .show("camel.legID", "1")
    .hex("inap.receivingSideID", "01");
}

#[test]
fn apply_charging_report_with_a_tariff_switch() {
    // The phase 3 shape: no aChChargingAddress.
    let result = CamelCallResult::TimeDurationChargingResult(TimeDurationChargingResult::new(
        ReceivingSideId::leg(LEG2),
        TimeInformation::TimeIfTariffSwitch(TimeIfTariffSwitch {
            time_since_tariff_switch: 100,
            tariff_switch_interval: Some(300),
        }),
    ));
    let arg = ApplyChargingReportArg::from_call_result(&result).unwrap();
    let ber = known_answer(
        &arg,
        "
        04 12
           a0 10                               -- timeDurationChargingResult [0], 5 + 11
              a0 03 81 01 02                   --   partyToCharge: receivingSideID leg2
              a1 09                            --   timeInformation [1] EXPLICIT
                 a1 07                         --     timeIfTariffSwitch [1], 3 + 4
                    80 01 64                   --       timeSinceTariffSwitch 100
                    81 02 01 2c                --       tariffSwitchInterval 300
        ",
    );
    assert_eq!(arg.call_result().unwrap(), result);
    let Some(d) = on_context(
        op_codes::APPLY_CHARGING_REPORT,
        &ber,
        &ac::CAP_V3_GSMSSF_SCF_GENERIC,
    ) else {
        return;
    };
    d.show("camel.timeDurationChargingResultpartyToCharge", "1")
        .hex("camel.receivingSideID", "02")
        .show("camel.timeInformation", "1")
        .present("camel.timeIfTariffSwitch_element")
        .show("camel.timeSinceTariffSwitch", "100")
        .show("camel.timeIfTariffSwitch_tariffSwitchInterval", "300")
        .absent("camel.aChChargingAddress");
}

#[test]
fn apply_charging_report_rejects_the_sequence_wrapper() {
    // Before 2.0.0: SEQUENCE { OCTET STRING }.
    let old = vector("30 08 04 06 a0 04 a0 02 81 00");
    assert!(gsm_cap::decode::<ApplyChargingReportArg>(&old).is_err());
}

// ── FurnishChargingInformation ──────────────────────────────────────────────

#[test]
fn furnish_charging_information_is_a_bare_octet_string() {
    let characteristics =
        CamelFciBillingChargingCharacteristics::FciBccCamelSequence1(FciBccCamelSequence1 {
            free_format_data: vector("ca fe 00 01").into(),
            party_to_charge: Some(SendingSideId::leg(LEG2)),
            append_free_format_data: Some(AppendFreeFormatData::Append),
        });
    let arg = FurnishChargingInformationArg::from_characteristics(&characteristics).unwrap();
    let ber = known_answer(
        &arg,
        "
        04 10                                  -- FurnishChargingInformationArg ::=
                                               --   FCIBillingChargingCharacteristics: a
                                               --   universal OCTET STRING, no SEQUENCE
           a0 0e                               -- fCIBCCCAMELsequence1 [0], 6 + 5 + 3
              80 04 ca fe 00 01                --   freeFormatData [0]
              a1 03 80 01 02                   --   partyToCharge [1] EXPLICIT { sendingSideID [0] leg2 }
              82 01 01                         --   appendFreeFormatData [2] append(1)
        ",
    );
    assert_eq!(arg.characteristics().unwrap(), characteristics);

    let Some(d) = on_context(
        op_codes::FURNISH_CHARGING_INFORMATION,
        &ber,
        &ac::CAP_V3_GSMSSF_SCF_GENERIC,
    ) else {
        return;
    };
    d.hex(
        "camel.FurnishChargingInformationArg",
        "a00e8004cafe0001a103800102820101",
    )
    .present("camel.fci_fCIBCCCAMELsequence1_element")
    .hex("camel.freeFormatData", "cafe0001")
    .show("camel.fCIBCCCAMELsequence1partyToCharge", "0")
    .hex("camel.sendingSideID", "02")
    .show("camel.appendFreeFormatData", "1");
}

#[test]
fn furnish_charging_information_rejects_the_sequence_wrapper() {
    // Before 2.0.0: SEQUENCE { OCTET STRING }.
    let old = vector("30 08 04 06 a0 04 80 02 ca fe");
    assert!(gsm_cap::decode::<FurnishChargingInformationArg>(&old).is_err());
}
