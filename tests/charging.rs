//! ApplyCharging (op 35), ApplyChargingReport (op 36) and
//! FurnishChargingInformation (op 34), 3GPP TS 29.078 V18.0.0 clauses 5.1 and
//! 6.1.1, with the phase 3 form of the charging characteristics from V3.16.0
//! and the phase 2 form from GSM 09.78 V7.1.0 (ETSI TS 101 046) clause 6.3.
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
    CamelAChBillingChargingCharacteristics, CamelAChBillingChargingCharacteristicsV2,
    CamelAChBillingChargingCharacteristicsV3, CamelCallResult,
    CamelFciBillingChargingCharacteristics, Code, CriticalityType, ExtensionField,
    FciBccCamelSequence1, LegId, ReceivingSideId, ReleaseIfDurationExceeded, SendingSideId,
    TimeDurationCharging, TimeDurationChargingResult, TimeDurationChargingV2,
    TimeDurationChargingV3, TimeIfTariffSwitch, TimeInformation, LEG1, LEG2,
};
use rasn::types::{Any, Integer};

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

// ── ApplyCharging, phase 2 ──────────────────────────────────────────────────
//
// GSM 09.78 V7.1.0 clause 6.3, module CAP-DataTypes, DEFINITIONS IMPLICIT TAGS:
//
//   CAMEL-AChBillingChargingCharacteristics ::= CHOICE {
//     timeDurationCharging [0] SEQUENCE {
//       maxCallPeriodDuration     [0] INTEGER (1..864000),
//       releaseIfdurationExceeded [1] ReleaseIfDurationExceeded OPTIONAL,
//       tariffSwitchInterval      [2] INTEGER (1..86400)        OPTIONAL } }
//
//   ReleaseIfDurationExceeded ::= SEQUENCE {
//     tone       BOOLEAN DEFAULT FALSE,
//     ...,
//     extensions [10] SEQUENCE SIZE(1..numOfExtensions) OF ExtensionField OPTIONAL }
//
// Tags are implicit, so `[0] SEQUENCE` is `A0`, `[0] INTEGER` is `80`,
// `[1] ReleaseIfDurationExceeded` (a SEQUENCE) is the constructed `A1` and
// `[2] INTEGER` is `82`. `tone` has no tag of its own: universal BOOLEAN, `01`.

fn phase_2(
    time_duration_charging: TimeDurationChargingV2,
) -> CamelAChBillingChargingCharacteristicsV2 {
    CamelAChBillingChargingCharacteristicsV2::TimeDurationCharging(time_duration_charging)
}

#[test]
fn apply_charging_phase_2() {
    let characteristics = phase_2(TimeDurationChargingV2 {
        release_if_duration_exceeded: Some(ReleaseIfDurationExceeded {
            tone: Some(true),
            extensions: None,
        }),
        tariff_switch_interval: Some(300),
        ..TimeDurationChargingV2::new(3000)
    });
    known_answer(
        &characteristics,
        "
        a0 0d                                  -- timeDurationCharging [0], 4 + 5 + 4
           80 02 0b b8                         --   maxCallPeriodDuration 3000 (300 s)
           a1 03                               --   releaseIfdurationExceeded [1], a SEQUENCE
              01 01 ff                         --     tone BOOLEAN TRUE
           82 02 01 2c                         --   tariffSwitchInterval 300 s
        ",
    );

    let arg = ApplyChargingArg {
        party_to_charge: Some(SendingSideId::leg(LEG1)),
        ..ApplyChargingArg::with_characteristics(&characteristics).unwrap()
    };
    let ber = known_answer(
        &arg,
        "
        30 16                                  -- 17 + 5 = 22
           80 0f                               -- aChBillingChargingCharacteristics [0]
              a0 0d 80 02 0b b8 a1 03 01 01 ff 82 02 01 2c
           a2 03 80 01 01                      -- partyToCharge: sendingSideID leg1
        ",
    );
    assert_eq!(
        arg.characteristics::<CamelAChBillingChargingCharacteristicsV2>()
            .unwrap(),
        characteristics
    );
    // Phase 3 and phase 4 have `releaseIfdurationExceeded [1] BOOLEAN`, the
    // primitive `81`: neither reads the phase 2 SEQUENCE.
    assert!(arg
        .characteristics::<CamelAChBillingChargingCharacteristicsV3>()
        .is_err());
    assert!(arg
        .characteristics::<CamelAChBillingChargingCharacteristics>()
        .is_err());

    let Some(d) = on_context(op_codes::APPLY_CHARGING, &ber, &ac::CAP_V2_GSMSSF_TO_GSMSCF) else {
        return;
    };
    d.present("camel.ApplyChargingArg_element")
        .hex(
            "camel.aChBillingChargingCharacteristics",
            "a00d80020bb8a1030101ff8202012c",
        )
        .present("camel.timeDurationCharging_element")
        .show("camel.maxCallPeriodDuration", "3000")
        .present("camel.releaseIfdurationExceeded_element")
        .show("camel.tone", "True")
        .show("camel.tariffSwitchInterval", "300")
        .show("camel.partyToCharge", "0")
        .hex("camel.sendingSideID", "01");
}

#[test]
fn apply_charging_phase_2_without_release() {
    // Only the mandatory member: the call is not released when the period
    // ends, the gsmSSF reports and waits.
    let characteristics = phase_2(TimeDurationChargingV2::new(3000));
    let content = known_answer(
        &characteristics,
        "
        a0 04                                  -- timeDurationCharging [0]
           80 02 0b b8                         --   maxCallPeriodDuration 3000
        ",
    );
    // maxCallPeriodDuration at its upper bound, 864000 = 0x0D2F00 (24 h).
    known_answer(
        &phase_2(TimeDurationChargingV2::new(864_000)),
        "a0 05 80 03 0d 2f 00",
    );
    // tariffSwitchInterval without releaseIfdurationExceeded, at its upper
    // bound 86400 = 0x015180: a leading 00 is not needed, bit 8 of 01 is 0.
    known_answer(
        &phase_2(TimeDurationChargingV2 {
            tariff_switch_interval: Some(86_400),
            ..TimeDurationChargingV2::new(1)
        }),
        "
        a0 08
           80 01 01                            --   maxCallPeriodDuration 1 (100 ms)
           82 03 01 51 80                      --   tariffSwitchInterval 86400 s
        ",
    );

    let arg = ApplyChargingArg::new(content.into());
    let ber = known_answer(&arg, "30 08 80 06 a0 04 80 02 0b b8");
    let Some(d) = on_context(op_codes::APPLY_CHARGING, &ber, &ac::CAP_V2_GSMSSF_TO_GSMSCF) else {
        return;
    };
    d.show("camel.maxCallPeriodDuration", "3000")
        .absent("camel.releaseIfdurationExceeded_element")
        .absent("camel.tone")
        .absent("camel.tariffSwitchInterval");
}

/// `tone BOOLEAN DEFAULT FALSE`. X.690 8.9.3 leaves a member that has its
/// default value to the sender in BER ("may, but need not"), and 11.5 forbids
/// encoding it in DER. CAP is BER, so a peer may send either form and both
/// must be read. As everywhere in this crate the member is an `Option`:
/// `None` leaves it out, which is the DER form and the one to send;
/// `Some(false)` writes the default out and is what an explicit FALSE from a
/// peer decodes to, so that the octets survive a decode and encode.
#[test]
fn apply_charging_phase_2_tone_default() {
    // Release without a tone, the member left out: an empty SEQUENCE.
    let omitted = phase_2(TimeDurationChargingV2 {
        release_if_duration_exceeded: Some(ReleaseIfDurationExceeded::default()),
        ..TimeDurationChargingV2::new(3000)
    });
    let content = known_answer(
        &omitted,
        "
        a0 06
           80 02 0b b8                         --   maxCallPeriodDuration 3000
           a1 00                               --   releaseIfdurationExceeded [1] {}: tone FALSE
        ",
    );

    // Release without a tone, FALSE written out.
    let written = phase_2(TimeDurationChargingV2 {
        release_if_duration_exceeded: Some(ReleaseIfDurationExceeded {
            tone: Some(false),
            extensions: None,
        }),
        ..TimeDurationChargingV2::new(3000)
    });
    let explicit = known_answer(
        &written,
        "
        a0 09
           80 02 0b b8
           a1 03
              01 01 00                         --     tone BOOLEAN FALSE
        ",
    );
    // The two say the same thing and the accessor agrees.
    for value in [&omitted, &written] {
        let CamelAChBillingChargingCharacteristicsV2::TimeDurationCharging(t) = value;
        let release = t.release_if_duration_exceeded.as_ref().unwrap();
        assert!(!release.tone());
    }
    assert!(ReleaseIfDurationExceeded::with_tone().tone());

    // BER reads any non-zero octet as TRUE (X.690 8.2.2).
    let any_true: CamelAChBillingChargingCharacteristicsV2 =
        gsm_cap::decode(&vector("a0 09 80 02 0b b8 a1 03 01 01 01")).unwrap();
    let CamelAChBillingChargingCharacteristicsV2::TimeDurationCharging(t) = any_true;
    assert_eq!(
        t.release_if_duration_exceeded,
        Some(ReleaseIfDurationExceeded::with_tone())
    );

    for (content, tone) in [(content, None), (explicit, Some("False"))] {
        let ber = gsm_cap::encode(&ApplyChargingArg::new(content.into())).unwrap();
        let Some(d) = on_context(op_codes::APPLY_CHARGING, &ber, &ac::CAP_V2_GSMSSF_TO_GSMSCF)
        else {
            return;
        };
        d.show("camel.maxCallPeriodDuration", "3000")
            .present("camel.releaseIfdurationExceeded_element");
        match tone {
            Some(shown) => d.show("camel.tone", shown),
            None => d.absent("camel.tone"),
        };
    }
}

#[test]
fn apply_charging_phase_2_release_extensions() {
    let characteristics = phase_2(TimeDurationChargingV2 {
        release_if_duration_exceeded: Some(ReleaseIfDurationExceeded {
            tone: Some(true),
            extensions: Some(vec![ExtensionField {
                extension_type: Code::Local(Integer::from(1)),
                criticality: Some(CriticalityType::Abort),
                // The extension's own type, here a BOOLEAN TRUE.
                value: Any::new(vec![0x01, 0x01, 0xff]),
            }]),
        }),
        ..TimeDurationChargingV2::new(3000)
    });
    let content = known_answer(
        &characteristics,
        "
        a0 18                                  -- timeDurationCharging [0], 4 + 20
           80 02 0b b8                         --   maxCallPeriodDuration 3000
           a1 12                               --   releaseIfdurationExceeded [1], 3 + 15
              01 01 ff                         --     tone TRUE
              aa 0d                            --     extensions [10]
                 30 0b                         --       ExtensionField
                    02 01 01                   --         type: local 1
                    0a 01 01                   --         criticality: abort(1)
                    a1 03 01 01 ff             --         value [1] EXPLICIT BOOLEAN TRUE
        ",
    );
    let ber = gsm_cap::encode(&ApplyChargingArg::new(content.into())).unwrap();
    let Some(d) = on_context(op_codes::APPLY_CHARGING, &ber, &ac::CAP_V2_GSMSSF_TO_GSMSCF) else {
        return;
    };
    d.show("camel.tone", "True")
        .show("camel.extensions", "1")
        .show("camel.extension_code_local", "1")
        .show("camel.criticality", "1");
}

#[test]
fn apply_charging_phase_2_rejects_damaged_input() {
    let decode =
        |text: &str| gsm_cap::decode::<CamelAChBillingChargingCharacteristicsV2>(&vector(text));
    // The intact value, for reference.
    assert!(decode("a0 0d 80 02 0b b8 a1 03 01 01 ff 82 02 01 2c").is_ok());

    // Cut short inside tariffSwitchInterval.
    assert!(decode("a0 0d 80 02 0b b8 a1 03 01 01 ff 82 02 01").is_err());
    // Outer length one more than the content.
    assert!(decode("a0 0e 80 02 0b b8 a1 03 01 01 ff 82 02 01 2c").is_err());
    // The mandatory maxCallPeriodDuration is missing.
    assert!(decode("a0 05 a1 03 01 01 ff").is_err());
    // An empty SEQUENCE.
    assert!(decode("a0 00").is_err());
    // The phase 3 and phase 4 form of [1]: a primitive BOOLEAN.
    assert!(decode("a0 07 80 02 0b b8 81 01 ff").is_err());
    // A BOOLEAN of two octets.
    assert!(decode("a0 0a 80 02 0b b8 a1 04 01 02 ff ff").is_err());
    // A member ReleaseIfDurationExceeded does not have, [5].
    assert!(decode("a0 0c 80 02 0b b8 a1 06 01 01 ff 85 01 00").is_err());
    // The phase 3 tone [3] and the phase 4 audibleIndicator [3] after the
    // phase 2 members: phase 2 has no [3].
    assert!(decode("a0 07 80 02 0b b8 83 01 ff").is_err());
    assert!(decode("a0 09 80 02 0b b8 a3 03 01 01 ff").is_err());
    // An alternative the CHOICE does not have, [1].
    assert!(decode("a1 04 80 02 0b b8").is_err());
    // Octets after the value.
    assert!(decode("a0 04 80 02 0b b8 00").is_err());
    // Nothing at all.
    assert!(decode("").is_err());
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
fn apply_charging_report_phase_2() {
    // GSM 09.78 V7.1.0 clause 6.3:
    //
    //   CAMEL-CallResult ::= CHOICE {
    //     timeDurationChargingResult [0] SEQUENCE {
    //       partyToCharge   [0] ReceivingSideID,
    //       timeInformation [1] TimeInformation,
    //       callActive      [2] BOOLEAN DEFAULT TRUE } }
    //
    // The first three members of the later releases with the same tags, so
    // the one type reads all phases. A phase 2 gsmSSF sends nothing else.
    let result = CamelCallResult::TimeDurationChargingResult(TimeDurationChargingResult {
        leg_active: Some(false),
        ..TimeDurationChargingResult::new(
            ReceivingSideId::leg(LEG1),
            TimeInformation::TimeIfNoTariffSwitch(300),
        )
    });
    let arg = ApplyChargingReportArg::from_call_result(&result).unwrap();
    let ber = known_answer(
        &arg,
        "
        04 10                                  -- CallResult, an OCTET STRING
           a0 0e                               -- timeDurationChargingResult [0], 5 + 6 + 3
              a0 03 81 01 01                   --   partyToCharge [0] EXPLICIT { receivingSideID [1] leg1 }
              a1 04 80 02 01 2c                --   timeInformation [1] EXPLICIT
                                               --     { timeIfNoTariffSwitch [0] 300 = 30 s }
              82 01 00                         --   callActive [2] FALSE
        ",
    );
    assert_eq!(arg.call_result().unwrap(), result);
    let Some(d) = on_context(
        op_codes::APPLY_CHARGING_REPORT,
        &ber,
        &ac::CAP_V2_GSMSSF_TO_GSMSCF,
    ) else {
        return;
    };
    d.present("camel.timeDurationChargingResult_element")
        .show("camel.timeDurationChargingResultpartyToCharge", "1")
        .hex("camel.receivingSideID", "01")
        .show("camel.timeInformation", "0")
        .show("camel.timeIfNoTariffSwitch", "300")
        .show("camel.legActive", "False");
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
