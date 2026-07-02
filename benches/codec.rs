//! Codec micro-benchmarks: CAP operation-argument BER encode/decode throughput.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! Every fixture is built from the public API with **synthetic** values (fictional
//! `+1-555-01xx` numbers, made-up IMSI/keys), so the benches measure exactly the
//! work this crate does — `rasn` BER pack/unpack of the CAP argument types — with
//! no I/O in the path. Covers the classic call-control triad InitialDP / Connect /
//! EventReportBCSM.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rasn::types::Integer;

use gsm_cap::operations::{ConnectArg, EventReportBcsmArg, InitialDpArg};
use gsm_cap::types::EventTypeBcsm;

/// A representative InitialDP (gsmSSF → gsmSCF): service key + a handful of the
/// common optional fields populated with synthetic wire bytes.
fn sample_initial_dp() -> InitialDpArg {
    InitialDpArg {
        service_key: Integer::from(42),
        called_party_number: Some(vec![0x03, 0x55, 0x01, 0x23].into()),
        calling_party_number: Some(vec![0x03, 0x55, 0x01, 0x99].into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: None,
        imsi: Some(vec![0x00, 0x10, 0x19, 0x00, 0x00].into()),
        location_information: None,
        call_reference_number: Some(vec![0xDE, 0xAD, 0xBE, 0xEF].into()),
        msc_address: Some(vec![0x91, 0x55, 0x01, 0x00].into()),
        called_party_bcd_number: None,
        time_and_timezone: None,
    }
}

/// A representative Connect (gsmSCF → gsmSSF): a single destination routing
/// address.
fn sample_connect() -> ConnectArg {
    ConnectArg {
        destination_routing_address: vec![vec![0x03, 0x55, 0x01, 0x23].into()],
        original_called_party_id: None,
        calling_partys_category: None,
        redirecting_party_id: None,
        generic_numbers: None,
    }
}

/// A representative EventReportBCSM (gsmSSF → gsmSCF): an O-Answer report.
fn sample_event_report() -> EventReportBcsmArg {
    EventReportBcsmArg {
        event_type_bcsm: EventTypeBcsm::OAnswer,
        leg_id: Some(vec![0x02].into()),
        misc_call_info: None,
    }
}

fn bench_codec(c: &mut Criterion) {
    let initial_dp = sample_initial_dp();
    let connect = sample_connect();
    let event_report = sample_event_report();

    let initial_dp_ber = gsm_cap::encode(&initial_dp).expect("encode idp");
    let connect_ber = gsm_cap::encode(&connect).expect("encode connect");
    let event_report_ber = gsm_cap::encode(&event_report).expect("encode erb");

    let mut g = c.benchmark_group("codec");
    g.throughput(Throughput::Elements(1));

    g.bench_function("initial_dp/encode", |b| {
        b.iter_batched(
            || initial_dp.clone(),
            |v| gsm_cap::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("initial_dp/decode", |b| {
        b.iter(|| gsm_cap::decode::<InitialDpArg>(&initial_dp_ber).unwrap())
    });

    g.bench_function("connect/encode", |b| {
        b.iter_batched(
            || connect.clone(),
            |v| gsm_cap::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("connect/decode", |b| {
        b.iter(|| gsm_cap::decode::<ConnectArg>(&connect_ber).unwrap())
    });

    g.bench_function("event_report_bcsm/encode", |b| {
        b.iter_batched(
            || event_report.clone(),
            |v| gsm_cap::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("event_report_bcsm/decode", |b| {
        b.iter(|| gsm_cap::decode::<EventReportBcsmArg>(&event_report_ber).unwrap())
    });

    g.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
