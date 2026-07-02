//! Memory-leak check.
//!
//! A counting global allocator tracks **live bytes** (allocated − freed) — RSS is
//! too noisy (the OS/allocator retains freed pages), but live bytes are exact, so
//! a real leak shows up as monotonic growth. Two phases hammer the CAP BER codec:
//!
//!   1. **call control** — encode + decode InitialDP, Connect and EventReportBCSM
//!      for many cycles (the `rasn` BER pack/unpack + `Vec` churn path).
//!   2. **SMS** — the same for InitialDPSMS (CAMEL-for-SMS).
//!
//! Each phase asserts live bytes return to a flat baseline. Exits non-zero on a
//! leak. All fixtures are synthetic. Driven by `scripts/mem_leak_test.sh`.
//!
//! Run: `cargo run --release --example leak_check`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use rasn::types::Integer;

use gsm_cap::operations::{ConnectArg, EventReportBcsmArg, InitialDpArg, InitialDpSmsArg};
use gsm_cap::types::{EventTypeBcsm, EventTypeSms};

// ── Counting allocator ──────────────────────────────────────────────────────
static LIVE: AtomicI64 = AtomicI64::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, l, new_size);
        if !p.is_null() {
            LIVE.fetch_add(new_size as i64 - l.size() as i64, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

// ── Synthetic fixtures ───────────────────────────────────────────────────────
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

fn sample_connect() -> ConnectArg {
    ConnectArg {
        destination_routing_address: vec![vec![0x03, 0x55, 0x01, 0x23].into()],
        original_called_party_id: None,
        calling_partys_category: None,
        redirecting_party_id: None,
        generic_numbers: None,
    }
}

fn sample_event_report() -> EventReportBcsmArg {
    EventReportBcsmArg {
        event_type_bcsm: EventTypeBcsm::OAnswer,
        leg_id: Some(vec![0x02].into()),
        misc_call_info: None,
    }
}

fn sample_initial_dp_sms() -> InitialDpSmsArg {
    InitialDpSmsArg {
        service_key: Integer::from(7),
        destination_subscriber_number: Some(vec![0x91, 0x55, 0x01, 0x23].into()),
        calling_party_number: Some(vec![0x91, 0x55, 0x01, 0x88].into()),
        event_type_sms: Some(EventTypeSms::OSmsSubmission),
        imsi: Some(vec![0x00, 0x10, 0x19, 0x00, 0x00].into()),
        location_information_msc: None,
        smsc_address: Some(vec![0x91, 0x55, 0x01, 0x00].into()),
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

// ── Phase 1: call-control codec ──────────────────────────────────────────────
fn call_control_cycle(iters: usize) {
    let idp = sample_initial_dp();
    let connect = sample_connect();
    let erb = sample_event_report();
    for _ in 0..iters {
        let b = gsm_cap::encode(&idp).unwrap();
        std::hint::black_box(gsm_cap::decode::<InitialDpArg>(&b).unwrap());
        let b = gsm_cap::encode(&connect).unwrap();
        std::hint::black_box(gsm_cap::decode::<ConnectArg>(&b).unwrap());
        let b = gsm_cap::encode(&erb).unwrap();
        std::hint::black_box(gsm_cap::decode::<EventReportBcsmArg>(&b).unwrap());
    }
}

// ── Phase 2: SMS codec ───────────────────────────────────────────────────────
fn sms_cycle(iters: usize) {
    let idp_sms = sample_initial_dp_sms();
    for _ in 0..iters {
        let b = gsm_cap::encode(&idp_sms).unwrap();
        std::hint::black_box(gsm_cap::decode::<InitialDpSmsArg>(&b).unwrap());
    }
}

fn report(phase: &str, base: i64) -> i64 {
    let growth = live() - base;
    println!("  {phase}: live = {} bytes (Δ {:+})", live(), growth);
    growth
}

fn main() {
    const ITERS: usize = 100_000;
    const CYCLES: usize = 10;
    const BUDGET: i64 = 64 * 1024;

    // Phase 1: call control.
    println!("[call control] {CYCLES} x {ITERS} encode+decode round-trips (InitialDP + Connect + EventReportBCSM)");
    call_control_cycle(ITERS); // warm up
    let cc_base = live();
    for c in 1..=CYCLES {
        call_control_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), cc_base);
    }
    let cc_growth = live() - cc_base;

    // Phase 2: SMS.
    println!("\n[sms] {CYCLES} x {ITERS} encode+decode round-trips (InitialDPSMS)");
    sms_cycle(ITERS); // warm up
    let sms_base = live();
    for c in 1..=CYCLES {
        sms_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), sms_base);
    }
    let sms_growth = live() - sms_base;

    // Verdict.
    println!();
    let mut ok = true;
    if cc_growth > BUDGET {
        eprintln!("FAIL: call-control live bytes grew {cc_growth} (> {BUDGET})");
        ok = false;
    }
    if sms_growth > BUDGET {
        eprintln!("FAIL: SMS live bytes grew {sms_growth} (> {BUDGET})");
        ok = false;
    }
    if !ok {
        std::process::exit(1);
    }
    println!("PASS: call-control Δ {cc_growth} ≤ {BUDGET}; SMS Δ {sms_growth} ≤ {BUDGET}");
}
