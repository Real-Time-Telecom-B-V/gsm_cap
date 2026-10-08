//! Independent-decoder harness: hand a CAP argument produced by this crate to
//! Wireshark's CAMEL dissector and read back the fields it decoded.
//!
//! A round-trip through our own decoder cannot catch a mistake that the encoder
//! and the decoder share (a wrong tag number, a missing EXPLICIT wrapper, a
//! SEQUENCE that should not be there). `tshark` is generated from the ASN.1 of
//! 3GPP TS 29.078 / TS 29.002 by a different toolchain, so it does not share
//! our bugs.
//!
//! The argument is wrapped the way it travels on a signalling link:
//!
//! ```text
//!   CAP argument
//!     -> TCAP Begin (AARQ with the application context) or Continue, one
//!        Invoke / ReturnResultLast carrying the operation code
//!     -> SCCP UDT, called and calling SSN 146 (CAP)
//!     -> M3UA DATA (SI 3)
//!     -> text2pcap dummy SCTP/IP/Ethernet (payload protocol identifier 3)
//! ```
//!
//! and dissected with `tshark -T pdml`, which yields every decoded field with
//! its abbreviation, its display value and its raw octets. Tests assert on
//! those fields. A dissection that merely does not crash proves nothing.
//!
//! `tshark` and `text2pcap` are optional. When either is missing the helpers
//! return `None` after printing a `SKIP` line, and the byte-level known-answer
//! vectors in the same test files still pin the encoding. Set
//! `GSM_CAP_REQUIRE_TSHARK=1` to turn a missing tool into a test failure.
//!
//! All addresses are synthetic: point codes 1 and 2, global titles in the
//! fictional `+1 555 01xx` range.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use rasn::types::{Any, ObjectIdentifier};
use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use tcap::{
    Begin, Component, Continue, DialoguePortion, Invoke, OperationCode, ReturnResult,
    ReturnResultValue, TcapMessage,
};

/// How the CAP argument is carried in TCAP.
pub enum Carrier<'a> {
    /// TCAP Begin with an AARQ naming this application context, one Invoke.
    Begin(&'a ObjectIdentifier),
    /// TCAP Continue without a dialogue portion, one Invoke.
    Continue,
    /// TCAP Continue without a dialogue portion, one ReturnResultLast.
    Result,
}

/// One field of the dissection, as `tshark -T pdml` reports it.
#[derive(Debug, Clone)]
pub struct Field {
    /// Field abbreviation, for example `camel.serviceKey`.
    pub name: String,
    /// Display value, for example `42`.
    pub show: String,
    /// The labelled line Wireshark prints, for example `serviceKey: 42`.
    pub showname: String,
    /// Raw octets covered by the field, lowercase hex. For a primitive BER
    /// type these are the content octets.
    pub value: String,
}

/// A dissected frame.
#[derive(Debug, Clone)]
pub struct Dissection {
    pub fields: Vec<Field>,
    pub pdml: String,
}

impl Dissection {
    /// Raw octets (hex) of every occurrence of `name`, in frame order.
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|f| f.name == name)
            .map(|f| f.value.as_str())
            .collect()
    }

    /// Display value of every occurrence of `name`, in frame order.
    pub fn shows(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|f| f.name == name)
            .map(|f| f.show.as_str())
            .collect()
    }

    /// Assert `name` was dissected exactly once with these raw octets.
    #[track_caller]
    pub fn hex(&self, name: &str, expected: &str) -> &Self {
        assert_eq!(
            self.values(name),
            vec![expected],
            "raw octets of {name}\n{}",
            self.summary()
        );
        self
    }

    /// Assert `name` was dissected with these raw octets, once per entry.
    #[track_caller]
    pub fn hex_all(&self, name: &str, expected: &[&str]) -> &Self {
        assert_eq!(
            self.values(name),
            expected,
            "raw octets of {name}\n{}",
            self.summary()
        );
        self
    }

    /// Assert `name` was dissected exactly once with this display value.
    #[track_caller]
    pub fn show(&self, name: &str, expected: &str) -> &Self {
        assert_eq!(
            self.shows(name),
            vec![expected],
            "display value of {name}\n{}",
            self.summary()
        );
        self
    }

    /// Assert `name` was dissected with these display values, once per entry.
    #[track_caller]
    pub fn show_all(&self, name: &str, expected: &[&str]) -> &Self {
        assert_eq!(
            self.shows(name),
            expected,
            "display value of {name}\n{}",
            self.summary()
        );
        self
    }

    /// Assert `name` is present exactly once (for NULL members and constructed
    /// members whose content is asserted through their children).
    #[track_caller]
    pub fn present(&self, name: &str) -> &Self {
        assert_eq!(
            self.values(name).len(),
            1,
            "{name} should be dissected exactly once\n{}",
            self.summary()
        );
        self
    }

    /// Assert `name` does not occur.
    #[track_caller]
    pub fn absent(&self, name: &str) -> &Self {
        assert!(
            self.values(name).is_empty(),
            "{name} should not be dissected\n{}",
            self.summary()
        );
        self
    }

    /// The reasons this dissection is not clean, empty when it is.
    ///
    /// Only TCAP and what it carries is judged. The layers below are scaffolding
    /// built here, and Wireshark labels the synthetic point codes "Unknown"
    /// because no operator owns them.
    pub fn problems(&self) -> Vec<String> {
        let upper = self
            .fields
            .iter()
            .position(|f| f.name == "tcap")
            .unwrap_or(0);
        let mut out = Vec::new();
        for f in &self.fields[upper..] {
            let name = f.name.as_str();
            let bad_name = name.starts_with("_ws.malformed")
                || name.starts_with("_ws.expert")
                || name.starts_with("_ws.unreassembled")
                || name.contains(".error")
                || name.contains("unknown");
            let label = f.showname.to_ascii_lowercase();
            let bad_label = label.contains("malformed")
                || label.contains("unknown")
                || label.contains("ber error")
                || label.contains("expert info");
            if bad_name || bad_label {
                out.push(format!("{name}: {}", f.showname));
            }
        }
        out
    }

    /// The upper-layer fields, one per line, for assertion messages.
    pub fn summary(&self) -> String {
        self.fields
            .iter()
            .filter(|f| {
                ["tcap.", "camel.", "gsm_map.", "inap.", "ber.", "_ws."]
                    .iter()
                    .any(|p| f.name.starts_with(p))
            })
            .map(|f| format!("  {} = {} [{}]", f.name, f.show, f.value))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn tool(name: &str) -> bool {
    Command::new(name)
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether `tshark` and `text2pcap` can be run. Prints a `SKIP` line when not.
pub fn tshark_available() -> bool {
    if tool("tshark") && tool("text2pcap") {
        return true;
    }
    let message = "tshark / text2pcap not found: the independent Wireshark dissection \
                   is skipped, only the byte-level vectors run";
    assert!(
        std::env::var_os("GSM_CAP_REQUIRE_TSHARK").is_none(),
        "GSM_CAP_REQUIRE_TSHARK is set but {message}"
    );
    eprintln!("SKIP: {message}");
    false
}

fn address(digits: &str) -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: digits.to_string(),
    };
    SccpAddress::with_gt(gt, Some(SubsystemNumber::Cap))
}

/// TCAP message carrying `argument` (already BER-encoded) for `operation`.
pub fn tcap_message(operation: i64, argument: Option<&[u8]>, carrier: &Carrier) -> Vec<u8> {
    let parameter = argument.map(|a| Any::new(a.to_vec()));
    let operation_code = OperationCode::Local(operation);
    let message = match carrier {
        Carrier::Begin(context) => TcapMessage::Begin(Begin {
            otid: vec![0x00, 0x00, 0x10, 0x01].into(),
            dialogue_portion: Some(DialoguePortion::aarq(context)),
            components: Some(vec![Component::Invoke(Invoke {
                invoke_id: 1,
                linked_id: None,
                operation_code,
                parameter,
            })]),
        }),
        Carrier::Continue => TcapMessage::Continue(Continue {
            otid: vec![0x00, 0x00, 0x20, 0x02].into(),
            dtid: vec![0x00, 0x00, 0x10, 0x01].into(),
            dialogue_portion: None,
            components: Some(vec![Component::Invoke(Invoke {
                invoke_id: 2,
                linked_id: None,
                operation_code,
                parameter,
            })]),
        }),
        Carrier::Result => TcapMessage::Continue(Continue {
            otid: vec![0x00, 0x00, 0x20, 0x02].into(),
            dtid: vec![0x00, 0x00, 0x10, 0x01].into(),
            dialogue_portion: None,
            components: Some(vec![Component::ReturnResultLast(ReturnResult {
                invoke_id: 2,
                result: Some(ReturnResultValue {
                    operation_code,
                    parameter,
                }),
            })]),
        }),
    };
    tcap::encode(&message).expect("tcap encode")
}

/// SCCP UDT (called and calling SSN 146) inside an M3UA DATA message.
///
/// M3UA (RFC 4666): common header `version 1, reserved, class 1 (Transfer),
/// type 1 (DATA), length`, then one Protocol Data parameter (tag 0x0210):
/// `OPC, DPC, SI 3 (SCCP), NI 0, MP 0, SLS 0, user data`, padded to four octets.
pub fn m3ua_frame(tcap: Vec<u8>) -> Vec<u8> {
    let udt = UnitData::new(address("15550199001"), address("15550100123"), tcap)
        .encode()
        .expect("sccp encode");

    let mut parameter = Vec::new();
    parameter.extend_from_slice(&1u32.to_be_bytes()); // OPC
    parameter.extend_from_slice(&2u32.to_be_bytes()); // DPC
    parameter.extend_from_slice(&[3, 0, 0, 0]); // SI, NI, MP, SLS
    parameter.extend_from_slice(&udt);
    let parameter_length = 4 + parameter.len();
    let padding = (4 - parameter_length % 4) % 4;

    let mut frame = vec![1, 0, 1, 1];
    frame.extend_from_slice(&((8 + parameter_length + padding) as u32).to_be_bytes());
    frame.extend_from_slice(&0x0210u16.to_be_bytes());
    frame.extend_from_slice(&(parameter_length as u16).to_be_bytes());
    frame.extend_from_slice(&parameter);
    frame.resize(frame.len() + padding, 0);
    frame
}

fn attribute(line: &str, key: &str) -> Option<String> {
    let needle = format!(" {key}=\"");
    let start = line.find(&needle)? + needle.len();
    let end = line[start..].find('"')? + start;
    Some(
        line[start..end]
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

fn parse_pdml(pdml: &str) -> Vec<Field> {
    pdml.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            if !(line.starts_with("<field ") || line.starts_with("<proto ")) {
                return None;
            }
            Some(Field {
                name: attribute(line, "name")?,
                show: attribute(line, "show").unwrap_or_default(),
                showname: attribute(line, "showname").unwrap_or_default(),
                value: attribute(line, "value").unwrap_or_default(),
            })
        })
        .collect()
}

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Dissect one M3UA frame with `tshark`. `None` when the tools are missing.
pub fn dissect_frame(frame: &[u8]) -> Option<Dissection> {
    if !tshark_available() {
        return None;
    }
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "gsm_cap-tshark-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).expect("temporary directory");
    let dump = directory.join("frame.txt");
    let capture = directory.join("frame.pcap");

    let mut text = String::from("000000");
    for byte in frame {
        text.push_str(&format!(" {byte:02x}"));
    }
    text.push('\n');
    std::fs::write(&dump, text).expect("write hex dump");

    // -S: dummy SCTP DATA chunk, ports 2905 (M3UA), payload protocol id 3.
    let converted = Command::new("text2pcap")
        .args(["-q", "-S", "2905,2905,3"])
        .arg(&dump)
        .arg(&capture)
        .output()
        .expect("run text2pcap");
    assert!(
        converted.status.success(),
        "text2pcap failed: {}",
        String::from_utf8_lossy(&converted.stderr)
    );

    // An empty configuration directory keeps the run independent of whatever
    // protocol preferences the local Wireshark profile carries.
    let dissected = Command::new("tshark")
        .env("WIRESHARK_CONFIG_DIR", &directory)
        .env("XDG_CONFIG_HOME", &directory)
        .arg("-r")
        .arg(&capture)
        .args(["-T", "pdml"])
        .output()
        .expect("run tshark");
    assert!(
        dissected.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&dissected.stderr)
    );
    let _ = std::fs::remove_dir_all(&directory);

    let pdml = String::from_utf8_lossy(&dissected.stdout).into_owned();
    let fields = parse_pdml(&pdml);
    Some(Dissection { fields, pdml })
}

/// Dissect `argument` as the parameter of `operation` and check the frame is
/// clean: Wireshark recognised CAMEL, read the operation code we sent, and
/// reported nothing malformed, unknown or erroneous anywhere in the frame.
#[track_caller]
pub fn dissect(operation: i64, argument: Option<&[u8]>, carrier: Carrier) -> Option<Dissection> {
    let dissection = dissect_frame(&m3ua_frame(tcap_message(operation, argument, &carrier)))?;
    assert_clean(&dissection, operation);
    Some(dissection)
}

/// Same wrapping as [`dissect`] without the cleanliness assertion, for tests
/// that document what Wireshark rejects.
pub fn dissect_unchecked(
    operation: i64,
    argument: Option<&[u8]>,
    carrier: Carrier,
) -> Option<Dissection> {
    dissect_frame(&m3ua_frame(tcap_message(operation, argument, &carrier)))
}

#[track_caller]
pub fn assert_clean(dissection: &Dissection, operation: i64) {
    assert!(
        dissection.fields.iter().any(|f| f.name == "camel"),
        "Wireshark did not hand the frame to its CAMEL dissector\n{}",
        dissection.summary()
    );
    assert_eq!(
        dissection.shows("camel.local"),
        vec![operation.to_string()],
        "operation code\n{}",
        dissection.summary()
    );
    let problems = dissection.problems();
    assert!(
        problems.is_empty(),
        "Wireshark rejects this encoding:\n  {}\n{}",
        problems.join("\n  "),
        dissection.summary()
    );
}

/// Bytes of a hand-written vector: hex octets, free whitespace, and `--`
/// comments running to the end of the line.
pub fn vector(text: &str) -> Vec<u8> {
    let octets: String = text
        .lines()
        .map(|line| line.split("--").next().unwrap_or(""))
        .flat_map(str::split_whitespace)
        .collect();
    hex::decode(&octets).unwrap_or_else(|e| panic!("bad hex in vector ({e}): {octets}"))
}

/// The known-answer check, both directions, against a vector that was
/// assembled by hand from the ASN.1 and not produced by this crate:
/// `value` must encode to exactly those bytes, and those bytes must decode to
/// exactly `value`. Returns the bytes.
#[track_caller]
pub fn known_answer<T>(value: &T, hand_assembled: &str) -> Vec<u8>
where
    T: rasn::Encode + rasn::Decode + PartialEq + std::fmt::Debug,
{
    let expected = vector(hand_assembled);
    let encoded = gsm_cap::encode(value).expect("encode");
    assert_eq!(
        hex::encode(&encoded),
        hex::encode(&expected),
        "encoding differs from the hand-assembled vector"
    );
    let decoded: T = gsm_cap::decode(&expected).expect("decode the hand-assembled vector");
    assert_eq!(&decoded, value, "decoding the hand-assembled vector");
    expected
}
