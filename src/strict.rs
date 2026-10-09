//! A guard against members that disappear during decoding.
//!
//! `rasn` 0.28 decodes an OPTIONAL member behind an EXPLICIT tag by trying to
//! decode it and, if anything inside fails, reporting the member as absent
//! (`decode_optional_with_explicit_prefix`: `.or_else(|_| Ok(None))`). By then
//! the member's octets have been consumed, so no "unexpected extra data" error
//! follows either. In CAP every member whose type is a CHOICE is explicitly
//! tagged (`legID`, `partyToCharge`, `eventSpecificInformationBCSM`, ...), so
//! a peer that sends one of those with content this crate cannot read would
//! get a successful decode with the member silently gone. A gsmSCF would then
//! act on a report that has lost its leg, or its cause.
//!
//! The guard is structural and does not depend on which type is decoded: the
//! decoded value is encoded again, and the two encodings are walked side by
//! side. Every element this crate would emit must be met by an element with
//! the same tag on the wire, and the wire must hold nothing more. Contents of
//! primitive elements are not compared, since BER lets a sender write the same
//! value in more than one way (any non-zero octet for TRUE, long or
//! indefinite lengths), and neither is the primitive / constructed bit, which
//! `rasn` does not check on an explicit wrapper either.

/// Nesting allowed while walking. CAP arguments nest about ten levels deep;
/// the bound keeps a hostile open-type value from exhausting the stack.
const MAX_DEPTH: usize = 64;

struct Element<'a> {
    class: u8,
    number: u32,
    constructed: bool,
    content: &'a [u8],
    rest: &'a [u8],
}

impl Element<'_> {
    fn tag(&self) -> String {
        let class = match self.class {
            0 => "UNIVERSAL ",
            1 => "APPLICATION ",
            2 => "",
            _ => "PRIVATE ",
        };
        format!("[{class}{}]", self.number)
    }
}

/// Split one tag-length-value off the front of `input`.
fn element(input: &[u8], depth: usize) -> Result<Element<'_>, String> {
    if depth > MAX_DEPTH {
        return Err(format!("nesting deeper than {MAX_DEPTH} levels"));
    }
    let (&first, mut rest) = input
        .split_first()
        .ok_or_else(|| "truncated: no identifier octet".to_string())?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut number = u32::from(first & 0x1f);
    if number == 0x1f {
        // High tag number form: base 128, most significant group first.
        number = 0;
        loop {
            let (&octet, tail) = rest
                .split_first()
                .ok_or_else(|| "truncated tag number".to_string())?;
            rest = tail;
            number = number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(octet & 0x7f)))
                .ok_or_else(|| "tag number too large".to_string())?;
            if octet & 0x80 == 0 {
                break;
            }
        }
    }

    let (&length_octet, rest) = rest
        .split_first()
        .ok_or_else(|| "truncated: no length octet".to_string())?;
    if length_octet == 0x80 {
        // Indefinite form: the content runs to the matching end-of-contents.
        let mut cursor = rest;
        loop {
            if let Some(after) = cursor.strip_prefix(&[0x00, 0x00]) {
                let content = &rest[..rest.len() - cursor.len()];
                return Ok(Element {
                    class,
                    number,
                    constructed,
                    content,
                    rest: after,
                });
            }
            cursor = element(cursor, depth + 1)?.rest;
        }
    }
    let length = if length_octet < 0x80 {
        usize::from(length_octet)
    } else {
        let count = usize::from(length_octet & 0x7f);
        if count > std::mem::size_of::<usize>() || rest.len() < count {
            return Err("unusable length".to_string());
        }
        rest[..count]
            .iter()
            .fold(0usize, |value, &octet| (value << 8) | usize::from(octet))
    };
    let rest = if length_octet < 0x80 {
        rest
    } else {
        &rest[usize::from(length_octet & 0x7f)..]
    };
    if rest.len() < length {
        return Err("truncated content".to_string());
    }
    let (content, rest) = rest.split_at(length);
    Ok(Element {
        class,
        number,
        constructed,
        content,
        rest,
    })
}

fn walk(mut wire: &[u8], mut canonical: &[u8], depth: usize) -> Result<(), String> {
    while !canonical.is_empty() {
        let expected = element(canonical, depth)?;
        if wire.is_empty() {
            // Cannot happen for a value rasn just decoded from `wire`.
            return Err(format!("{} is missing on the wire", expected.tag()));
        }
        let found = element(wire, depth)?;
        if (found.class, found.number) != (expected.class, expected.number) {
            return Err(format!(
                "member {} is present but its content could not be decoded",
                found.tag()
            ));
        }
        if expected.constructed {
            walk(found.content, expected.content, depth + 1)?;
        }
        wire = found.rest;
        canonical = expected.rest;
    }
    if wire.is_empty() {
        return Ok(());
    }
    match element(wire, depth) {
        Ok(found) => Err(format!(
            "member {} is present but its content could not be decoded",
            found.tag()
        )),
        Err(_) => Err(format!("{} trailing octets", wire.len())),
    }
}

/// Check that `canonical`, the encoding of the value decoded from `wire`,
/// accounts for every element of `wire`.
pub(crate) fn nothing_dropped(wire: &[u8], canonical: &[u8]) -> Result<(), String> {
    walk(wire, canonical, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_encodings_pass() {
        let bytes = [0x30, 0x08, 0x80, 0x01, 0x07, 0xa3, 0x03, 0x81, 0x01, 0x02];
        assert_eq!(nothing_dropped(&bytes, &bytes), Ok(()));
    }

    #[test]
    fn a_dropped_member_is_reported_with_its_tag() {
        // [3] is on the wire, the re-encoding has only [0].
        let wire = [0x30, 0x08, 0x80, 0x01, 0x07, 0xa3, 0x03, 0x80, 0x01, 0x02];
        let canonical = [0x30, 0x03, 0x80, 0x01, 0x07];
        let error = nothing_dropped(&wire, &canonical).unwrap_err();
        assert!(error.contains("[3]"), "{error}");
    }

    #[test]
    fn a_member_dropped_before_another_is_reported() {
        // [2] vanished, [4] survived: the walk meets [2] where it expects [4].
        let wire = [0x30, 0x06, 0x82, 0x01, 0x02, 0x84, 0x01, 0x00];
        let canonical = [0x30, 0x03, 0x84, 0x01, 0x00];
        let error = nothing_dropped(&wire, &canonical).unwrap_err();
        assert!(error.contains("[2]"), "{error}");
    }

    #[test]
    fn length_forms_do_not_matter() {
        let canonical = [0x30, 0x05, 0xa2, 0x03, 0x80, 0x01, 0x02];
        let long = [0x30, 0x81, 0x06, 0xa2, 0x81, 0x03, 0x80, 0x01, 0x02];
        let indefinite = [
            0x30, 0x80, 0xa2, 0x80, 0x80, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(nothing_dropped(&long, &canonical), Ok(()));
        assert_eq!(nothing_dropped(&indefinite, &canonical), Ok(()));
    }

    #[test]
    fn primitive_content_is_not_compared() {
        // BOOLEAN TRUE as 01 on the wire, FF when encoded again.
        assert_eq!(
            nothing_dropped(
                &[0x30, 0x03, 0x81, 0x01, 0x01],
                &[0x30, 0x03, 0x81, 0x01, 0xff]
            ),
            Ok(())
        );
    }

    #[test]
    fn high_tag_numbers_are_read() {
        let wire = [0x30, 0x07, 0x9f, 0x32, 0x00, 0xbf, 0x34, 0x01, 0x00];
        let canonical = [0x30, 0x03, 0x9f, 0x32, 0x00];
        let error = nothing_dropped(&wire, &canonical).unwrap_err();
        assert!(error.contains("[52]"), "{error}");
    }

    #[test]
    fn trailing_octets_after_the_value_are_reported() {
        let error = nothing_dropped(&[0x04, 0x01, 0x15, 0xff], &[0x04, 0x01, 0x15]).unwrap_err();
        assert!(error.contains("trailing"), "{error}");
    }

    #[test]
    fn nesting_is_bounded() {
        // 100 nested indefinite-length constructed elements.
        let mut wire = Vec::new();
        for _ in 0..100 {
            wire.extend_from_slice(&[0x30, 0x80]);
        }
        for _ in 0..100 {
            wire.extend_from_slice(&[0x00, 0x00]);
        }
        assert!(nothing_dropped(&wire, &wire).is_err());
    }
}
