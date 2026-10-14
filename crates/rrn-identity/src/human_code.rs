//! Short codes that two people read aloud and compare.
//!
//! A ceremony that a human authenticates — pairing a device, confirming a
//! recovery request — ends with each side showing a code derived from a
//! digest of the ceremony's transcript. This module renders such a digest in
//! Crockford base32, which drops the letters most often misread (`I`, `L`,
//! `O`, `U`), and normalizes what a person types back so a lowercase letter, a
//! missing hyphen, or an `O` typed for a `0` still matches.
//!
//! The rendering is a cross-implementation contract: the phone reaches it
//! through the mobile FFI rather than re-implementing it, and
//! `docs/spec/pairing.md` pins it.

/// Crockford base32: digits, then the uppercase letters without `I`, `L`, `O`,
/// and `U`.
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The most characters a 32-byte digest can fill: `floor(256 / 5)`.
pub const MAX_CHARS: usize = 51;

/// Renders the first `chars × 5` bits of `digest`, read big-endian, as
/// Crockford base32, with a `-` after every `group` characters (but not at
/// the end). `chars` is clamped to [`MAX_CHARS`]; a `group` of 0 inserts no
/// hyphens.
pub fn render(digest: &[u8; 32], chars: usize, group: usize) -> String {
    let chars = chars.min(MAX_CHARS);
    let mut out = String::with_capacity(chars + chars / group.max(1));
    for i in 0..chars {
        if group > 0 && i > 0 && i % group == 0 {
            out.push('-');
        }
        out.push(char::from(ALPHABET[usize::from(five_bits(digest, i * 5))]));
    }
    out
}

/// The five bits of `digest` starting at bit `start` (bit 0 is the most
/// significant bit of byte 0). `start + 5 <= 256` for every caller.
fn five_bits(digest: &[u8; 32], start: usize) -> u8 {
    let byte = start / 8;
    let hi = u16::from(digest[byte]) << 8;
    let lo = digest.get(byte + 1).copied().map_or(0, u16::from);
    let window = hi | lo;
    let shift = 16 - 5 - (start % 8);
    ((window >> shift) & 0x1f) as u8
}

/// Canonicalizes a typed code for comparison: uppercase, hyphens and
/// whitespace dropped, and the Crockford aliases folded (`O` → `0`, `I` and
/// `L` → `1`). Any other character is kept as typed, so a code containing one
/// simply fails to match.
pub fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_known_bits_big_endian() {
        // 0b00000_00001_00010_00011_11111 ... → "0123Z"
        let mut digest = [0u8; 32];
        // bits: 00000 00001 00010 00011 11111 → pack big-endian.
        let bits: u64 = 0b00000_00001_00010_00011_11111;
        let packed = bits << (64 - 25);
        digest[..8].copy_from_slice(&packed.to_be_bytes());
        assert_eq!(render(&digest, 5, 0), "0123Z");
    }

    #[test]
    fn all_ones_and_all_zeros() {
        assert_eq!(render(&[0xff; 32], 10, 5), "ZZZZZ-ZZZZZ");
        assert_eq!(render(&[0x00; 32], 10, 5), "00000-00000");
    }

    #[test]
    fn groups_and_clamps() {
        let digest = [0xa5; 32];
        let full = render(&digest, 200, 0);
        assert_eq!(full.len(), MAX_CHARS);
        assert_eq!(render(&digest, 6, 3).len(), 7);
        assert_eq!(render(&digest, 6, 3).as_bytes()[3], b'-');
        assert_eq!(render(&digest, 0, 5), "");
    }

    #[test]
    fn normalize_accepts_aliases_and_hyphens() {
        assert_eq!(normalize("abcde-fghjk"), "ABCDEFGHJK");
        assert_eq!(normalize(" o0iIlL-1 "), "0011111");
        assert_eq!(normalize("12 34\t5"), "12345");
        // A rendered code normalizes to itself minus its hyphens.
        let code = render(&[0x5c; 32], 10, 5);
        assert_eq!(normalize(&code), code.replace('-', ""));
        assert_eq!(normalize(&code.to_lowercase()), code.replace('-', ""));
    }
}
