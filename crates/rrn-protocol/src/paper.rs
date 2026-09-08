//! Paper / QR text encodings for DTN carriage over paper (T2.5.1, ADR-0020;
//! Overview §10.3 Class 4 "paper fallback").
//!
//! When every electronic carrier is gone — no internet, no LoRa, no SMS — signed
//! bytes still move on paper: a member prints QR codes, a courier carries the
//! sheets, the station scans them back. This module is the text layer of that
//! fallback: the string forms a QR code carries, and the codecs that split a
//! payload across several QRs and reassemble it. It is pure codec — no image
//! rendering, no PDF layout, no scanning (that is T2.5.2 for the CLI and the
//! mobile repo for phones).
//!
//! # What travels, and how it is framed
//!
//! Three families of signed bytes cross on paper, each with its own prefix so one
//! scanner entry point ([`classify`]) can route a scanned string without guessing:
//!
//! - **Multi-part payloads** — [`crate::bundle::Bundle`]s and receipt envelopes
//!   ([`crate::receipt::encode_signed`]) exceed one QR's practical capacity, so
//!   they are split into ordered **paper chunks** under the [`MULTIPART_PREFIX`]
//!   (`rrnp:`) and rebuilt by a [`PaperReassembler`].
//! - **Certificates** — a station-signed `HeadroomCertificate` (`rrn_ledger`) envelope
//!   is small and rides in a single QR under [`CERT_PREFIX`] (`rrncert:`).
//! - **Spend vouchers** — the offline point-of-sale form: a [`SpendVoucher`]
//!   bundling the cert-backed proposal, its certificate, and the payer's presented
//!   spend history (exactly the inputs of the mobile FFI's `offline_spend_verify`,
//!   ADR-0021 §3) under [`SPEND_PREFIX`] (`rrnspend:`), single-QR when it fits and
//!   [`MULTIPART_PREFIX`] chunks (kind letter `s`) when it does not.
//!
//! # The chunk header is human-sortable plumbing, not a security boundary
//!
//! Unlike [`crate::framing`]'s binary frame header, a paper chunk is *text*,
//! self-describing, and human-checkable: a person can read the grouping id and the
//! "sheet 2 of 5" counter off the sheet. That plumbing is unauthenticated — a
//! [`payload_id8`] is only the first 8 base64url characters of the payload's
//! Blake3 hash, an accidental-mixing guard, not an integrity proof. Real integrity
//! lives, as everywhere in this crate (ADR-0008/0020), in the signatures *inside*
//! the carried bytes: a reassembled bundle's entries and a receipt's station
//! signature are verified by the same code the electronic path uses. Reassembly
//! recomputes the full Blake3 over the concatenation and checks its `payload_id8`
//! matches the sheets' claim, so a mis-collated set of sheets is caught, and a
//! caller holding an independently-known full id (a `bundle_id`) can compare all
//! 32 bytes by hashing the returned payload.
//!
//! # Encoding alphabet
//!
//! All binary payloads in these forms are **base64url without padding** (RFC 4648
//! §5). This diverges from the pre-existing recovery-shard QR (§2 of
//! `docs/spec/qr-payloads.md`), which uses standard base64 with padding and is
//! left unchanged; the new forms use base64url so a chunk string is URL- and
//! filename-safe and contains no `/` (which would collide with the chunk field
//! separator) and no `+`/`=` (rejected as [`PaperError::BadAlphabet`]).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::serialize::checked_from_data;

/// Scheme prefix of a multi-part paper chunk (`rrnp:<kind>/<id8>/<i>/<n>/<data>`).
pub const MULTIPART_PREFIX: &str = "rrnp:";
/// Scheme prefix of a single-QR certificate (`rrncert:<base64url>`).
pub const CERT_PREFIX: &str = "rrncert:";
/// Scheme prefix of a spend voucher (`rrnspend:<base64url>`, or `rrnp:` chunks
/// with kind letter `s` when it exceeds one QR).
pub const SPEND_PREFIX: &str = "rrnspend:";

// Pre-existing QR forms `classify` recognizes (but does not parse) so one scanner
// entry point can route every code (see `docs/spec/qr-payloads.md` §§1–2).
/// Scheme prefix of a recovery-shard QR (`rrnrecovery:<base64>`, §2).
pub const RECOVERY_PREFIX: &str = "rrnrecovery:";
/// Scheme prefix of the `rrn:` address URI envelope (`rrn:address?…`, §1).
pub const URI_PREFIX: &str = "rrn:";
/// Leading characters of a bare bech32m address (`rrn1…`, HRP `rrn`, §1).
pub const ADDRESS_PREFIX: &str = "rrn1";

/// The most chunks one multi-part payload may be split into. Bounds the "sheet
/// `i` of `n`" counter and keeps a paper document human-manageable. A payload
/// needing more is refused at [`encode_chunks`].
pub const MAX_CHUNKS: usize = 64;

/// Raw payload bytes per multi-part chunk. Chosen so the emitted QR string stays
/// within the normative per-QR budget: base64url expands 3 bytes to 4 characters,
/// so 720 bytes → 960 characters of `data`, plus ≤ 22 characters of prefix and
/// header fields → ≤ 982 characters total (well under [`MAX_QR_TEXT_CHARS`] and
/// the ≤ 1100 acceptance bound).
///
/// **Divergence from the T2.5.1 sketch (noted per PROCESS.md rule 3):** the ticket
/// text said "raw payload bytes split every 1000 bytes", but 1000 raw bytes
/// base64url-encode to 1334 characters, which exceeds both the ≤ 1000-byte per-QR
/// budget (measured on the QR's byte-mode text) and the ticket's own "every
/// emitted string ≤ 1100 chars" test. The behavioral requirements — a chunk fits a
/// mid-size QR, and every emitted string ≤ 1100 chars — are preserved exactly; the
/// slice size is sized to satisfy them.
pub const CHUNK_PAYLOAD_BYTES: usize = 720;

/// Largest raw payload a single-QR form (`rrncert:` / `rrnspend:`) may carry, so
/// its emitted string stays within [`MAX_QR_TEXT_CHARS`]: 740 bytes → 987
/// base64url characters, plus the ≤ 9-character prefix → ≤ 996 characters.
pub const SINGLE_QR_MAX_BYTES: usize = 740;

/// The base64url (no-pad) character length of `n` raw bytes: `ceil(n·4/3)`. Used
/// to bound an *incoming* field's decoded size *before* decoding it, so a hostile
/// string cannot force a large allocation on the way in.
const fn b64u_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Largest `data` field (in base64url characters) a single chunk may carry — the
/// encoding of [`CHUNK_PAYLOAD_BYTES`]. Enforced on decode so a reassembler's
/// per-payload memory is bounded by `count × CHUNK_PAYLOAD_BYTES` (≤ ~46 KiB), the
/// bound the threat model relies on (mirrors [`crate::framing`]'s `chunk_len`
/// guard).
pub const MAX_CHUNK_DATA_CHARS: usize = b64u_len(CHUNK_PAYLOAD_BYTES);

/// Largest single-QR body (`rrncert:` / `rrnspend:`) in base64url characters — the
/// encoding of [`SINGLE_QR_MAX_BYTES`]. A longer string is refused before it is
/// decoded.
pub const MAX_SINGLE_QR_DATA_CHARS: usize = b64u_len(SINGLE_QR_MAX_BYTES);

/// The normative per-QR text budget in characters. A version-40 QR at EC level M
/// holds far more (~2331 bytes byte-mode), but print-and-scan reliability wants a
/// mid-size code, so every emitted string is kept at or under this.
pub const MAX_QR_TEXT_CHARS: usize = 1000;

/// GSM 03.38 single (non-concatenated) SMS capacity in GSM-7 septets (3GPP TS
/// 23.038). Informational: the SMS carrier always sizes to the *concatenated*
/// per-part figure below, which is the conservative case.
pub const GSM7_SINGLE_SMS_CHARS: usize = 160;

/// GSM 03.38 concatenated-SMS per-part capacity in GSM-7 septets: an 8-bit
/// concatenation UDH costs 7 of the 160 septets, leaving 153 (3GPP TS 23.040
/// §9.2.3.24). The SMS chunk budget ([`sms_chunk_budget_bytes`]) sizes a chunk to
/// `max_parts × 153` characters so one chunk rides in one (concatenated) SMS.
pub const GSM7_CONCAT_PART_CHARS: usize = 153;

/// The largest a multi-part chunk header can be, in characters, so the SMS budget
/// can subtract it: `rrnp:`(5) + kind(1) + `/`(1) + id8(8) + `/`(1) + index(≤2) +
/// `/`(1) + count(≤2) + `/`(1). `index`/`count` are ≤ [`MAX_CHUNKS`] (64), so ≤ 2
/// digits each — the header never exceeds this, and the data field takes the rest.
pub const MAX_CHUNK_HEADER_CHARS: usize =
    MULTIPART_PREFIX.len() + 1 + 1 + PAYLOAD_ID8_LEN + 1 + 2 + 1 + 2 + 1;

/// The QR chunk-payload budget passed to [`encode_chunks_with_budget`] by the
/// paper/QR path — the same [`CHUNK_PAYLOAD_BYTES`] the plain [`encode_chunks`]
/// uses, named for symmetry with the SMS preset. Emitted QR strings are unchanged.
pub const QR_CHUNK_BUDGET_BYTES: usize = CHUNK_PAYLOAD_BYTES;

/// The raw payload bytes one SMS-carried chunk holds, given the station's
/// `[sms] max_parts_per_message`: a chunk rides in one message of up to
/// `max_parts` concatenated GSM-7 parts, so its whole string must fit
/// `max_parts × 153` characters. Subtracting the worst-case header
/// ([`MAX_CHUNK_HEADER_CHARS`]) leaves the base64url `data` budget, and base64url
/// expands 3 bytes to 4 characters, so the raw budget is `floor(data_chars ×
/// 3/4)`. The result is clamped to [`CHUNK_PAYLOAD_BYTES`] (the reassembler's
/// per-chunk memory bound, [`MAX_CHUNK_DATA_CHARS`]) so an over-large `max_parts`
/// cannot produce a chunk the receiver would refuse.
///
/// At the default `max_parts = 4`: `153×4 = 612` chars − 22 header = 590 data
/// chars → `floor(590 × 3/4) = 442` bytes (pinned by a test).
pub fn sms_chunk_budget_bytes(max_parts_per_message: usize) -> usize {
    let parts = max_parts_per_message.max(1);
    let text_chars = GSM7_CONCAT_PART_CHARS.saturating_mul(parts);
    let data_chars = text_chars.saturating_sub(MAX_CHUNK_HEADER_CHARS);
    // base64url of N bytes is ceil(N·4/3) chars, so the largest N whose encoding
    // fits `data_chars` is floor(data_chars·3/4).
    let bytes = data_chars.saturating_mul(3) / 4;
    bytes.clamp(1, CHUNK_PAYLOAD_BYTES)
}

/// Length of a [`payload_id8`] — the first 8 base64url characters of the payload's
/// 32-byte Blake3 hash. A human-checkable grouping key ("all sheets say A6k9QzTw"),
/// not an integrity proof (see the module docs).
pub const PAYLOAD_ID8_LEN: usize = 8;

/// [`SpendVoucher`] container version, carried in its `v` field.
pub const SPEND_VOUCHER_VERSION: u64 = 1;

/// Maximum presented-history entries in a [`SpendVoucher`] — a decode DoS bound.
pub const MAX_VOUCHER_HISTORY: usize = 64;

/// An error encoding or decoding a paper payload.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PaperError {
    /// A payload would need more than [`MAX_CHUNKS`] chunks at
    /// [`CHUNK_PAYLOAD_BYTES`] per chunk.
    #[error("payload needs {needed} chunks, over the {max} cap")]
    TooManyChunks {
        /// Chunks the payload would require.
        needed: usize,
        /// The cap ([`MAX_CHUNKS`]).
        max: usize,
    },
    /// The string did not begin with the expected scheme prefix for this codec.
    #[error("not the expected paper payload form")]
    NotPaperPayload,
    /// A structural fault in a chunk string (field count, kind letter, or a
    /// non-decimal index/count).
    #[error("malformed paper chunk: {0}")]
    Malformed(&'static str),
    /// A base64url field (chunk `data` or a single-QR body) contained a character
    /// outside the base64url alphabet — e.g. a `+` or `=` (standard-base64
    /// artifacts). (A `/` inside a chunk instead miscounts the fields and surfaces
    /// as [`Malformed`](Self::Malformed); in a single-QR body it is `BadAlphabet`.)
    #[error("payload is not valid base64url (no padding)")]
    BadAlphabet,
    /// A chunk's `data` field was longer than [`MAX_CHUNK_DATA_CHARS`] — over the
    /// per-chunk budget, refused *before* decoding so it cannot force a large
    /// allocation (the memory bound the threat model relies on).
    #[error("chunk data is {found} chars, over the {max}-char per-chunk budget")]
    ChunkTooLarge {
        /// The `data` field's character length.
        found: usize,
        /// The cap ([`MAX_CHUNK_DATA_CHARS`]).
        max: usize,
    },
    /// A chunk's `index`/`count` are inconsistent: `count` is 0 or over
    /// [`MAX_CHUNKS`], or `index` is not in `1..=count`.
    #[error("chunk index {index} out of range for count {count}")]
    IndexOutOfRange {
        /// The 1-based index seen.
        index: usize,
        /// The declared chunk count.
        count: usize,
    },
    /// A chunk's `kind`, `payload_id8`, or `count` disagreed with the sheets
    /// already accepted for this payload — sheets from two different payloads
    /// mixed together.
    #[error("chunk does not match the payload being reassembled")]
    Mixed,
    /// A second, *different* chunk arrived for an already-filled index (the first
    /// is kept and this refused — a mis-print/mis-scan tripwire).
    #[error("conflicting content for an already-seen chunk index")]
    ChunkConflict,
    /// All chunks arrived but the reassembled bytes did not hash to the claimed
    /// [`payload_id8`] — the sheets were mis-collated. The partial is discarded so
    /// a clean re-scan can rebuild it.
    #[error("reassembled payload does not match its id")]
    HashMismatch,
    /// A single-QR form carried more than [`SINGLE_QR_MAX_BYTES`] — it could never
    /// have fit one QR, so it is refused rather than trusted.
    #[error("single-QR payload is {found} bytes, over the {max}-byte budget")]
    Oversized {
        /// Decoded byte length seen.
        found: usize,
        /// The cap ([`SINGLE_QR_MAX_BYTES`]).
        max: usize,
    },
    /// A [`SpendVoucher`] container was not well-formed canonical CBOR of the
    /// expected shape/version.
    #[error("malformed spend voucher: {0}")]
    Cbor(String),
}

/// Which multi-part payload family a chunk carries, one letter on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaperKind {
    /// A [`crate::bundle::Bundle`] — kind letter `b`.
    Bundle,
    /// A receipt envelope ([`crate::receipt::encode_signed`]) — kind letter `r`.
    Receipt,
    /// A [`SpendVoucher`] too large for a single QR — kind letter `s`.
    SpendVoucher,
}

impl PaperKind {
    /// The one-letter wire tag.
    pub fn letter(&self) -> char {
        match self {
            PaperKind::Bundle => 'b',
            PaperKind::Receipt => 'r',
            PaperKind::SpendVoucher => 's',
        }
    }

    /// Parses a one-letter wire tag, or `None` for any other string.
    pub fn from_letter(s: &str) -> Option<Self> {
        match s {
            "b" => Some(PaperKind::Bundle),
            "r" => Some(PaperKind::Receipt),
            "s" => Some(PaperKind::SpendVoucher),
            _ => None,
        }
    }
}

/// The payload family a scanned string belongs to, for one-entry-point routing.
/// [`classify`] recognizes the form by prefix; it does **not** validate or parse
/// the body (an unparseable `rrn1…` still classifies as [`Address`](Self::Address)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaperPayloadKind {
    /// A bare bech32m address (`rrn1…`, §1).
    Address,
    /// The `rrn:` address URI envelope (`rrn:address?…`, §1).
    AddressUri,
    /// A recovery-shard QR (`rrnrecovery:`, §2).
    RecoveryShard,
    /// A multi-part paper chunk (`rrnp:`, §5).
    Multipart,
    /// A single-QR certificate (`rrncert:`, §6).
    Certificate,
    /// A spend voucher (`rrnspend:`, §7).
    SpendVoucher,
    /// No known prefix matched — rejected, not guessed at.
    Unknown,
}

/// Which registered payload family a scanned string is, by prefix (see
/// [`PaperPayloadKind`]). Checks the specific `rrn…:` schemes before the bare
/// `rrn:`/`rrn1` forms so an unambiguous longest-prefix match wins.
pub fn classify(s: &str) -> PaperPayloadKind {
    if s.starts_with(MULTIPART_PREFIX) {
        PaperPayloadKind::Multipart
    } else if s.starts_with(CERT_PREFIX) {
        PaperPayloadKind::Certificate
    } else if s.starts_with(SPEND_PREFIX) {
        PaperPayloadKind::SpendVoucher
    } else if s.starts_with(RECOVERY_PREFIX) {
        PaperPayloadKind::RecoveryShard
    } else if s.starts_with(URI_PREFIX) {
        PaperPayloadKind::AddressUri
    } else if s.starts_with(ADDRESS_PREFIX) {
        PaperPayloadKind::Address
    } else {
        PaperPayloadKind::Unknown
    }
}

/// Base64url (no padding) of `bytes`.
fn b64u_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64url (no padding) decode; any out-of-alphabet character (`+`, `=`, `/`, …)
/// or bad length is [`PaperError::BadAlphabet`].
fn b64u_decode(s: &str) -> Result<Vec<u8>, PaperError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| PaperError::BadAlphabet)
}

/// Strips `prefix`, then decodes a single-QR base64url body to bytes bounded by
/// [`SINGLE_QR_MAX_BYTES`]. The char-length pre-check refuses an over-budget body
/// *before* decoding, so a huge string cannot force a large allocation; the
/// post-decode byte check pins the exact budget. Shared by [`decode_certificate`]
/// and [`decode_spend_voucher`].
fn decode_single_qr(s: &str, prefix: &str) -> Result<Vec<u8>, PaperError> {
    let data = s.strip_prefix(prefix).ok_or(PaperError::NotPaperPayload)?;
    if data.len() > MAX_SINGLE_QR_DATA_CHARS {
        return Err(PaperError::Oversized {
            found: data.len(),
            max: SINGLE_QR_MAX_BYTES,
        });
    }
    let bytes = b64u_decode(data)?;
    if bytes.len() > SINGLE_QR_MAX_BYTES {
        return Err(PaperError::Oversized {
            found: bytes.len(),
            max: SINGLE_QR_MAX_BYTES,
        });
    }
    Ok(bytes)
}

/// The human-checkable grouping key for a payload: the first [`PAYLOAD_ID8_LEN`]
/// base64url characters of its 32-byte Blake3 hash. Not an integrity proof — see
/// the module docs.
pub fn payload_id8(payload: &[u8]) -> String {
    let full = b64u_encode(&Hash::of(payload).to_bytes());
    // Blake3 is 32 bytes ⇒ 43 base64url chars, always ≥ PAYLOAD_ID8_LEN; the chars
    // are ASCII so byte-slicing is char-safe.
    full[..PAYLOAD_ID8_LEN].to_string()
}

/// Splits `payload` into ordered multi-part paper chunk strings at the QR budget
/// ([`CHUNK_PAYLOAD_BYTES`]) — the paper/QR path. Byte-identical to what it always
/// emitted; the cross-platform QR fixtures pin it. Thin wrapper over
/// [`encode_chunks_with_budget`].
///
/// Each string is `rrnp:<kind>/<payload_id8>/<index>/<count>/<data>` with a 1-based
/// `index`, a shared `payload_id8`, and base64url `data`. An empty payload yields
/// exactly one empty-`data` chunk. Refuses a payload that would need more than
/// [`MAX_CHUNKS`] chunks ([`PaperError::TooManyChunks`]).
pub fn encode_chunks(kind: PaperKind, payload: &[u8]) -> Result<Vec<String>, PaperError> {
    encode_chunks_with_budget(kind, payload, CHUNK_PAYLOAD_BYTES)
}

/// Splits `payload` into ordered multi-part chunk strings at an explicit per-chunk
/// **payload budget** in raw bytes — the same `rrnp:` grammar as [`encode_chunks`],
/// generalized so a narrower carrier (SMS, [`sms_chunk_budget_bytes`]) can pack
/// smaller chunks while the QR path keeps its [`CHUNK_PAYLOAD_BYTES`] budget and its
/// byte-for-byte output. The reassembler ([`PaperReassembler`]) is budget-agnostic —
/// it reads `count`/`index` off each chunk — so chunks made at *any* budget
/// reassemble on the receiver without it knowing which carrier produced them.
///
/// `chunk_budget_bytes` is clamped to `1..=CHUNK_PAYLOAD_BYTES`: the upper bound is
/// the reassembler's per-chunk memory cap ([`MAX_CHUNK_DATA_CHARS`]), so no budget
/// can emit a chunk the receiver would refuse as [`PaperError::ChunkTooLarge`].
/// Refuses a payload that would need more than [`MAX_CHUNKS`] chunks at the budget.
pub fn encode_chunks_with_budget(
    kind: PaperKind,
    payload: &[u8],
    chunk_budget_bytes: usize,
) -> Result<Vec<String>, PaperError> {
    let budget = chunk_budget_bytes.clamp(1, CHUNK_PAYLOAD_BYTES);
    let count = payload.len().div_ceil(budget).max(1);
    if count > MAX_CHUNKS {
        return Err(PaperError::TooManyChunks {
            needed: count,
            max: MAX_CHUNKS,
        });
    }
    let id8 = payload_id8(payload);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * budget;
        let end = (start + budget).min(payload.len());
        let data = b64u_encode(&payload[start..end]);
        out.push(format!(
            "{}{}/{}/{}/{}/{}",
            MULTIPART_PREFIX,
            kind.letter(),
            id8,
            i + 1,
            count,
            data
        ));
    }
    Ok(out)
}

/// A parsed multi-part chunk: its header fields and decoded body bytes.
struct ParsedChunk {
    kind: PaperKind,
    id8: String,
    /// 1-based.
    index: usize,
    count: usize,
    data: Vec<u8>,
}

/// Parses and structurally validates one `rrnp:` chunk string.
fn parse_chunk(s: &str) -> Result<ParsedChunk, PaperError> {
    let rest = s
        .strip_prefix(MULTIPART_PREFIX)
        .ok_or(PaperError::NotPaperPayload)?;
    // Exactly five fields; `data` is last and base64url (never contains `/`), so a
    // stray separator makes the field count wrong and is refused here.
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 5 {
        return Err(PaperError::Malformed("chunk needs exactly 5 fields"));
    }
    let kind = PaperKind::from_letter(parts[0]).ok_or(PaperError::Malformed("unknown kind"))?;
    let id8 = parts[1];
    if id8.len() != PAYLOAD_ID8_LEN || !id8.bytes().all(is_base64url_char) {
        return Err(PaperError::Malformed("bad payload_id8"));
    }
    let index = parse_canonical_decimal(parts[2]).ok_or(PaperError::Malformed("bad index"))?;
    let count = parse_canonical_decimal(parts[3]).ok_or(PaperError::Malformed("bad count"))?;
    if count == 0 || count > MAX_CHUNKS || index < 1 || index > count {
        return Err(PaperError::IndexOutOfRange { index, count });
    }
    // Bound the `data` field before decoding, so a chunk claiming megabytes of
    // base64 cannot force a large allocation (the reassembler's memory bound).
    if parts[4].len() > MAX_CHUNK_DATA_CHARS {
        return Err(PaperError::ChunkTooLarge {
            found: parts[4].len(),
            max: MAX_CHUNK_DATA_CHARS,
        });
    }
    let data = b64u_decode(parts[4])?;
    Ok(ParsedChunk {
        kind,
        id8: id8.to_string(),
        index,
        count,
        data,
    })
}

/// Whether `b` is a base64url alphabet byte (`A–Z a–z 0–9 - _`).
fn is_base64url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Parses a **canonical** decimal `usize`: ASCII digits only, no sign, no leading
/// zero (so `"1"` parses but `"+1"`, `"01"`, and `" 1"` are refused). The wire
/// form is canonical so the mobile parser and this one agree byte-for-byte on
/// every input, not just well-formed ones.
fn parse_canonical_decimal(s: &str) -> Option<usize> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

/// Reassembles one multi-part payload from its paper chunks.
///
/// Order-independent and duplicate-idempotent, mirroring [`crate::framing`]'s
/// reassembler but for one payload at a time (a person collating the sheets of one
/// document): the first chunk pins the payload's `kind`, `payload_id8`, and
/// `count`, and any later chunk disagreeing on them is [`PaperError::Mixed`] — two
/// payloads' sheets shuffled together are refused, never silently merged. A repeat
/// of a chunk already held is a no-op; a *different* body for a held index is
/// [`PaperError::ChunkConflict`].
#[derive(Default)]
pub struct PaperReassembler {
    header: Option<Header>,
    /// One slot per 0-based index; `Some` once that chunk's bytes have arrived.
    chunks: Vec<Option<Vec<u8>>>,
    seen: usize,
}

/// The `(kind, id8, count)` a [`PaperReassembler`] pins from its first chunk.
struct Header {
    kind: PaperKind,
    id8: String,
    count: usize,
}

impl PaperReassembler {
    /// A fresh reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one scanned chunk string.
    ///
    /// Returns `Ok(Some((kind, payload)))` when this chunk completes the payload
    /// and its recomputed [`payload_id8`] matches the sheets' claim; `Ok(None)`
    /// while still incomplete or on a duplicate; an `Err` describing why a chunk
    /// was refused. A [`PaperError::HashMismatch`] at completion discards the
    /// partial so a clean re-scan can rebuild it; every other error leaves the
    /// in-progress state untouched.
    pub fn accept(&mut self, s: &str) -> Result<Option<(PaperKind, Vec<u8>)>, PaperError> {
        let chunk = parse_chunk(s)?;
        match &self.header {
            None => {
                self.chunks = vec![None; chunk.count];
                self.header = Some(Header {
                    kind: chunk.kind,
                    id8: chunk.id8.clone(),
                    count: chunk.count,
                });
            }
            Some(h) => {
                if h.kind != chunk.kind || h.id8 != chunk.id8 || h.count != chunk.count {
                    return Err(PaperError::Mixed);
                }
            }
        }
        let slot = &mut self.chunks[chunk.index - 1];
        match slot {
            Some(existing) if *existing == chunk.data => return Ok(None),
            Some(_) => return Err(PaperError::ChunkConflict),
            None => {
                *slot = Some(chunk.data);
                self.seen += 1;
            }
        }
        let header = self.header.as_ref().expect("header just set");
        if self.seen < header.count {
            return Ok(None);
        }
        let mut payload = Vec::new();
        for c in &self.chunks {
            payload.extend_from_slice(c.as_deref().expect("all chunks present"));
        }
        // The concatenation must hash back to the sheets' claimed id8, or the
        // sheets were mis-collated. Discard the partial either way so a clean
        // re-scan can rebuild it.
        let claimed = header.id8.clone();
        let kind = header.kind;
        self.reset();
        if payload_id8(&payload) != claimed {
            return Err(PaperError::HashMismatch);
        }
        Ok(Some((kind, payload)))
    }

    /// The 1-based indexes still missing, or `None` before any chunk is accepted —
    /// the primitive a CLI "scan sheets 3, 5" prompt uses.
    pub fn missing(&self) -> Option<Vec<usize>> {
        self.header.as_ref()?;
        Some(
            self.chunks
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.is_none().then_some(i + 1))
                .collect(),
        )
    }

    fn reset(&mut self) {
        self.header = None;
        self.chunks = Vec::new();
        self.seen = 0;
    }
}

/// Encodes a station-signed certificate envelope as a single-QR string,
/// `rrncert:<base64url>`.
///
/// **Precondition:** `envelope.len() <= SINGLE_QR_MAX_BYTES`. A real certificate
/// envelope is small (~285 bytes; see the §6 size test), so this always holds and
/// the function is infallible. A caller that hands it an over-budget envelope gets
/// a string [`decode_certificate`] will refuse as [`PaperError::Oversized`] — this
/// codec is for certificates, which are never that large; there is no single-QR
/// form for arbitrary large bytes (use [`encode_chunks`]).
pub fn encode_certificate(envelope: &[u8]) -> String {
    format!("{}{}", CERT_PREFIX, b64u_encode(envelope))
}

/// Decodes a single-QR `rrncert:` string back to the certificate envelope bytes.
///
/// Refuses a string without the prefix ([`PaperError::NotPaperPayload`]), bad
/// base64url ([`PaperError::BadAlphabet`]), or a body over [`SINGLE_QR_MAX_BYTES`]
/// ([`PaperError::Oversized`], checked before decoding) — one that could never
/// have fit a QR. It does not interpret the bytes; the caller verifies the station
/// signature.
pub fn decode_certificate(s: &str) -> Result<Vec<u8>, PaperError> {
    decode_single_qr(s, CERT_PREFIX)
}

/// The offline point-of-sale voucher: the inputs a receiver needs to verify a
/// cert-backed spend entirely offline (ADR-0021 §3), carried on paper.
///
/// It is **not** a signed record — it is a container of already-signed envelope
/// byte-blobs (the `{signer, sig, body}` framing the DTN and FFI surfaces use),
/// exactly the arguments of the mobile FFI's `offline_spend_verify`. This module
/// treats each blob as opaque bytes; the receiver's verifier decodes and checks
/// the signatures inside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendVoucher {
    /// The signed cert-backed `TransactionProposal` (`rrn_ledger`) envelope bytes —
    /// the spend being presented.
    pub proposal: Vec<u8>,
    /// The signed `HeadroomCertificate` (`rrn_ledger`) envelope bytes the spend is
    /// backed by.
    pub cert: Vec<u8>,
    /// The payer's presented spend history against the certificate — each a signed
    /// cert-backed proposal envelope. Bounded by [`MAX_VOUCHER_HISTORY`] on decode.
    pub history: Vec<Vec<u8>>,
}

impl SpendVoucher {
    /// Encodes the voucher to canonical dCBOR container bytes: a
    /// `{v, proposal, cert, history}` map (ADR-0002).
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("v", SPEND_VOUCHER_VERSION);
        m.insert("proposal", CBOR::to_byte_string(self.proposal.clone()));
        m.insert("cert", CBOR::to_byte_string(self.cert.clone()));
        let history: Vec<CBOR> = self
            .history
            .iter()
            .map(|h| CBOR::to_byte_string(h.clone()))
            .collect();
        m.insert("history", history);
        CBOR::from(m).to_cbor_data()
    }

    /// Decodes canonical dCBOR container bytes (see [`encode`](Self::encode)) back
    /// into a voucher. Refuses a wrong version, a mis-shaped map, or a history over
    /// [`MAX_VOUCHER_HISTORY`] entries.
    pub fn decode(bytes: &[u8]) -> Result<Self, PaperError> {
        let cbor = checked_from_data(bytes).map_err(|e| PaperError::Cbor(e.to_string()))?;
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(PaperError::Cbor("voucher is not a CBOR map".into())),
        };
        if map
            .extract::<&str, u64>("v")
            .map_err(|e| PaperError::Cbor(e.to_string()))?
            != SPEND_VOUCHER_VERSION
        {
            return Err(PaperError::Cbor("unsupported voucher version".into()));
        }
        let byte_field = |name: &'static str| -> Result<Vec<u8>, PaperError> {
            Ok(map
                .extract::<&str, CBOR>(name)
                .map_err(|e| PaperError::Cbor(e.to_string()))?
                .try_into_byte_string()
                .map_err(|e| PaperError::Cbor(e.to_string()))?
                .as_slice()
                .to_vec())
        };
        let proposal = byte_field("proposal")?;
        let cert = byte_field("cert")?;
        let raw_history = match map
            .extract::<&str, CBOR>("history")
            .map_err(|e| PaperError::Cbor(e.to_string()))?
            .into_case()
        {
            CBORCase::Array(items) => items,
            _ => return Err(PaperError::Cbor("history is not an array".into())),
        };
        if raw_history.len() > MAX_VOUCHER_HISTORY {
            return Err(PaperError::Cbor("history over the cap".into()));
        }
        let mut history = Vec::with_capacity(raw_history.len());
        for item in raw_history {
            history.push(
                item.try_into_byte_string()
                    .map_err(|e| PaperError::Cbor(e.to_string()))?
                    .as_slice()
                    .to_vec(),
            );
        }
        Ok(SpendVoucher {
            proposal,
            cert,
            history,
        })
    }
}

/// Encodes a spend voucher for paper: a single `rrnspend:<base64url>` string when
/// the container fits [`SINGLE_QR_MAX_BYTES`], else multi-part `rrnp:` chunks with
/// kind letter `s` (which can refuse with [`PaperError::TooManyChunks`]).
pub fn encode_spend_voucher(v: &SpendVoucher) -> Result<Vec<String>, PaperError> {
    let cbor = v.encode();
    if cbor.len() <= SINGLE_QR_MAX_BYTES {
        Ok(vec![format!("{}{}", SPEND_PREFIX, b64u_encode(&cbor))])
    } else {
        encode_chunks(PaperKind::SpendVoucher, &cbor)
    }
}

/// Decodes a single-QR `rrnspend:` string into a [`SpendVoucher`].
///
/// For a voucher too large for one QR (carried as `rrnp:` kind-`s` chunks),
/// reassemble the bytes with a [`PaperReassembler`] and call [`SpendVoucher::decode`]
/// instead. Refuses a missing prefix, bad base64url, or a body over
/// [`SINGLE_QR_MAX_BYTES`].
pub fn decode_spend_voucher(s: &str) -> Result<SpendVoucher, PaperError> {
    let bytes = decode_single_qr(s, SPEND_PREFIX)?;
    SpendVoucher::decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The longest possible chunk-string overhead (id8=8, index/count two digits
    /// each): every emitted chunk string stays under this + the base64url data.
    #[test]
    fn multipart_roundtrip_and_string_budget() {
        let payload: Vec<u8> = (0..5_000u32).map(|i| i as u8).collect();
        let chunks = encode_chunks(PaperKind::Bundle, &payload).unwrap();
        // 5000 / 720 = 7 chunks.
        assert_eq!(chunks.len(), 7);
        for c in &chunks {
            assert!(c.starts_with("rrnp:b/"));
            assert!(c.len() <= 1100, "emitted string {} chars", c.len());
            assert!(c.len() <= MAX_QR_TEXT_CHARS);
        }
        let mut r = PaperReassembler::new();
        let mut got = None;
        for c in &chunks {
            if let Some(out) = r.accept(c).unwrap() {
                got = Some(out);
            }
        }
        assert_eq!(got, Some((PaperKind::Bundle, payload)));
        assert_eq!(r.missing(), None); // completed ⇒ reset
    }

    #[test]
    fn empty_payload_is_one_empty_chunk() {
        let chunks = encode_chunks(PaperKind::Receipt, &[]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].ends_with('/')); // empty data field
        let mut r = PaperReassembler::new();
        assert_eq!(
            r.accept(&chunks[0]).unwrap(),
            Some((PaperKind::Receipt, Vec::new()))
        );
    }

    #[test]
    fn reassembly_is_order_independent_and_duplicate_idempotent() {
        let payload: Vec<u8> = (0..2_000u32).map(|i| (i * 7) as u8).collect();
        let chunks = encode_chunks(PaperKind::Bundle, &payload).unwrap();
        assert!(chunks.len() >= 3);
        let mut r = PaperReassembler::new();
        let mut got = None;
        // Deliver reversed, and re-feed each chunk immediately (idempotent).
        for c in chunks.iter().rev() {
            let first = r.accept(c).unwrap();
            let repeat = r.accept(c).unwrap();
            // A duplicate never completes on its own; completion happens once, on
            // whichever chunk fills the last slot.
            if let Some(out) = first {
                got = Some(out);
            } else {
                assert_eq!(repeat, None);
            }
        }
        assert_eq!(got, Some((PaperKind::Bundle, payload)));
    }

    #[test]
    fn count_overflow_is_refused_at_encode() {
        // One byte over MAX_CHUNKS * CHUNK_PAYLOAD_BYTES needs MAX_CHUNKS + 1 chunks.
        let payload = vec![0u8; MAX_CHUNKS * CHUNK_PAYLOAD_BYTES + 1];
        assert_eq!(
            encode_chunks(PaperKind::Bundle, &payload),
            Err(PaperError::TooManyChunks {
                needed: MAX_CHUNKS + 1,
                max: MAX_CHUNKS,
            })
        );
    }

    #[test]
    fn mixed_id_and_mixed_count_are_refused() {
        let a = encode_chunks(PaperKind::Bundle, &[1u8; 1_500]).unwrap();
        let b = encode_chunks(PaperKind::Bundle, &[2u8; 1_500]).unwrap();
        // Two different payloads ⇒ different id8s.
        let mut r = PaperReassembler::new();
        assert_eq!(r.accept(&a[0]).unwrap(), None);
        assert_eq!(r.accept(&b[1]), Err(PaperError::Mixed));

        // A chunk that agrees on id8 but lies about count is also refused.
        let parsed = parse_chunk(&a[0]).unwrap();
        let forged = format!("rrnp:b/{}/1/9/{}", parsed.id8, b64u_encode(&parsed.data));
        let mut r2 = PaperReassembler::new();
        assert_eq!(r2.accept(&a[0]).unwrap(), None);
        assert_eq!(r2.accept(&forged), Err(PaperError::Mixed));
    }

    #[test]
    fn a_conflicting_duplicate_is_refused() {
        let chunks = encode_chunks(PaperKind::Bundle, &[9u8; 1_500]).unwrap();
        let mut r = PaperReassembler::new();
        assert_eq!(r.accept(&chunks[0]).unwrap(), None);
        // Same header (id8/count/index) but different data.
        let parsed = parse_chunk(&chunks[0]).unwrap();
        let conflicting = format!(
            "rrnp:b/{}/{}/{}/{}",
            parsed.id8,
            parsed.index,
            parsed.count,
            b64u_encode(b"different")
        );
        assert_eq!(r.accept(&conflicting), Err(PaperError::ChunkConflict));
    }

    #[test]
    fn a_mis_collated_set_fails_the_hash() {
        // Build a two-chunk payload, then swap the two chunks' data across their
        // headers so both slots fill but the concatenation hashes wrong.
        let payload: Vec<u8> = (0..1_000u32).map(|i| i as u8).collect();
        let chunks = encode_chunks(PaperKind::Bundle, &payload).unwrap();
        assert_eq!(chunks.len(), 2);
        let c0 = parse_chunk(&chunks[0]).unwrap();
        let c1 = parse_chunk(&chunks[1]).unwrap();
        // index 1 carries chunk-2's data; index 2 carries chunk-1's data.
        let swapped_1 = format!("rrnp:b/{}/1/2/{}", c0.id8, b64u_encode(&c1.data));
        let swapped_2 = format!("rrnp:b/{}/2/2/{}", c0.id8, b64u_encode(&c0.data));
        let mut r = PaperReassembler::new();
        assert_eq!(r.accept(&swapped_1).unwrap(), None);
        assert_eq!(r.accept(&swapped_2), Err(PaperError::HashMismatch));
        // Discarded ⇒ a clean re-scan rebuilds.
        assert_eq!(r.missing(), None);
        let mut got = None;
        for c in &chunks {
            if let Some(out) = r.accept(c).unwrap() {
                got = Some(out);
            }
        }
        assert_eq!(got, Some((PaperKind::Bundle, payload)));
    }

    #[test]
    fn bad_alphabet_in_data_is_refused() {
        let good = encode_chunks(PaperKind::Bundle, b"hello world").unwrap();
        let parsed = parse_chunk(&good[0]).unwrap();
        // Inject a standard-base64 `+` and `=` into the data field.
        let bad_plus = format!("rrnp:b/{}/1/1/AAAA+BBB", parsed.id8);
        let bad_pad = format!("rrnp:b/{}/1/1/AAA=", parsed.id8);
        let mut r = PaperReassembler::new();
        assert_eq!(r.accept(&bad_plus), Err(PaperError::BadAlphabet));
        let mut r2 = PaperReassembler::new();
        assert_eq!(r2.accept(&bad_pad), Err(PaperError::BadAlphabet));
    }

    #[test]
    fn malformed_chunks_are_refused() {
        let mut r = PaperReassembler::new();
        // Not the prefix.
        assert_eq!(r.accept("rrncert:AAAA"), Err(PaperError::NotPaperPayload));
        // Wrong field count.
        assert_eq!(
            r.accept("rrnp:b/AAAAAAAA/1/1"),
            Err(PaperError::Malformed("chunk needs exactly 5 fields"))
        );
        // Unknown kind letter.
        assert_eq!(
            r.accept("rrnp:z/AAAAAAAA/1/1/AAAA"),
            Err(PaperError::Malformed("unknown kind"))
        );
        // Non-decimal index.
        assert_eq!(
            r.accept("rrnp:b/AAAAAAAA/x/1/AAAA"),
            Err(PaperError::Malformed("bad index"))
        );
        // index > count.
        assert_eq!(
            r.accept("rrnp:b/AAAAAAAA/2/1/AAAA"),
            Err(PaperError::IndexOutOfRange { index: 2, count: 1 })
        );
        // count over MAX_CHUNKS.
        assert_eq!(
            r.accept("rrnp:b/AAAAAAAA/1/65/AAAA"),
            Err(PaperError::IndexOutOfRange {
                index: 1,
                count: 65
            })
        );
        // Bad payload_id8 length.
        assert_eq!(
            r.accept("rrnp:b/SHORT/1/1/AAAA"),
            Err(PaperError::Malformed("bad payload_id8"))
        );
    }

    #[test]
    fn an_oversized_chunk_data_field_is_refused_before_decoding() {
        // A chunk claiming far more base64 than one chunk may hold is refused on
        // its char length, before any decode — the reassembler memory bound.
        let data = "A".repeat(MAX_CHUNK_DATA_CHARS + 4);
        let s = format!("rrnp:b/AAAAAAAA/1/1/{data}");
        let mut r = PaperReassembler::new();
        assert_eq!(
            r.accept(&s),
            Err(PaperError::ChunkTooLarge {
                found: MAX_CHUNK_DATA_CHARS + 4,
                max: MAX_CHUNK_DATA_CHARS,
            })
        );
        // A real max-size chunk (720 bytes ⇒ 960 chars) is accepted.
        let ok = encode_chunks(PaperKind::Bundle, &vec![7u8; CHUNK_PAYLOAD_BYTES]).unwrap();
        assert_eq!(ok.len(), 1);
        let mut r2 = PaperReassembler::new();
        assert!(r2.accept(&ok[0]).unwrap().is_some());
    }

    #[test]
    fn non_canonical_index_or_count_is_refused() {
        // Leading zero, leading `+`, and whitespace are all non-canonical decimals,
        // so the mobile parser and this one agree byte-for-byte on every input.
        let mut r = PaperReassembler::new();
        assert_eq!(
            r.accept("rrnp:b/AAAAAAAA/01/1/AAAA"),
            Err(PaperError::Malformed("bad index"))
        );
        assert_eq!(
            r.accept("rrnp:b/AAAAAAAA/1/+1/AAAA"),
            Err(PaperError::Malformed("bad count"))
        );
        assert_eq!(
            r.accept("rrnp:b/AAAAAAAA/ 1/1/AAAA"),
            Err(PaperError::Malformed("bad index"))
        );
    }

    #[test]
    fn certificate_single_qr_roundtrip_and_size_budget() {
        // A realistic certificate envelope is ~300 bytes; assert its QR string is
        // well under the 1000-char budget (the §6 size claim).
        let envelope = vec![0x5Au8; 300];
        let s = encode_certificate(&envelope);
        assert!(s.starts_with("rrncert:"));
        assert!(s.len() < 1000, "cert QR string {} chars", s.len());
        assert_eq!(decode_certificate(&s).unwrap(), envelope);
    }

    #[test]
    fn an_oversized_single_qr_certificate_is_refused() {
        let s = encode_certificate(&vec![0u8; SINGLE_QR_MAX_BYTES + 1]);
        assert_eq!(
            decode_certificate(&s),
            Err(PaperError::Oversized {
                found: SINGLE_QR_MAX_BYTES + 1,
                max: SINGLE_QR_MAX_BYTES,
            })
        );
    }

    #[test]
    fn decode_certificate_rejects_wrong_prefix_and_bad_alphabet() {
        assert_eq!(
            decode_certificate("rrnp:AAAA"),
            Err(PaperError::NotPaperPayload)
        );
        assert_eq!(
            decode_certificate("rrncert:has+plus"),
            Err(PaperError::BadAlphabet)
        );
    }

    fn sample_voucher(history: usize) -> SpendVoucher {
        SpendVoucher {
            proposal: vec![0x11; 120],
            cert: vec![0x22; 90],
            history: (0..history).map(|i| vec![i as u8; 100]).collect(),
        }
    }

    #[test]
    fn spend_voucher_container_roundtrips() {
        let v = sample_voucher(2);
        let bytes = v.encode();
        assert_eq!(SpendVoucher::decode(&bytes).unwrap(), v);
    }

    #[test]
    fn spend_voucher_single_qr_when_small() {
        // Small voucher (no history) fits one QR.
        let v = sample_voucher(0);
        let strings = encode_spend_voucher(&v).unwrap();
        assert_eq!(strings.len(), 1);
        assert!(strings[0].starts_with("rrnspend:"));
        assert_eq!(decode_spend_voucher(&strings[0]).unwrap(), v);
    }

    #[test]
    fn spend_voucher_chunks_when_large() {
        // A big history pushes the container past the single-QR budget, so it is
        // carried as rrnp: kind-`s` chunks and reassembles to the same voucher.
        let v = sample_voucher(20);
        let strings = encode_spend_voucher(&v).unwrap();
        assert!(
            strings.len() > 1,
            "expected multi-part, got {}",
            strings.len()
        );
        assert!(strings.iter().all(|s| s.starts_with("rrnp:s/")));
        let mut r = PaperReassembler::new();
        let mut got = None;
        for s in &strings {
            if let Some(out) = r.accept(s).unwrap() {
                got = Some(out);
            }
        }
        let (kind, bytes) = got.unwrap();
        assert_eq!(kind, PaperKind::SpendVoucher);
        assert_eq!(SpendVoucher::decode(&bytes).unwrap(), v);
    }

    #[test]
    fn spend_voucher_decode_rejects_bad_version_and_shape() {
        // Wrong version.
        let mut m = Map::new();
        m.insert("v", 2u64);
        m.insert("proposal", CBOR::to_byte_string(vec![1u8]));
        m.insert("cert", CBOR::to_byte_string(vec![2u8]));
        m.insert("history", Vec::<CBOR>::new());
        let bytes = CBOR::from(m).to_cbor_data();
        assert!(matches!(
            SpendVoucher::decode(&bytes),
            Err(PaperError::Cbor(_))
        ));
        // Garbage.
        assert!(matches!(
            SpendVoucher::decode(&[0xff, 0x00, 0x13]),
            Err(PaperError::Cbor(_))
        ));
    }

    #[test]
    fn spend_voucher_decode_rejects_deeply_nested_input() {
        // A container nested far deeper than dCBOR's recursive decoder can
        // survive must be refused via `checked_from_data`, not crash the thread.
        let mut deep = vec![0x81u8; 50_000]; // array-of-one, nested 50k deep
        deep.push(0x00);
        assert!(matches!(
            SpendVoucher::decode(&deep),
            Err(PaperError::Cbor(_))
        ));
    }

    #[test]
    fn spend_voucher_decode_rejects_oversized_history_and_bad_items() {
        // History over the cap.
        let over: Vec<CBOR> = (0..(MAX_VOUCHER_HISTORY + 1))
            .map(|_| CBOR::to_byte_string(vec![0u8; 4]))
            .collect();
        let mut m = Map::new();
        m.insert("v", SPEND_VOUCHER_VERSION);
        m.insert("proposal", CBOR::to_byte_string(vec![1u8]));
        m.insert("cert", CBOR::to_byte_string(vec![2u8]));
        m.insert("history", over);
        assert!(matches!(
            SpendVoucher::decode(&CBOR::from(m).to_cbor_data()),
            Err(PaperError::Cbor(_))
        ));

        // A history entry that is not a byte string.
        let mut m = Map::new();
        m.insert("v", SPEND_VOUCHER_VERSION);
        m.insert("proposal", CBOR::to_byte_string(vec![1u8]));
        m.insert("cert", CBOR::to_byte_string(vec![2u8]));
        m.insert("history", vec![CBOR::from(7u64)]);
        assert!(matches!(
            SpendVoucher::decode(&CBOR::from(m).to_cbor_data()),
            Err(PaperError::Cbor(_))
        ));

        // A missing required field (`cert`).
        let mut m = Map::new();
        m.insert("v", SPEND_VOUCHER_VERSION);
        m.insert("proposal", CBOR::to_byte_string(vec![1u8]));
        m.insert("history", Vec::<CBOR>::new());
        assert!(matches!(
            SpendVoucher::decode(&CBOR::from(m).to_cbor_data()),
            Err(PaperError::Cbor(_))
        ));
    }

    #[test]
    fn an_oversized_single_qr_body_is_refused_before_decoding() {
        // A huge `rrncert:`/`rrnspend:` string is refused on its char length,
        // before the base64 is decoded into a large allocation.
        let giant = "A".repeat(MAX_SINGLE_QR_DATA_CHARS + 4);
        assert_eq!(
            decode_certificate(&format!("rrncert:{giant}")),
            Err(PaperError::Oversized {
                found: MAX_SINGLE_QR_DATA_CHARS + 4,
                max: SINGLE_QR_MAX_BYTES,
            })
        );
        assert!(matches!(
            decode_spend_voucher(&format!("rrnspend:{giant}")),
            Err(PaperError::Oversized { .. })
        ));
    }

    #[test]
    fn single_qr_strings_stay_within_the_1100_char_bound() {
        // The cert and (small) voucher single-QR forms are within the acceptance
        // bound, like the chunk strings.
        let cert = encode_certificate(&vec![0u8; SINGLE_QR_MAX_BYTES]);
        assert!(cert.len() <= 1100, "cert {} chars", cert.len());
        let strings = encode_spend_voucher(&sample_voucher(0)).unwrap();
        assert_eq!(strings.len(), 1);
        assert!(
            strings[0].len() <= 1100,
            "voucher {} chars",
            strings[0].len()
        );
    }

    #[test]
    fn classify_routes_every_known_prefix_and_rejects_garbage() {
        assert_eq!(
            classify("rrnp:b/AAAAAAAA/1/1/AAAA"),
            PaperPayloadKind::Multipart
        );
        assert_eq!(classify("rrncert:AAAA"), PaperPayloadKind::Certificate);
        assert_eq!(classify("rrnspend:AAAA"), PaperPayloadKind::SpendVoucher);
        assert_eq!(
            classify("rrnrecovery:AAAA"),
            PaperPayloadKind::RecoveryShard
        );
        assert_eq!(
            classify("rrn:address?addr=rrn1x"),
            PaperPayloadKind::AddressUri
        );
        assert_eq!(
            classify("rrn18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5scr4w0n"),
            PaperPayloadKind::Address
        );
        // Garbage and near-misses route to Unknown, never guessed.
        assert_eq!(classify("http://example.com"), PaperPayloadKind::Unknown);
        assert_eq!(classify("rrn"), PaperPayloadKind::Unknown);
        assert_eq!(classify(""), PaperPayloadKind::Unknown);
        assert_eq!(classify("rrnq:whatever"), PaperPayloadKind::Unknown);
    }

    #[test]
    fn payload_id8_is_eight_base64url_chars() {
        let id = payload_id8(b"some payload bytes");
        assert_eq!(id.len(), PAYLOAD_ID8_LEN);
        assert!(id.bytes().all(is_base64url_char));
        // Deterministic: same bytes ⇒ same id.
        assert_eq!(id, payload_id8(b"some payload bytes"));
    }

    #[test]
    fn encode_chunks_is_byte_identical_to_the_qr_budget_wrapper() {
        // The QR path must keep its exact output: `encode_chunks` == the general
        // encoder at `CHUNK_PAYLOAD_BYTES` (== QR_CHUNK_BUDGET_BYTES). The
        // cross-platform QR fixtures pin these bytes.
        let payload: Vec<u8> = (0..4_000u32).map(|i| (i * 5) as u8).collect();
        assert_eq!(QR_CHUNK_BUDGET_BYTES, CHUNK_PAYLOAD_BYTES);
        assert_eq!(
            encode_chunks(PaperKind::Bundle, &payload).unwrap(),
            encode_chunks_with_budget(PaperKind::Bundle, &payload, CHUNK_PAYLOAD_BYTES).unwrap()
        );
    }

    #[test]
    fn sms_chunk_budget_is_pinned_and_fits_one_message() {
        // The default `[sms] max_parts_per_message = 4`: 153×4 = 612 chars, minus
        // the 22-char worst-case header, is 590 base64url data chars, so the raw
        // budget is floor(590 × 3/4) = 442 bytes. Pinned so the SMS spec's math and
        // the code cannot drift apart.
        assert_eq!(MAX_CHUNK_HEADER_CHARS, 22);
        assert_eq!(sms_chunk_budget_bytes(4), 442);
        // And every emitted SMS chunk string fits one 4-part concatenated message.
        let limit = GSM7_CONCAT_PART_CHARS * 4;
        let budget = sms_chunk_budget_bytes(4);
        // A payload spanning several chunks, incl. a full-size chunk (2-digit count).
        let payload: Vec<u8> = (0..(budget * 12 + 7) as u32)
            .map(|i| (i * 3) as u8)
            .collect();
        let chunks = encode_chunks_with_budget(PaperKind::Bundle, &payload, budget).unwrap();
        assert!(chunks.len() >= 12);
        for c in &chunks {
            assert!(
                c.chars().count() <= limit,
                "SMS chunk {} chars over the {}-char 4-part budget",
                c.chars().count(),
                limit
            );
        }
        // A tiny `max_parts` still yields a usable (clamped ≥ 1) budget.
        assert!(sms_chunk_budget_bytes(1) >= 1);
        // A large `max_parts` is clamped to the reassembler's per-chunk cap.
        assert_eq!(sms_chunk_budget_bytes(100), CHUNK_PAYLOAD_BYTES);
    }

    #[test]
    fn sms_budget_chunks_reassemble_via_the_shared_reassembler() {
        // Chunks packed at the SMS budget reassemble with the same budget-agnostic
        // PaperReassembler the QR path uses — byte-identical payload out.
        let payload: Vec<u8> = (0..3_333u32).map(|i| (i ^ 0xA5) as u8).collect();
        let chunks =
            encode_chunks_with_budget(PaperKind::Receipt, &payload, sms_chunk_budget_bytes(4))
                .unwrap();
        assert!(chunks.len() > 1, "expected a multi-chunk payload");
        let mut r = PaperReassembler::new();
        let mut got = None;
        for c in &chunks {
            if let Some(out) = r.accept(c).unwrap() {
                got = Some(out);
            }
        }
        assert_eq!(got, Some((PaperKind::Receipt, payload)));
    }

    /// The GSM 03.38 basic-alphabet ASCII characters (3GPP TS 23.038): every one is
    /// a single GSM-7 septet, needing no escape. Deliberately excludes the
    /// extension-table ASCII characters (`` ` ^ [ \ ] { | } ~ ``), which cost two
    /// septets — the audit proves the chunk grammar never emits one of those.
    const GSM7_BASIC_ASCII: &str =
        " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

    #[test]
    fn gsm7_alphabet_audit_every_emittable_char_is_a_basic_septet() {
        // The full set of characters the `rrnp:` chunk grammar can put on the wire:
        // the prefix, kind letters, the `/` separator, decimal digits, and the
        // base64url alphabet (id8 and data). The ticket's finding: `_` (and `-`) ARE
        // in the GSM-7 basic set, so no SMS-specific alphabet variant is needed.
        let mut emittable: std::collections::BTreeSet<char> = std::collections::BTreeSet::new();
        for c in "rrnp:".chars().chain("/".chars()) {
            emittable.insert(c);
        }
        for k in [
            PaperKind::Bundle,
            PaperKind::Receipt,
            PaperKind::SpendVoucher,
        ] {
            emittable.insert(k.letter());
        }
        for c in ('0'..='9')
            .chain('A'..='Z')
            .chain('a'..='z')
            .chain(['-', '_'])
        {
            emittable.insert(c);
        }
        for c in &emittable {
            assert!(
                GSM7_BASIC_ASCII.contains(*c),
                "grammar emits {c:?}, which is NOT a GSM-7 basic septet"
            );
        }
        // Belt-and-braces: encode a real chunk over a payload covering every byte
        // value and assert every character it emits is a basic septet too.
        let payload: Vec<u8> = (0u32..=255).map(|b| b as u8).collect();
        for chunk in
            encode_chunks_with_budget(PaperKind::Bundle, &payload, sms_chunk_budget_bytes(4))
                .unwrap()
        {
            for c in chunk.chars() {
                assert!(
                    GSM7_BASIC_ASCII.contains(c),
                    "emitted {c:?} is not GSM-7 basic"
                );
            }
        }
    }
}
