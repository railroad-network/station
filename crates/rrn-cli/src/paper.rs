//! `rrn paper` — the operator/courier paper-fallback tools (T2.5.2).
//!
//! Turns station-held payloads into printable QR sheets, and turns scanned QR
//! *text* back into ingested bundles: the physical-credential leg of the
//! offline-first design (ADR-0020 §3 DTN receipts, ADR-0021 §4 offline spends,
//! design overview "Class 4: paper fallback").
//!
//! # This surface verifies; it never signs and never opens a database
//!
//! Every other `rrn` command is a thin pass-through to a daemon RPC. The paper
//! tools do a little more — they *decode and verify* payloads locally, because
//! scanned QR text is untrusted courier input and a courier must be able to
//! inspect a sheet with no station reachable (`rrn paper show`). That is the only
//! reason this module links `rrn-protocol`/`rrn-ledger`/`rrn-crypto`. It holds no
//! key and touches no SQLite: it cannot author records. Offline *signing* — a
//! member spending from a partitioned phone — lives in `rrn-mobile-ffi`
//! (T2.4.2), not here; a member is a phone, and the CLI is the operator's
//! station console. (`rrn paper export-outbox` and a CLI-side wallet are
//! deliberately **not** in this ticket — there is no non-mobile member wallet in
//! the system today; that is deferred to T2.5.3 behind a new ADR.)
//!
//! # Scanning is out of band
//!
//! The CLI does not decode camera images. `ingest`/`show` consume QR *text* —
//! one payload string per line — as produced by any commodity scanner app or
//! webcam tool. The rendering side is hand-rolled over the raw QR module matrix
//! (monochrome PNG with stored/uncompressed DEFLATE, and a deterministic vector
//! PDF) so no imaging or compression dependency enters the audit surface.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use dcbor::prelude::*;

use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_crypto::serialize::{checked_from_data, from_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::escrow::{self, HeadroomCertificate};
use rrn_ledger::transaction::TransactionProposal;
use rrn_protocol::bundle::Bundle;
use rrn_protocol::outbox;
use rrn_protocol::paper::{
    self, classify, decode_certificate, decode_spend_voucher, encode_certificate, encode_chunks,
    PaperKind, PaperPayloadKind, PaperReassembler, SpendVoucher,
};
use rrn_protocol::receipt::{self, Disposition};
use rrn_station::core::{hex, unhex};
use rrn_station::rpc::{CertExportResult, CertRequestResult, ReceiptsFetchResult, WhoamiResult};
use rrn_station::rpc_client::UnixClient;

use crate::{emit, parse, Format};

/// Pixels per QR module in generated PNGs, and the quiet-zone width in modules.
/// Fixed and generous — print reliability over file size (the T2.5.1 intent).
const PNG_SCALE: usize = 6;
const QUIET: usize = 4;

/// The `rrn paper …` subcommands (T2.5.2).
#[derive(clap::Subcommand)]
pub enum PaperCmd {
    /// Classify and pretty-print any paper payload(s) without ingesting them —
    /// the courier's inspection path. Verifies every signature it can and reports
    /// missing chunks for incomplete multi-part groups. Needs no station.
    Show {
        /// Files of QR-text lines (one payload string per line). Repeatable.
        #[arg(long = "in", required = true)]
        input: Vec<PathBuf>,
    },
    /// Reassemble scanned QR text, submit carried bundles to the station, and
    /// print each record's outcome. Re-ingesting the same input is idempotent.
    Ingest {
        /// Files of QR-text lines (one payload string per line). Repeatable.
        #[arg(long = "in", required = true)]
        input: Vec<PathBuf>,
        /// Write the station's delivery receipts here (as `receipts.txt` + QR
        /// sheet) for the carry-back leg.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fetch pending delivery receipts and render them for a courier to carry
    /// back to their authors (the carry-back leg). Fetching never confirms
    /// delivery — only the author's own device does.
    ExportReceipts {
        /// Where to write `receipts.txt` and the QR sheet.
        #[arg(long)]
        out: PathBuf,
        /// Restrict to receipts for these `rrn1…` authors. Repeatable; omit for
        /// the whole pending queue.
        #[arg(long = "author")]
        authors: Vec<String>,
        /// Only receipts for records admitted at/after this admission-clock time.
        #[arg(long)]
        since: Option<i64>,
    },
    /// Print a headroom-certificate wallet card: an existing certificate (by id)
    /// or one requested now, as an `rrncert:` QR with member, cap, and expiry.
    Cert {
        /// Where to write the card (PDF + PNG).
        #[arg(long)]
        out: PathBuf,
        /// Export an existing certificate by its hex content id.
        #[arg(long, conflicts_with = "request")]
        cert_id: Option<String>,
        /// Reserve a new certificate for this cap (Commons, e.g. `10`) and export
        /// it.
        #[arg(long, conflicts_with = "cert_id")]
        request: Option<String>,
    },
    /// Print a member credential card: the member's bare address QR
    /// (qr-payloads §1 — no new format) with an optional name.
    Credential {
        /// Where to write the card (PDF + PNG).
        #[arg(long)]
        out: PathBuf,
        /// The member's `rrn1…` address.
        #[arg(long)]
        address: String,
        /// A human name to caption the card with.
        #[arg(long)]
        name: Option<String>,
    },
    /// Render already-encoded QR-text lines to a printable sheet: one
    /// `chunk_NN_of_MM.png` per line plus a captioned `sheet.pdf`. The shared
    /// print primitive (what `export-receipts` uses internally).
    Render {
        /// A file of QR-text lines to render.
        #[arg(long = "in")]
        input: PathBuf,
        /// Where to write the PNGs and `sheet.pdf`.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Dispatches `rrn paper …`. Only `ingest`, `export-receipts`, and `cert` reach
/// the station; `show`, `credential`, and `render` are purely local.
pub async fn cmd_paper(client: &UnixClient, fmt: Format, cmd: PaperCmd) -> Result<()> {
    match cmd {
        PaperCmd::Show { input } => cmd_show(fmt, &input),
        PaperCmd::Ingest { input, out } => cmd_ingest(client, fmt, &input, out.as_deref()).await,
        PaperCmd::ExportReceipts {
            out,
            authors,
            since,
        } => cmd_export_receipts(client, fmt, &out, &authors, since).await,
        PaperCmd::Cert {
            out,
            cert_id,
            request,
        } => cmd_cert(client, fmt, &out, cert_id, request).await,
        PaperCmd::Credential { out, address, name } => cmd_credential(fmt, &out, &address, name),
        PaperCmd::Render { input, out } => cmd_render(fmt, &input, &out),
    }
}

// ===========================================================================
// Reading and grouping scanned lines
// ===========================================================================

/// One payload recovered from scanned lines, with everything `show`/`ingest`
/// need to act on and print it.
struct Payload {
    /// The 8-char grouping id (multi-part) or `payload_id8` of a single QR.
    id8: String,
    /// What kind of payload this is, resolved to a concrete carried record.
    kind: PayloadKind,
    /// The reassembled/decoded bytes, when the payload is complete.
    bytes: Option<Vec<u8>>,
    /// 1-based chunk indexes still missing (multi-part only).
    missing: Vec<usize>,
    /// Total chunk count seen in the header (1 for a single QR).
    count: usize,
    /// A per-payload parse/decode error, when the line(s) could not be recovered.
    /// A bad line is reported here rather than aborting the whole file, so one
    /// mangled QR never hides the good payloads beside it.
    note: Option<String>,
}

/// The resolved kind of a recovered payload.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadKind {
    Bundle,
    Receipt,
    Certificate,
    SpendVoucher,
    Address,
    /// A recovery shard (`rrnrecovery:`) — outside the paper tools (use
    /// `rrn recover`); reported, never acted on.
    RecoveryShard,
    Unknown,
}

impl PayloadKind {
    fn label(self) -> &'static str {
        match self {
            PayloadKind::Bundle => "bundle",
            PayloadKind::Receipt => "receipt",
            PayloadKind::Certificate => "certificate",
            PayloadKind::SpendVoucher => "spend-voucher",
            PayloadKind::Address => "address",
            PayloadKind::RecoveryShard => "recovery-shard",
            PayloadKind::Unknown => "unknown",
        }
    }
}

/// Reads QR-text lines from `files`, skipping blanks, and groups them into
/// payloads: multi-part `rrnp:` chunks reassembled per id, single QRs standalone.
/// Order-independent; a re-scanned complete group is ignored (idempotent), and a
/// malformed line becomes a reported error payload rather than aborting the run —
/// one mangled QR must never hide the good payloads beside it.
fn read_payloads(files: &[PathBuf]) -> Result<Vec<Payload>> {
    // Multi-part groups keyed by id8, in first-seen order.
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, (PaperReassembler, usize)> =
        std::collections::HashMap::new();
    // id8s already completed — later duplicate chunks for them are dropped, so a
    // re-scanned sheet does not resurrect a phantom "incomplete" group.
    let mut done: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<Payload> = Vec::new();

    for file in files {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            match classify(line) {
                PaperPayloadKind::Multipart => {
                    let Some((_, id8, _, count)) = parse_multipart_header(line) else {
                        out.push(error_payload(
                            paper::payload_id8(line.as_bytes()),
                            "malformed multipart chunk header",
                        ));
                        continue;
                    };
                    if done.contains(&id8) {
                        continue; // already reassembled; ignore the re-scan
                    }
                    let (reass, _) = groups.entry(id8.clone()).or_insert_with(|| {
                        order.push(id8.clone());
                        (PaperReassembler::new(), count)
                    });
                    match reass.accept(line) {
                        Ok(Some((kind, bytes))) => {
                            out.push(Payload {
                                id8: id8.clone(),
                                kind: kind_of(kind),
                                bytes: Some(bytes),
                                missing: Vec::new(),
                                count,
                                note: None,
                            });
                            groups.remove(&id8);
                            order.retain(|o| o != &id8);
                            done.insert(id8);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            out.push(error_payload(id8.clone(), &format!("chunk rejected: {e}")));
                            groups.remove(&id8);
                            order.retain(|o| o != &id8);
                        }
                    }
                }
                other => out.push(single_payload(line, other)),
            }
        }
    }

    // Any groups still open are incomplete — report their missing chunks. Their
    // wire kind is unknown until completion, so report the group generically.
    for id8 in order {
        if let Some((re, count)) = groups.remove(&id8) {
            out.push(Payload {
                id8,
                kind: PayloadKind::Unknown,
                bytes: None,
                missing: re.missing().unwrap_or_default(),
                count,
                note: None,
            });
        }
    }
    Ok(out)
}

/// A payload that could not be recovered from its line(s), carrying the reason.
fn error_payload(id8: String, note: &str) -> Payload {
    Payload {
        id8,
        kind: PayloadKind::Unknown,
        bytes: None,
        missing: Vec::new(),
        count: 1,
        note: Some(note.to_string()),
    }
}

/// Maps a wire [`PaperKind`] to the resolved [`PayloadKind`].
fn kind_of(k: PaperKind) -> PayloadKind {
    match k {
        PaperKind::Bundle => PayloadKind::Bundle,
        PaperKind::Receipt => PayloadKind::Receipt,
        PaperKind::SpendVoucher => PayloadKind::SpendVoucher,
    }
}

/// Builds a [`Payload`] from a single (non-multipart) QR string. A decode failure
/// becomes an error payload — never an abort — so a mangled single QR is reported
/// alongside the good payloads in the same file.
fn single_payload(line: &str, kind: PaperPayloadKind) -> Payload {
    let id8 = paper::payload_id8(line.as_bytes());
    let (kind, bytes) = match kind {
        PaperPayloadKind::Certificate => match decode_certificate(line) {
            Ok(bytes) => (PayloadKind::Certificate, Some(bytes)),
            Err(e) => return error_payload(id8, &format!("bad certificate QR: {e}")),
        },
        PaperPayloadKind::SpendVoucher => match decode_spend_voucher(line) {
            Ok(v) => (PayloadKind::SpendVoucher, Some(v.encode())),
            Err(e) => return error_payload(id8, &format!("bad spend voucher QR: {e}")),
        },
        PaperPayloadKind::Address | PaperPayloadKind::AddressUri => {
            (PayloadKind::Address, Some(line.as_bytes().to_vec()))
        }
        PaperPayloadKind::RecoveryShard => (PayloadKind::RecoveryShard, None),
        PaperPayloadKind::Multipart => unreachable!("multipart handled by the reassembler"),
        PaperPayloadKind::Unknown => (PayloadKind::Unknown, None),
    };
    Payload {
        id8,
        kind,
        bytes,
        missing: Vec::new(),
        count: 1,
        note: None,
    }
}

/// Parses an `rrnp:<kind>/<id8>/<index>/<count>/<data>` header, returning
/// `(kind_letter, id8, index, count)`. `None` if the shape is wrong.
fn parse_multipart_header(line: &str) -> Option<(char, String, usize, usize)> {
    let rest = line.strip_prefix(paper::MULTIPART_PREFIX)?;
    let mut parts = rest.splitn(5, '/');
    let kind = parts.next()?.chars().next()?;
    let id8 = parts.next()?.to_string();
    let index: usize = parts.next()?.parse().ok()?;
    let count: usize = parts.next()?.parse().ok()?;
    parts.next()?; // data — presence only
    Some((kind, id8, index, count))
}

// ===========================================================================
// Inspection (verify + summarize a decoded payload)
// ===========================================================================

/// A rendered inspection of one payload: a machine object and a text block.
struct Inspection {
    json: Value,
    text: String,
    /// A one-line summary used for QR-sheet captions.
    summary: String,
}

/// Inspects a completed payload, verifying every signature it can offline. The
/// signer *identity* is not cross-checked to a known station here (that needs the
/// daemon); a self-consistent signature proves the bytes were not tampered with
/// after signing (ADR-0002).
fn inspect(p: &Payload) -> Inspection {
    match (p.kind, &p.bytes) {
        (PayloadKind::Bundle, Some(b)) => inspect_bundle(b),
        (PayloadKind::Receipt, Some(b)) => inspect_receipt(b),
        (PayloadKind::Certificate, Some(b)) => inspect_certificate(b),
        (PayloadKind::SpendVoucher, Some(b)) => inspect_spend_voucher(b),
        (PayloadKind::Address, Some(b)) => inspect_address(b),
        (PayloadKind::RecoveryShard, _) => Inspection {
            json: json!({ "kind": "recovery-shard" }),
            text: "recovery shard — not a paper-tools payload; use `rrn recover`".to_string(),
            summary: "recovery shard".to_string(),
        },
        _ => {
            let summary = if let Some(note) = &p.note {
                format!("{} ({note})", p.kind.label())
            } else if p.bytes.is_none() && !p.missing.is_empty() {
                format!(
                    "{} (incomplete: missing {} of {})",
                    p.kind.label(),
                    p.missing.len(),
                    p.count
                )
            } else {
                format!("{} (undecodable)", p.kind.label())
            };
            Inspection {
                json: json!({ "kind": p.kind.label(), "missing": p.missing, "error": p.note }),
                text: summary.clone(),
                summary,
            }
        }
    }
}

fn inspect_bundle(bytes: &[u8]) -> Inspection {
    let bundle = match Bundle::decode(bytes) {
        Ok(b) => b,
        Err(e) => return undecodable("bundle", &e.to_string()),
    };
    let mut records = Vec::new();
    let mut lines = vec![format!(
        "bundle: {} record(s), assembled @ {}",
        bundle.entries.len(),
        bundle.assembled_at
    )];
    let mut all_ok = true;
    let mut kinds: Vec<String> = Vec::new();
    for (i, env) in bundle.entries.iter().enumerate() {
        let signed = match env.to_signed() {
            Ok(s) => s,
            Err(e) => {
                all_ok = false;
                lines.push(format!("  [{i}] undecodable entry: {e}"));
                continue;
            }
        };
        let ok = outbox::validate(&signed).is_ok();
        all_ok &= ok;
        let entry = &signed.payload;
        let kind = record_kind(&entry.record_bytes).unwrap_or_else(|| "?".to_string());
        kinds.push(short_kind(&kind));
        lines.push(format!(
            "  [{i}] {} pos {} by {} record {} — {}",
            kind,
            entry.position,
            short_addr(&entry.author),
            short_hash(&hex(&entry.record_hash().to_bytes())),
            if ok {
                "signatures ok"
            } else {
                "SIGNATURE INVALID"
            },
        ));
        records.push(json!({
            "record_kind": kind,
            "position": entry.position,
            "author": entry.author.to_string(),
            "record_hash": hex(&entry.record_hash().to_bytes()),
            "verified": ok,
        }));
    }
    let summary = format!(
        "bundle · {} record(s) [{}]",
        bundle.entries.len(),
        kinds.join(", ")
    );
    Inspection {
        json: json!({
            "kind": "bundle",
            "assembled_at": bundle.assembled_at,
            "records": records,
            "verified": all_ok,
        }),
        text: lines.join("\n"),
        summary,
    }
}

fn inspect_receipt(bytes: &[u8]) -> Inspection {
    let signed = match receipt::decode_signed(bytes) {
        Ok(s) => s,
        Err(e) => return undecodable("receipt", &e.to_string()),
    };
    let sig_ok = signed.verify().is_ok();
    let station_matches = Address::from_public_key(signed.signer) == signed.payload.station;
    let r = &signed.payload;
    let mut lines = vec![format!(
        "receipt from {}: {} outcome(s), received @ {} — {}",
        short_addr(&r.station),
        r.outcomes.len(),
        r.received_at,
        if sig_ok && station_matches {
            "station signature ok"
        } else {
            "STATION SIGNATURE INVALID"
        },
    )];
    let mut outcomes = Vec::new();
    for o in &r.outcomes {
        let (disp, seq) = disposition_text(&o.disposition);
        lines.push(format!(
            "  {} → {}",
            short_hash(&hex(&o.record_hash.to_bytes())),
            disp
        ));
        outcomes.push(json!({
            "record_hash": hex(&o.record_hash.to_bytes()),
            "disposition": disp,
            "seq": seq,
        }));
    }
    Inspection {
        json: json!({
            "kind": "receipt",
            "station": r.station.to_string(),
            "received_at": r.received_at,
            "outcomes": outcomes,
            "verified": sig_ok && station_matches,
        }),
        text: lines.join("\n"),
        summary: format!(
            "receipt · {} outcome(s) from {}",
            r.outcomes.len(),
            short_addr(&r.station)
        ),
    }
}

fn inspect_certificate(bytes: &[u8]) -> Inspection {
    let signed = match escrow::decode_certificate_envelope(bytes) {
        Some(s) => s,
        None => return undecodable("certificate", "not a certificate envelope"),
    };
    let ok = signed.verify().is_ok();
    let c = &signed.payload;
    let text = format!(
        "certificate {}\n  member {}\n  cap {}\n  issued {}  expires {}\n  station signature {}",
        short_hash(&hex(&c.cert_id.0.to_bytes())),
        c.member,
        rrn_station::history::fmt_commons(c.cap_centi),
        c.issued_at,
        c.expires_at,
        if ok { "ok" } else { "INVALID" },
    );
    Inspection {
        json: json!({
            "kind": "certificate",
            "cert_id": hex(&c.cert_id.0.to_bytes()),
            "member": c.member.to_string(),
            "cap_centi": c.cap_centi,
            "issued_at": c.issued_at,
            "expires_at": c.expires_at,
            "verified": ok,
        }),
        text,
        summary: format!(
            "certificate · cap {} for {}",
            rrn_station::history::fmt_commons(c.cap_centi),
            short_addr(&c.member)
        ),
    }
}

fn inspect_spend_voucher(bytes: &[u8]) -> Inspection {
    let v = match SpendVoucher::decode(bytes) {
        Ok(v) => v,
        Err(e) => return undecodable("spend-voucher", &e.to_string()),
    };
    let mut lines = vec!["spend voucher (structural + signature check only —".to_string()];
    lines
        .push("  the full offline-spend verdict is the mobile `offline_spend_verify`)".to_string());

    let mut proposal_ok = None;
    let mut cert_ok = None;
    let mut sender_binds = None;
    let mut summary = "spend voucher".to_string();

    // Proposal envelope → TransactionProposal.
    if let Some((signer, sig, body)) = decode_envelope(&v.proposal) {
        if let Ok(p) = from_canonical_bytes::<TransactionProposal>(&body) {
            let signed = SignedPayload {
                payload: p.clone(),
                signer,
                signature: sig,
            };
            let ok = signed.verify().is_ok();
            proposal_ok = Some(ok);
            lines.push(format!(
                "  proposal: {} → {} amount {} cert {} — {}",
                short_addr(&p.sender),
                short_addr(&p.receiver),
                rrn_station::history::fmt_commons(p.amount_centi),
                p.cert_id
                    .as_ref()
                    .map(|c| short_hash(&hex(&c.0.to_bytes())))
                    .unwrap_or_else(|| "(none)".to_string()),
                if ok {
                    "signature ok"
                } else {
                    "SIGNATURE INVALID"
                },
            ));
            summary = format!(
                "spend voucher · {} → {} amount {}",
                short_addr(&p.sender),
                short_addr(&p.receiver),
                rrn_station::history::fmt_commons(p.amount_centi)
            );
            // Cert envelope → HeadroomCertificate.
            if let Some(cert) = escrow::decode_certificate_envelope(&v.cert) {
                let cok = cert.verify().is_ok();
                cert_ok = Some(cok);
                sender_binds = Some(cert.payload.member == p.sender);
                lines.push(format!(
                    "  certificate: cap {} for {} — {}; sender binds: {}",
                    rrn_station::history::fmt_commons(cert.payload.cap_centi),
                    short_addr(&cert.payload.member),
                    if cok {
                        "signature ok"
                    } else {
                        "SIGNATURE INVALID"
                    },
                    if sender_binds == Some(true) {
                        "yes"
                    } else {
                        "NO"
                    },
                ));
            } else {
                lines.push("  certificate: undecodable".to_string());
            }
        } else {
            lines.push("  proposal: undecodable".to_string());
        }
    } else {
        lines.push("  proposal: undecodable envelope".to_string());
    }
    lines.push(format!("  history: {} prior entr(y/ies)", v.history.len()));

    Inspection {
        json: json!({
            "kind": "spend-voucher",
            "proposal_verified": proposal_ok,
            "certificate_verified": cert_ok,
            "sender_binds_certificate": sender_binds,
            "history_len": v.history.len(),
        }),
        text: lines.join("\n"),
        summary,
    }
}

fn inspect_address(bytes: &[u8]) -> Inspection {
    let s = String::from_utf8_lossy(bytes);
    let addr = s.trim().strip_prefix("rrn:").unwrap_or(s.trim());
    let ok = addr.parse::<Address>().is_ok();
    Inspection {
        json: json!({ "kind": "address", "address": addr, "valid": ok }),
        text: format!(
            "address {} — {}",
            addr,
            if ok { "valid bech32m" } else { "INVALID" }
        ),
        summary: format!("address {}", short_hash(addr)),
    }
}

fn undecodable(kind: &str, why: &str) -> Inspection {
    Inspection {
        json: json!({ "kind": kind, "error": why }),
        text: format!("{kind}: undecodable ({why})"),
        summary: format!("{kind} (undecodable)"),
    }
}

/// Peeks the `kind` discriminator out of a signed record's canonical bytes.
fn record_kind(record_bytes: &[u8]) -> Option<String> {
    let cbor = checked_from_data(record_bytes).ok()?;
    match cbor.into_case() {
        CBORCase::Map(map) => map.extract::<&str, String>("kind").ok(),
        _ => None,
    }
}

/// Decodes the repo's house `{signer, sig, body}` signed-record envelope.
/// Does not verify — the caller reconstructs the typed payload and verifies.
fn decode_envelope(bytes: &[u8]) -> Option<(PublicKey, Signature, Vec<u8>)> {
    let cbor = checked_from_data(bytes).ok()?;
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return None,
    };
    let signer: [u8; 32] = map
        .extract::<&str, CBOR>("signer")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let sig: [u8; 64] = map
        .extract::<&str, CBOR>("sig")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let body = map
        .extract::<&str, CBOR>("body")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .to_vec();
    Some((
        PublicKey::from_bytes(signer).ok()?,
        Signature::from_bytes(sig).ok()?,
        body,
    ))
}

fn disposition_text(d: &Disposition) -> (String, Option<u64>) {
    match d {
        Disposition::Admitted { seq } => (format!("admitted (seq {seq})"), Some(*seq)),
        Disposition::Known { seq } => (format!("known (seq {seq})"), Some(*seq)),
        Disposition::Refused { reason } => (format!("refused ({})", reason.as_slug()), None),
    }
}

/// `rrn.tx.proposal` → `proposal`, `rrn.dtn.receipt` → `receipt`, etc.
fn short_kind(kind: &str) -> String {
    kind.rsplit('.').next().unwrap_or(kind).to_string()
}

fn short_addr(a: &Address) -> String {
    short_hash(&a.to_string())
}

fn short_hash(s: &str) -> String {
    // Count and slice by `char`, never by byte: scanned input can hold multi-byte
    // characters (curly quotes, BOMs, em dashes), and a byte slice through one
    // would panic (finding: untrusted paper input must never abort the CLI).
    let n = s.chars().count();
    if n <= 14 {
        s.to_string()
    } else {
        let head: String = s.chars().take(8).collect();
        let tail: String = s.chars().skip(n - 4).collect();
        format!("{head}…{tail}")
    }
}

// ===========================================================================
// Commands
// ===========================================================================

fn cmd_show(fmt: Format, files: &[PathBuf]) -> Result<()> {
    let payloads = read_payloads(files)?;
    if payloads.is_empty() {
        bail!("no QR payloads found in the given file(s)");
    }
    let mut json = Vec::new();
    let mut text = String::new();
    for p in &payloads {
        let insp = inspect(p);
        if !p.missing.is_empty() {
            text.push_str(&format!(
                "[{}] {} — INCOMPLETE, missing chunk(s) {:?} of {}\n",
                p.id8,
                p.kind.label(),
                p.missing,
                p.count
            ));
            json.push(json!({
                "id8": p.id8,
                "kind": p.kind.label(),
                "complete": false,
                "missing": p.missing,
            }));
            continue;
        }
        text.push_str(&format!("[{}] {}\n", p.id8, insp.text));
        let mut obj = insp.json;
        obj["id8"] = json!(p.id8);
        obj["complete"] = json!(true);
        json.push(obj);
    }
    let raw = json!({ "payloads": json });
    emit(fmt, &raw, || Ok(text.trim_end().to_string()))
}

async fn cmd_ingest(
    client: &UnixClient,
    fmt: Format,
    files: &[PathBuf],
    out: Option<&Path>,
) -> Result<()> {
    let payloads = read_payloads(files)?;
    if payloads.is_empty() {
        bail!("no QR payloads found in the given file(s)");
    }
    // The station address, to confirm returned receipts are actually its.
    let whoami: WhoamiResult = parse(&client.call("whoami", json!({})).await?)?;
    let station_addr: Address = whoami
        .address
        .parse()
        .context("station returned an unparseable address")?;

    let mut results = Vec::new();
    let mut text = String::new();
    let mut carry_back: Vec<String> = Vec::new();

    for p in &payloads {
        if !p.missing.is_empty() {
            text.push_str(&format!(
                "[{}] {} — INCOMPLETE, missing {:?} of {}; not ingested\n",
                p.id8,
                p.kind.label(),
                p.missing,
                p.count
            ));
            results.push(json!({ "id8": p.id8, "ingested": false, "reason": "incomplete" }));
            continue;
        }
        match p.kind {
            PayloadKind::Bundle => {
                let bytes = p.bytes.as_ref().expect("complete bundle has bytes");
                let v = client
                    .call("bundle_submit", json!({ "bundle_hex": hex(bytes) }))
                    .await?;
                let receipt_hex = v
                    .get("receipt_hex")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow!("station returned no receipt"))?;
                let receipt_bytes =
                    unhex(receipt_hex).ok_or_else(|| anyhow!("receipt_hex is not hex"))?;
                let (verified, outcomes_json, outcomes_text) =
                    verify_and_render_receipt(&receipt_bytes, &station_addr)?;
                text.push_str(&format!(
                    "[{}] bundle → {}\n{}\n",
                    p.id8,
                    if verified {
                        "receipt verified"
                    } else {
                        "RECEIPT UNVERIFIED"
                    },
                    outcomes_text,
                ));
                carry_back.extend(encode_chunks(PaperKind::Receipt, &receipt_bytes)?);
                results.push(json!({
                    "id8": p.id8,
                    "ingested": true,
                    "receipt_verified": verified,
                    "outcomes": outcomes_json,
                }));
            }
            PayloadKind::Receipt => {
                let bytes = p.bytes.as_ref().expect("complete receipt has bytes");
                let (verified, outcomes_json, outcomes_text) =
                    verify_and_render_receipt(bytes, &station_addr)?;
                // No ack: the CLI is not the author. Only the author's own device
                // confirms delivery (ADR-0020 §3); a courier just carries.
                text.push_str(&format!(
                    "[{}] receipt (carried, not acked — the author's device confirms): {}\n{}\n",
                    p.id8,
                    if verified { "verified" } else { "UNVERIFIED" },
                    outcomes_text,
                ));
                results.push(json!({
                    "id8": p.id8,
                    "ingested": false,
                    "reason": "receipt-display-only",
                    "verified": verified,
                    "outcomes": outcomes_json,
                }));
            }
            other => {
                text.push_str(&format!(
                    "[{}] {} — not ingestible; use `rrn paper show`\n",
                    p.id8,
                    other.label()
                ));
                results.push(json!({ "id8": p.id8, "ingested": false, "reason": "not-a-bundle" }));
            }
        }
    }

    if let Some(dir) = out {
        if carry_back.is_empty() {
            text.push_str("(no receipts to carry back)\n");
        } else {
            write_lines_and_render(dir, "receipts", &carry_back)?;
            text.push_str(&format!(
                "wrote {} receipt chunk(s) to {}\n",
                carry_back.len(),
                dir.display()
            ));
        }
    }

    let raw = json!({ "results": results });
    emit(fmt, &raw, || Ok(text.trim_end().to_string()))
}

/// Verifies a delivery receipt is signed by `station` and renders its outcomes.
fn verify_and_render_receipt(bytes: &[u8], station: &Address) -> Result<(bool, Value, String)> {
    let signed = receipt::decode_signed(bytes).map_err(|e| anyhow!("undecodable receipt: {e}"))?;
    let verified = signed.verify().is_ok()
        && Address::from_public_key(signed.signer) == *station
        && signed.payload.station == *station;
    let mut lines = Vec::new();
    let mut outcomes = Vec::new();
    for o in &signed.payload.outcomes {
        let (disp, seq) = disposition_text(&o.disposition);
        lines.push(format!(
            "    {} → {}",
            short_hash(&hex(&o.record_hash.to_bytes())),
            disp
        ));
        outcomes.push(json!({
            "record_hash": hex(&o.record_hash.to_bytes()),
            "disposition": disp,
            "seq": seq,
        }));
    }
    Ok((verified, json!(outcomes), lines.join("\n")))
}

async fn cmd_export_receipts(
    client: &UnixClient,
    fmt: Format,
    out: &Path,
    authors: &[String],
    since: Option<i64>,
) -> Result<()> {
    let mut params = json!({ "authors": authors });
    if let Some(ts) = since {
        params["since"] = json!(ts);
    }
    let v = client.call("receipts_fetch", params).await?;
    let res: ReceiptsFetchResult = parse(&v)?;

    let mut lines = Vec::new();
    for hex_str in &res.receipts_hex {
        let bytes = unhex(hex_str).ok_or_else(|| anyhow!("receipt_hex is not hex"))?;
        lines.extend(encode_chunks(PaperKind::Receipt, &bytes)?);
    }
    if lines.is_empty() {
        return emit(
            fmt,
            &json!({ "receipts": 0, "truncated": res.truncated }),
            || Ok("no pending receipts".to_string()),
        );
    }
    write_lines_and_render(out, "receipts", &lines)?;
    let raw = json!({
        "receipts": res.receipts_hex.len(),
        "chunks": lines.len(),
        "truncated": res.truncated,
        "out": out.display().to_string(),
    });
    emit(fmt, &raw, || {
        let mut s = format!(
            "exported {} receipt(s) as {} QR chunk(s) to {}",
            res.receipts_hex.len(),
            lines.len(),
            out.display()
        );
        if res.truncated {
            s.push_str("\n(truncated — more receipts remain; run again)");
        }
        Ok(s)
    })
}

async fn cmd_cert(
    client: &UnixClient,
    fmt: Format,
    out: &Path,
    cert_id: Option<String>,
    request: Option<String>,
) -> Result<()> {
    let cert_id = match (cert_id, request) {
        (Some(id), None) => id,
        (None, Some(cap)) => {
            let cap_centi = crate::parse_amount(&cap)?;
            let v = client
                .call("cert_request", json!({ "cap_centi": cap_centi }))
                .await?;
            let r: CertRequestResult = parse(&v)?;
            r.cert_id
        }
        _ => bail!("give exactly one of --cert-id or --request"),
    };

    let v = client
        .call("cert_export", json!({ "cert_id": cert_id }))
        .await?;
    let res: CertExportResult = parse(&v)?;
    let envelope = unhex(&res.envelope_hex).ok_or_else(|| anyhow!("envelope_hex is not hex"))?;
    let signed = escrow::decode_certificate_envelope(&envelope)
        .ok_or_else(|| anyhow!("station returned an undecodable certificate"))?;
    let c: &HeadroomCertificate = &signed.payload;

    let qr = encode_certificate(&envelope);
    let title = "Railroad Network - Headroom Certificate";
    let lines = vec![
        format!("member  {}", c.member),
        format!("cap     {}", rrn_station::history::fmt_commons(c.cap_centi)),
        format!("expires {}", c.expires_at),
        format!("cert    {}", hex(&c.cert_id.0.to_bytes())),
    ];
    write_card(out, "certificate", title, &qr, &lines)?;

    let raw = json!({
        "cert_id": hex(&c.cert_id.0.to_bytes()),
        "member": c.member.to_string(),
        "cap_centi": c.cap_centi,
        "expires_at": c.expires_at,
        "out": out.display().to_string(),
    });
    emit(fmt, &raw, || {
        Ok(format!(
            "wrote certificate card ({}, cap {}) to {}",
            short_hash(&hex(&c.cert_id.0.to_bytes())),
            rrn_station::history::fmt_commons(c.cap_centi),
            out.display()
        ))
    })
}

fn cmd_credential(fmt: Format, out: &Path, address: &str, name: Option<String>) -> Result<()> {
    let addr: Address = address
        .parse()
        .with_context(|| format!("invalid rrn1… address: {address}"))?;
    let title = "Railroad Network - Member Credential";
    let mut lines = Vec::new();
    if let Some(n) = &name {
        lines.push(format!("name    {n}"));
    }
    lines.push(format!("address {addr}"));
    // The QR is the bare bech32m address (qr-payloads §1) — no new format.
    write_card(out, "credential", title, &addr.to_string(), &lines)?;
    let raw =
        json!({ "address": addr.to_string(), "name": name, "out": out.display().to_string() });
    emit(fmt, &raw, || {
        Ok(format!(
            "wrote credential card for {addr} to {}",
            out.display()
        ))
    })
}

fn cmd_render(fmt: Format, input: &Path, out: &Path) -> Result<()> {
    let text =
        std::fs::read_to_string(input).with_context(|| format!("read {}", input.display()))?;
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        bail!("no QR-text lines in {}", input.display());
    }
    let n = render_lines(out, &lines)?;
    let raw = json!({ "chunks": n, "out": out.display().to_string() });
    emit(fmt, &raw, || {
        Ok(format!(
            "rendered {n} QR(s) to {} (chunk_*.png + sheet.pdf)",
            out.display()
        ))
    })
}

// ===========================================================================
// Output: writing text + rendering QR sheets and cards
// ===========================================================================

/// Removes any previously rendered `chunk_*.png` and `sheet.pdf` from `dir`, so a
/// re-render with fewer chunks leaves no stale pages behind. Best effort.
fn clear_rendered(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "sheet.pdf" || (name.starts_with("chunk_") && name.ends_with(".png")) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Writes `<basename>.txt` (the raw QR strings, one per line — the no-printer /
/// debug path) then renders the sheet next to it.
fn write_lines_and_render(dir: &Path, basename: &str, lines: &[String]) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let txt = dir.join(format!("{basename}.txt"));
    std::fs::write(&txt, format!("{}\n", lines.join("\n")))
        .with_context(|| format!("write {}", txt.display()))?;
    render_lines(dir, lines)?;
    Ok(())
}

/// Renders each line to `chunk_NN_of_MM.png` and all lines to a captioned
/// `sheet.pdf`. Returns the number of QRs rendered.
fn render_lines(dir: &Path, lines: &[String]) -> Result<usize> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    // Clear any stale sheet from a previous, larger export so an old
    // `chunk_03_of_03.png` can't be printed beside a fresh `chunk_01_of_02.png`.
    clear_rendered(dir);
    let count = lines.len();
    // Caption summaries: reassemble/inspect the whole file so multi-part chunks
    // caption with a description of what the sheet carries (best-effort).
    let summaries = caption_summaries(lines);

    let mut items = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let png = qr_png(line)?;
        let name = format!("chunk_{:02}_of_{:02}.png", i + 1, count);
        let path = dir.join(&name);
        std::fs::write(&path, &png).with_context(|| format!("write {}", path.display()))?;
        let (id8, index, total) = caption_coords(line, i + 1, count);
        let summary = summaries
            .get(&id8)
            .cloned()
            .unwrap_or_else(|| "payload".to_string());
        items.push(SheetItem {
            qr_text: line.clone(),
            caption: vec![
                format!("{}  {}/{}", id8, index, total),
                truncate(&summary, 52),
            ],
        });
    }
    let pdf = render_sheet_pdf(&items)?;
    let sheet = dir.join("sheet.pdf");
    std::fs::write(&sheet, &pdf).with_context(|| format!("write {}", sheet.display()))?;
    Ok(count)
}

/// Per-payload one-line summaries keyed by id8, for sheet captions. Best effort:
/// undecodable or incomplete groups just get their kind label.
fn caption_summaries(lines: &[String]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    // Reuse the grouping logic by writing lines through read_payloads via a temp?
    // Avoid I/O: reassemble inline.
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, PaperReassembler> =
        std::collections::HashMap::new();
    for line in lines {
        match classify(line) {
            PaperPayloadKind::Multipart => {
                if let Some((_, id8, _, _)) = parse_multipart_header(line) {
                    let re = groups.entry(id8.clone()).or_insert_with(|| {
                        order.push(id8.clone());
                        PaperReassembler::new()
                    });
                    if let Ok(Some((kind, bytes))) = re.accept(line) {
                        let p = Payload {
                            id8: id8.clone(),
                            kind: kind_of(kind),
                            bytes: Some(bytes),
                            missing: Vec::new(),
                            count: 0,
                            note: None,
                        };
                        map.insert(id8.clone(), inspect(&p).summary);
                    } else {
                        map.entry(id8)
                            .or_insert_with(|| "multi-part payload".to_string());
                    }
                }
            }
            other => {
                let p = single_payload(line, other);
                let id8 = p.id8.clone();
                let s = inspect(&p).summary;
                map.insert(id8, s);
            }
        }
    }
    map
}

/// The (id8, index, count) to caption a line with.
fn caption_coords(
    line: &str,
    fallback_index: usize,
    fallback_count: usize,
) -> (String, usize, usize) {
    if let Some((_, id8, index, count)) = parse_multipart_header(line) {
        (id8, index, count)
    } else {
        (
            paper::payload_id8(line.as_bytes()),
            fallback_index,
            fallback_count,
        )
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// One QR + its caption lines on a sheet.
struct SheetItem {
    qr_text: String,
    caption: Vec<String>,
}

/// Writes a wallet-card PDF (`<basename>.pdf`) and a `<basename>.png` for one QR
/// with a title and a few text lines.
fn write_card(
    dir: &Path,
    basename: &str,
    title: &str,
    qr_text: &str,
    lines: &[String],
) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let png = qr_png(qr_text)?;
    std::fs::write(dir.join(format!("{basename}.png")), &png)?;
    let pdf = render_card_pdf(title, qr_text, lines)?;
    std::fs::write(dir.join(format!("{basename}.pdf")), &pdf)?;
    // The raw QR string too — the no-printer / debug path, and what `rrn paper
    // show` re-reads to verify the card.
    std::fs::write(dir.join(format!("{basename}.txt")), format!("{qr_text}\n"))?;
    Ok(())
}

// ===========================================================================
// QR → PNG (monochrome, hand-rolled, no imaging/compression dependency)
// ===========================================================================

/// Encodes `text` as a QR (EC level M) and renders it to a monochrome 8-bit
/// grayscale PNG with a quiet zone.
fn qr_png(text: &str) -> Result<Vec<u8>> {
    let (w, dark) = qr_matrix(text)?;
    let side = (w + 2 * QUIET) * PNG_SCALE;
    let mut px = vec![255u8; side * side];
    for my in 0..w {
        for mx in 0..w {
            if dark[my * w + mx] {
                let x0 = (mx + QUIET) * PNG_SCALE;
                let y0 = (my + QUIET) * PNG_SCALE;
                for dy in 0..PNG_SCALE {
                    let row = (y0 + dy) * side;
                    for dx in 0..PNG_SCALE {
                        px[row + x0 + dx] = 0;
                    }
                }
            }
        }
    }
    Ok(gray_png(side as u32, side as u32, &px))
}

/// The QR module matrix: `(width, dark)` where `dark[y*width + x]` is true for a
/// dark module.
fn qr_matrix(text: &str) -> Result<(usize, Vec<bool>)> {
    use qrcode::{Color, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|e| anyhow!("QR encode failed ({e}) — payload too large for one code"))?;
    let w = code.width();
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == Color::Dark)
        .collect();
    Ok((w, dark))
}

/// CRC-32 (IEEE 802.3), computed directly (no static table — QR PNGs are small).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Adler-32 checksum for the zlib trailer.
fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in bytes {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// A zlib stream carrying `raw` in stored (uncompressed) DEFLATE blocks — a
/// valid PNG IDAT without pulling in a DEFLATE implementation. QR bitmaps are
/// tiny, so the size cost is irrelevant.
fn zlib_stored(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01]; // zlib header: CMF=0x78, FLG=0x01
    let mut i = 0;
    loop {
        let end = (i + 0xFFFF).min(raw.len());
        let chunk = &raw[i..end];
        let last = end == raw.len();
        out.push(if last { 1 } else { 0 }); // BFINAL, BTYPE=00 (stored)
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
        i = end;
        if last {
            break;
        }
    }
    out.extend_from_slice(&adler32(raw).to_be_bytes());
    out
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// An 8-bit grayscale PNG from row-major pixels (`pixels.len() == w*h`).
fn gray_png(w: u32, h: u32, pixels: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity((w as usize + 1) * h as usize);
    for y in 0..h as usize {
        raw.push(0); // filter type 0 (None) for this scanline
        raw.extend_from_slice(&pixels[y * w as usize..(y + 1) * w as usize]);
    }
    let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(0); // color type 0 = grayscale
    ihdr.extend_from_slice(&[0, 0, 0]); // compression, filter, interlace
    png_chunk(&mut png, b"IHDR", &ihdr);
    png_chunk(&mut png, b"IDAT", &zlib_stored(&raw));
    png_chunk(&mut png, b"IEND", &[]);
    png
}

// ===========================================================================
// QR → PDF (deterministic, monochrome, hand-rolled vector — no PDF dependency)
// ===========================================================================

const PAGE_W: f64 = 612.0; // US Letter, points
const PAGE_H: f64 = 792.0;

/// A captioned grid of QR codes across as many Letter pages as needed.
fn render_sheet_pdf(items: &[SheetItem]) -> Result<Vec<u8>> {
    const COLS: usize = 2;
    const ROWS: usize = 3;
    const PER_PAGE: usize = COLS * ROWS;
    const MARGIN: f64 = 36.0;
    let cell_w = (PAGE_W - 2.0 * MARGIN) / COLS as f64;
    let cell_h = (PAGE_H - 2.0 * MARGIN) / ROWS as f64;
    let qr_size = cell_w.min(cell_h) - 40.0;

    let mut pages = Vec::new();
    for page in items.chunks(PER_PAGE) {
        let mut ops = String::new();
        for (i, item) in page.iter().enumerate() {
            let col = i % COLS;
            let row = i / COLS;
            let cell_x = MARGIN + col as f64 * cell_w;
            // rows fill top-down; PDF origin is bottom-left
            let cell_top = PAGE_H - MARGIN - row as f64 * cell_h;
            let qr_x = cell_x + (cell_w - qr_size) / 2.0;
            let qr_y = cell_top - qr_size - 12.0;
            draw_qr(&mut ops, item.qr_text.as_str(), qr_x, qr_y, qr_size)?;
            let mut ty = qr_y - 12.0;
            for line in &item.caption {
                draw_text(&mut ops, cell_x + 6.0, ty, 8.0, line);
                ty -= 10.0;
            }
        }
        pages.push(ops);
    }
    Ok(assemble_pdf(&pages))
}

/// A single wallet-card page: a QR, a title, and text lines beside it.
fn render_card_pdf(title: &str, qr_text: &str, lines: &[String]) -> Result<Vec<u8>> {
    // A card outline (3.375" × 2.125"), centered near the top of the page.
    let card_w = 3.375 * 72.0;
    let card_h = 2.125 * 72.0;
    let card_x = (PAGE_W - card_w) / 2.0;
    let card_y = PAGE_H - 72.0 - card_h;

    let mut ops = String::new();
    // Card border.
    ops.push_str(&format!(
        "0 0 0 RG 0.75 w {:.2} {:.2} {:.2} {:.2} re S\n",
        card_x, card_y, card_w, card_h
    ));
    let qr_size = card_h - 24.0;
    let qr_x = card_x + 12.0;
    let qr_y = card_y + 12.0;
    draw_qr(&mut ops, qr_text, qr_x, qr_y, qr_size)?;

    let text_x = qr_x + qr_size + 14.0;
    let mut ty = card_y + card_h - 20.0;
    draw_text(&mut ops, text_x, ty, 8.5, title);
    ty -= 15.0;
    // The text column is ~82 pt wide; at 7 pt Helvetica that is ~22 characters,
    // so wrap long values (a 62-char address) across lines rather than truncating
    // — the human-readable copy must stay complete (finding: don't cut the
    // address). The QR still carries the exact bytes regardless.
    for line in lines {
        for (i, seg) in wrap(line, 22).into_iter().enumerate() {
            let x = if i == 0 { text_x } else { text_x + 10.0 };
            draw_text(&mut ops, x, ty, 7.0, &seg);
            ty -= 9.5;
        }
    }
    Ok(assemble_pdf(&[ops]))
}

/// Wraps `s` into segments of at most `max` characters, breaking on char
/// boundaries (never mid-UTF-8). Preserves order; used for card text only.
fn wrap(s: &str, max: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return vec![s.to_string()];
    }
    chars.chunks(max).map(|c| c.iter().collect()).collect()
}

/// Draws a QR into `ops` as filled black rectangles (run-length per row) inside a
/// `size`×`size` box with bottom-left at `(x, y)`, including the quiet zone.
fn draw_qr(ops: &mut String, text: &str, x: f64, y: f64, size: f64) -> Result<()> {
    let (w, dark) = qr_matrix(text)?;
    let total = (w + 2 * QUIET) as f64;
    let m = size / total; // module edge in points
    ops.push_str("0 0 0 rg\n");
    for my in 0..w {
        let mut mx = 0;
        while mx < w {
            if dark[my * w + mx] {
                let start = mx;
                while mx < w && dark[my * w + mx] {
                    mx += 1;
                }
                let run = (mx - start) as f64;
                let rx = x + (QUIET + start) as f64 * m;
                // module row `my` from the top; PDF y grows upward
                let ry = y + size - (QUIET + my + 1) as f64 * m;
                ops.push_str(&format!(
                    "{:.2} {:.2} {:.2} {:.2} re f\n",
                    rx,
                    ry,
                    run * m,
                    m
                ));
            } else {
                mx += 1;
            }
        }
    }
    Ok(())
}

fn draw_text(ops: &mut String, x: f64, y: f64, size: f64, s: &str) {
    ops.push_str("0 0 0 rg\nBT\n");
    ops.push_str(&format!("/F1 {size:.1} Tf\n"));
    ops.push_str(&format!("{x:.2} {y:.2} Td\n"));
    ops.push_str(&format!("({}) Tj\n", pdf_escape(s)));
    ops.push_str("ET\n");
}

/// Escapes a string for a PDF literal string, dropping non-printable/non-ASCII.
fn pdf_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if (0x20..=0x7e).contains(&(c as u32)) => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

/// Assembles content streams into a minimal, valid PDF sharing one Helvetica
/// font. Deterministic: identical input bytes yield identical output.
fn assemble_pdf(pages: &[String]) -> Vec<u8> {
    let n_pages = pages.len().max(1);
    let total_objs = 3 + 2 * n_pages;
    let page_obj = |i: usize| 4 + 2 * i;
    let content_obj = |i: usize| 5 + 2 * i;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = vec![0usize; total_objs + 1];

    let push_obj = |out: &mut Vec<u8>, offsets: &mut Vec<usize>, num: usize, body: &str| {
        offsets[num] = out.len();
        out.extend_from_slice(format!("{num} 0 obj\n{body}\nendobj\n").as_bytes());
    };

    push_obj(
        &mut out,
        &mut offsets,
        1,
        "<< /Type /Catalog /Pages 2 0 R >>",
    );
    let kids: Vec<String> = (0..n_pages)
        .map(|i| format!("{} 0 R", page_obj(i)))
        .collect();
    push_obj(
        &mut out,
        &mut offsets,
        2,
        &format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            n_pages
        ),
    );
    push_obj(
        &mut out,
        &mut offsets,
        3,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    );
    for i in 0..n_pages {
        let content = pages.get(i).map(String::as_str).unwrap_or("");
        push_obj(
            &mut out,
            &mut offsets,
            page_obj(i),
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.0} {:.0}] \
                 /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
                PAGE_W,
                PAGE_H,
                content_obj(i)
            ),
        );
        let stream = format!(
            "<< /Length {} >>\nstream\n{}\nendstream",
            content.len(),
            content
        );
        push_obj(&mut out, &mut offsets, content_obj(i), &stream);
    }

    let xref_off = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", total_objs + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets[1..=total_objs] {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            total_objs + 1,
            xref_off
        )
        .as_bytes(),
    );
    out
}

#[cfg(test)]
mod tests;
