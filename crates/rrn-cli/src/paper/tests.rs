//! Unit tests for the local paper codecs and renderers (no station needed).
//! The end-to-end export→ingest→receipts path is exercised against a real
//! station daemon in `tests/it/paper_roundtrip.rs`.

use super::*;

/// A minimal valid PNG: signature, an 8-bit grayscale IHDR of the right size,
/// and a decodable stored-DEFLATE IDAT.
#[test]
fn qr_png_is_a_well_formed_png() {
    let png = qr_png("rrn1exampleaddress").expect("render");
    assert_eq!(&png[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    // IHDR length (13) + type at bytes 8..16.
    assert_eq!(&png[12..16], b"IHDR");
    // Width and height are equal and positive.
    let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
    let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
    assert!(w > 0 && w == h, "square, non-empty: {w}x{h}");
    assert_eq!(png[24], 8, "8-bit depth");
    assert_eq!(png[25], 0, "grayscale");
    // Ends with an IEND chunk.
    assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
}

#[test]
fn empty_zlib_stored_roundtrips_adler() {
    // A stored zlib stream of empty input is still well-formed (header + one
    // final empty block + adler of empty = 1).
    let z = zlib_stored(&[]);
    assert_eq!(&z[..2], &[0x78, 0x01]);
    assert_eq!(&z[z.len() - 4..], &1u32.to_be_bytes());
}

#[test]
fn sheet_pdf_is_well_formed() {
    let items = vec![
        SheetItem {
            qr_text: "rrnp:b/AAAAAAAA/1/2/abc".to_string(),
            caption: vec!["AAAAAAAA  1/2".to_string(), "bundle".to_string()],
        },
        SheetItem {
            qr_text: "rrnp:b/AAAAAAAA/2/2/def".to_string(),
            caption: vec!["AAAAAAAA  2/2".to_string(), "bundle".to_string()],
        },
    ];
    let pdf = render_sheet_pdf(&items).expect("render");
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf.ends_with(b"%%EOF\n"));
    let s = String::from_utf8_lossy(&pdf);
    assert!(s.contains("/Type /Catalog"));
    assert!(s.contains("startxref"));
}

#[test]
fn card_pdf_renders() {
    let pdf = render_card_pdf(
        "Railroad Network — Member Credential",
        "rrn1exampleaddress",
        &[
            "name    Alice".to_string(),
            "address rrn1example".to_string(),
        ],
    )
    .expect("render");
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf.ends_with(b"%%EOF\n"));
}

#[test]
fn multipart_header_parses() {
    let (kind, id8, index, count) =
        parse_multipart_header("rrnp:b/Ab_cD3fg/2/7/somedata").expect("parse");
    assert_eq!(kind, 'b');
    assert_eq!(id8, "Ab_cD3fg");
    assert_eq!(index, 2);
    assert_eq!(count, 7);
    assert!(parse_multipart_header("rrncert:abc").is_none());
}

#[test]
fn pdf_escape_neutralizes_delimiters() {
    assert_eq!(pdf_escape("a(b)c\\d"), "a\\(b\\)c\\\\d");
    assert_eq!(pdf_escape("Common — €"), "Common ? ?");
}

#[test]
fn short_hash_never_panics_on_multibyte_input() {
    // Scanned text can carry multi-byte chars straddling the 8th / (len-4)th
    // byte; short_hash must slice by char, not byte (finding: no CLI abort).
    for s in [
        "rrn1€€€€€€€€€€",
        "———————————————",
        "a",
        "🚂🚂🚂🚂🚂🚂🚂🚂🚂🚂",
    ] {
        let _ = short_hash(s); // must not panic
    }
    assert_eq!(short_hash("short"), "short");
    assert_eq!(short_hash("0123456789abcdef0123"), "01234567…0123");
}

#[test]
fn crc32_and_adler32_known_answers() {
    // CRC-32/IEEE and Adler-32 vectors — a regression here silently corrupts
    // every generated PNG, so pin the checksums.
    assert_eq!(crc32(b"IEND"), 0xAE42_6082);
    assert_eq!(crc32(b""), 0);
    assert_eq!(adler32(b""), 1);
    assert_eq!(adler32(b"abc"), 0x024d_0127);
}

#[test]
fn wrap_breaks_on_char_boundary() {
    assert_eq!(wrap("abc", 8), vec!["abc"]);
    assert_eq!(wrap("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
    // Multi-byte chars are never split.
    assert_eq!(wrap("€€€€€", 2), vec!["€€", "€€", "€"]);
}

#[test]
fn read_payloads_dedups_rescan_and_reports_bad_lines() {
    // A complete multi-part group, scanned twice (a common re-read), plus one
    // mangled line among the good ones. Expect: exactly one recovered payload for
    // the group (no phantom "incomplete"), and the bad line reported — never an
    // abort that hides the good payload.
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../rrn-protocol/tests/fixtures/paper/multipart_bundle.txt"
    );
    let group = std::fs::read_to_string(fixture).expect("read fixture");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scanned.txt");
    // group, then a garbage certificate line, then the whole group again.
    std::fs::write(&path, format!("{group}\nrrncert:!!not-base64!!\n{group}\n")).unwrap();

    let payloads = read_payloads(&[path]).expect("read_payloads must not abort");
    let complete: Vec<_> = payloads.iter().filter(|p| p.bytes.is_some()).collect();
    assert_eq!(complete.len(), 1, "the re-scanned group is deduped to one");
    assert!(
        payloads.iter().any(|p| p.note.is_some()),
        "the mangled certificate line is reported, not fatal"
    );
    assert!(
        payloads.iter().all(|p| p.missing.is_empty()),
        "no phantom incomplete group from the re-scan"
    );
}

// --- `show` pins station-signed artifacts to `--station` -------------------

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_ledger::escrow::{CertId, RequestId};
use rrn_protocol::receipt::{DeliveryReceipt, Outcome};

fn addr_of(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

fn pinned(station: Option<&Keypair>, receiver: Option<&Keypair>) -> ShowPins {
    ShowPins {
        station: station.map(addr_of),
        receiver: receiver.map(addr_of),
    }
}

/// A certificate for `member` signed by `signer`, as envelope bytes.
fn cert_bytes(signer: &Keypair, member: &Keypair, cap: i64, expires_at: i64) -> Vec<u8> {
    let cert = HeadroomCertificate::new(
        addr_of(member),
        cap,
        RequestId(Hash::of(b"req")),
        100,
        expires_at,
    );
    escrow::encode_certificate_envelope(&SignedPayload::sign(cert, signer))
}

/// A `{signer, sig, body}` proposal envelope.
fn proposal_bytes(signed: &SignedProposal) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("signer", CBOR::to_byte_string(signed.signer.to_bytes()));
    m.insert("sig", CBOR::to_byte_string(signed.signature.to_bytes()));
    m.insert(
        "body",
        CBOR::to_byte_string(to_canonical_bytes(signed.payload.clone())),
    );
    CBOR::from(m).to_cbor_data()
}

fn spend(
    member: &Keypair,
    receiver: &Keypair,
    cert: CertId,
    amount: i64,
    nonce: u64,
) -> SignedProposal {
    let p = TransactionProposal::new(
        addr_of(member),
        addr_of(receiver),
        amount,
        None,
        nonce,
        1_000,
        9_000,
    )
    .with_certificate(cert);
    SignedPayload::sign(p, member)
}

#[test]
fn certificate_signed_by_throwaway_key_is_not_verified() {
    let station = Keypair::generate();
    let throwaway = Keypair::generate();
    let member = Keypair::generate();
    let bytes = cert_bytes(&throwaway, &member, 1_000, 5_000);

    // No pin: the signature is self-consistent but the signer is unknown.
    let insp = inspect_certificate(&bytes, &ShowPins::default(), 1_000);
    assert_eq!(insp.json["verified"], false);
    assert_eq!(insp.json["signer_checked"], false);
    assert_eq!(insp.json["signature_valid"], true);
    assert_eq!(insp.json["signer"], addr_of(&throwaway).to_string());
    assert!(insp.text.contains("UNKNOWN key"), "{}", insp.text);
    assert!(!insp.text.contains("station signature ok"), "{}", insp.text);

    // Pinned to the real station: the other key is named.
    let insp = inspect_certificate(&bytes, &pinned(Some(&station), None), 1_000);
    assert_eq!(insp.json["verified"], false);
    assert_eq!(insp.json["signer_checked"], true);
    assert!(insp.text.contains("SIGNED BY ANOTHER KEY"), "{}", insp.text);

    // The real station's certificate verifies when pinned, until it expires.
    let real = cert_bytes(&station, &member, 1_000, 5_000);
    let insp = inspect_certificate(&real, &pinned(Some(&station), None), 1_000);
    assert_eq!(insp.json["verified"], true);
    assert!(
        insp.text.contains("station signature ok (pinned"),
        "{}",
        insp.text
    );
    let insp = inspect_certificate(&real, &pinned(Some(&station), None), 6_000);
    assert_eq!(insp.json["verified"], false);
    assert_eq!(insp.json["expired"], true);
}

#[test]
fn self_named_receipt_is_not_verified_against_the_pin() {
    let station = Keypair::generate();
    let forger = Keypair::generate();
    // A receipt that names its own signer — self-consistent, and not the station.
    let receipt = |signer: &Keypair, names: &Keypair| {
        let r = DeliveryReceipt {
            station: addr_of(names),
            outcomes: vec![Outcome {
                record_hash: Hash::of(b"record"),
                disposition: Disposition::Admitted { seq: 7 },
            }],
            received_at: 1_000,
        };
        receipt::encode_signed(&SignedPayload::sign(r, signer))
    };
    let forged = receipt(&forger, &forger);

    let insp = inspect_receipt(&forged, &ShowPins::default());
    assert_eq!(insp.json["verified"], false);
    assert_eq!(insp.json["signer_checked"], false);
    assert!(insp.text.contains("UNKNOWN key"), "{}", insp.text);

    let insp = inspect_receipt(&forged, &pinned(Some(&station), None));
    assert_eq!(insp.json["verified"], false);
    assert!(insp.text.contains("SIGNED BY ANOTHER KEY"), "{}", insp.text);

    // Signed by the station but naming another: not verified either.
    let misnamed = receipt(&station, &forger);
    let insp = inspect_receipt(&misnamed, &pinned(Some(&station), None));
    assert_eq!(insp.json["verified"], false);
    assert!(insp.text.contains("NAMES ANOTHER STATION"), "{}", insp.text);
    assert!(!insp.text.contains("signature ok"), "{}", insp.text);

    let genuine = receipt(&station, &station);
    let insp = inspect_receipt(&genuine, &pinned(Some(&station), None));
    assert_eq!(insp.json["verified"], true);
    assert!(
        insp.text.contains("station signature ok (pinned"),
        "{}",
        insp.text
    );
}

#[test]
fn voucher_verdicts_come_from_the_shared_verifier() {
    let station = Keypair::generate();
    let member = Keypair::generate();
    let receiver = Keypair::generate();
    let cert = cert_bytes(&station, &member, 1_000, 5_000);
    let cert_id = escrow::decode_certificate_envelope(&cert)
        .unwrap()
        .payload
        .cert_id;
    let voucher = |proposal: Vec<u8>, history: Vec<Vec<u8>>| {
        SpendVoucher {
            proposal,
            cert: cert.clone(),
            history,
        }
        .encode()
    };
    let both = pinned(Some(&station), Some(&receiver));

    // ok, with what would remain.
    let v = voucher(
        proposal_bytes(&spend(&member, &receiver, cert_id, 200, 1)),
        vec![proposal_bytes(&spend(&member, &receiver, cert_id, 300, 0))],
    );
    let insp = inspect_spend_voucher(&v, &both, 1_000);
    assert_eq!(insp.json["verdict"], "ok");
    assert_eq!(insp.json["verified"], true);
    assert_eq!(insp.json["remaining_centi"], 500);

    // wrong-receiver: the voucher pays someone else.
    let stranger = Keypair::generate();
    let v = voucher(
        proposal_bytes(&spend(&member, &stranger, cert_id, 200, 1)),
        vec![],
    );
    let insp = inspect_spend_voucher(&v, &both, 1_000);
    assert_eq!(insp.json["verdict"], "wrong-receiver");
    assert_eq!(insp.json["verified"], false);

    // overspent against the presented history.
    let v = voucher(
        proposal_bytes(&spend(&member, &receiver, cert_id, 300, 1)),
        vec![proposal_bytes(&spend(&member, &receiver, cert_id, 800, 0))],
    );
    let insp = inspect_spend_voucher(&v, &both, 1_000);
    assert_eq!(insp.json["verdict"], "overspent");
    assert_eq!(insp.json["verified"], false);

    // bad-proposal-signature: signed by someone other than the sender.
    let mut forged = spend(&member, &receiver, cert_id, 200, 1);
    let impostor = Keypair::generate();
    forged.signer = impostor.public_key();
    forged.signature = impostor.sign(&to_canonical_bytes(forged.payload.clone()));
    let v = voucher(proposal_bytes(&forged), vec![]);
    let insp = inspect_spend_voucher(&v, &both, 1_000);
    assert_eq!(insp.json["verdict"], "bad-proposal-signature");
    assert_eq!(insp.json["verified"], false);

    // A missing pin: no verdict, never verified — even for a good voucher.
    let good = voucher(
        proposal_bytes(&spend(&member, &receiver, cert_id, 200, 1)),
        vec![],
    );
    for pins in [
        ShowPins::default(),
        pinned(Some(&station), None),
        pinned(None, Some(&receiver)),
    ] {
        let insp = inspect_spend_voucher(&good, &pins, 1_000);
        assert!(insp.json["verdict"].is_null());
        assert_eq!(insp.json["verified"], false);
        assert!(insp.text.contains("verdict: not checked"), "{}", insp.text);
    }
}
