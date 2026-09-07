//! `paper-phone-sim` — a stand-in for a member's **phone** in the paper-fallback
//! demo (T2.5.2). It is deliberately not part of the product and not a wallet: it
//! exists so `scripts/demo-phase-2-paper.sh` (and a human) can play the offline
//! member whose records travel only on paper.
//!
//! Why an example and not the `rrn` CLI: a member's key lives on the phone
//! (ADR-0006), and offline authoring is `rrn-mobile-ffi`'s job (T2.4.2) — the CLI
//! is the operator's station console and holds no member key. This binary signs
//! with the **same** `rrn-protocol`/`rrn-ledger`/`rrn-crypto` wire types the
//! mobile FFI wraps, so the bytes it emits are exactly what a real phone would.
//!
//! Usage:
//!   paper-phone-sim gen-key <keyfile>
//!       → generate a member keypair, save it, print its rrn1… address
//!   paper-phone-sim sign-confirmation <keyfile> <proposal-id-hex> <out.txt>
//!       → confirm a proposal OFFLINE, wrap it in a one-entry DTN bundle, and
//!         write the bundle as `rrnp:` QR-text lines (one per line)
//!   paper-phone-sim read-receipt <receipts.txt>
//!       → reassemble the station's delivery receipt(s) and print the outcomes
//!
//! Limitation (fine for a one-shot demo): `sign-confirmation` always emits outbox
//! position 0 with an all-zero `prev_hash` — it keeps no chain state. Signing a
//! *second* record with the same key would produce another position-0 entry,
//! which the station treats as an outbox fork (refused, and recorded as
//! equivocation evidence, T2.3.3). A real phone chains via
//! `rrn-mobile-ffi::outbox_next_entry`; this stand-in does not.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_identity::address::Address;
use rrn_ledger::transaction::{SignedConfirmation, TransactionConfirmation, TransactionId};
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{OutboxEntry, SignedOutboxEntry};
use rrn_protocol::paper::{classify, encode_chunks, PaperKind, PaperPayloadKind, PaperReassembler};
use rrn_protocol::receipt::{self, Disposition};
use rrn_station::core::{hex, unhex};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("gen-key") => gen_key(&args[1..]),
        Some("sign-confirmation") => sign_confirmation(&args[1..]),
        Some("read-receipt") => read_receipt(&args[1..]),
        _ => {
            eprintln!(
                "usage: paper-phone-sim <gen-key|sign-confirmation|read-receipt> …\n\
                 see the file header for arguments"
            );
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

type R = Result<(), String>;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load_key(path: &str) -> Result<Keypair, String> {
    let hex_str = std::fs::read_to_string(path)
        .map_err(|e| format!("read key {path}: {e}"))?
        .trim()
        .to_string();
    let bytes = unhex(&hex_str).ok_or("key file is not hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "key must be 32 bytes")?;
    Ok(Keypair::from_secret(SecretKey::from_bytes(arr)))
}

fn gen_key(args: &[String]) -> R {
    let path = args.first().ok_or("gen-key <keyfile>")?;
    let kp = Keypair::generate();
    std::fs::write(path, hex(&kp.secret_key().to_bytes()))
        .map_err(|e| format!("write {path}: {e}"))?;
    let addr = Address::from_public_key(kp.public_key());
    println!("{addr}");
    Ok(())
}

fn sign_confirmation(args: &[String]) -> R {
    let [keyfile, proposal_hex, out] = args else {
        return Err("sign-confirmation <keyfile> <proposal-id-hex> <out.txt>".into());
    };
    let kp = load_key(keyfile)?;
    let addr = Address::from_public_key(kp.public_key());
    let id = Hash::from_hex(proposal_hex).map_err(|e| format!("bad proposal id: {e}"))?;

    // Confirm the proposal offline — the same record type the app signs.
    let conf = SignedConfirmation::sign(
        TransactionConfirmation {
            proposal_id: TransactionId(id),
            confirmer: addr,
            confirmed_at: now(),
        },
        &kp,
    );
    // Wrap it as this member's outbox entry (position 0, single-entry bundle) and
    // assemble the carriage bundle — exactly what `rrn-mobile-ffi::outbox_next_entry`
    // + `bundle_assemble` produce.
    let entry: SignedOutboxEntry = rrn_crypto::signed::SignedPayload::sign(
        OutboxEntry::wrapping(addr, 0, Hash::from_bytes([0u8; 32]), &conf, now()),
        &kp,
    );
    let bundle = Bundle::new(vec![EntryEnvelope::from_signed(&entry)], now());
    let chunks = encode_chunks(PaperKind::Bundle, &bundle.encode())
        .map_err(|e| format!("chunk bundle: {e}"))?;
    std::fs::write(out, format!("{}\n", chunks.join("\n")))
        .map_err(|e| format!("write {out}: {e}"))?;
    println!(
        "wrote {} QR chunk(s) for a confirmation by {addr} to {out}",
        chunks.len()
    );
    Ok(())
}

fn read_receipt(args: &[String]) -> R {
    let path = args.first().ok_or("read-receipt <receipts.txt>")?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut reass = PaperReassembler::new();
    let mut receipts: Vec<Vec<u8>> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match classify(line) {
            PaperPayloadKind::Multipart => {
                if let Some((_, bytes)) = reass.accept(line).map_err(|e| e.to_string())? {
                    receipts.push(bytes);
                }
            }
            _ => return Err(format!("not a receipt QR: {line}")),
        }
    }
    if receipts.is_empty() {
        return Err("no complete receipt found".into());
    }
    for bytes in &receipts {
        let signed = receipt::decode_signed(bytes).map_err(|e| format!("decode receipt: {e}"))?;
        let ok = signed.verify().is_ok();
        println!(
            "receipt from {} — station signature {}",
            signed.payload.station,
            if ok { "ok" } else { "INVALID" }
        );
        for o in &signed.payload.outcomes {
            let disp = match &o.disposition {
                Disposition::Admitted { seq } => format!("admitted (seq {seq})"),
                Disposition::Known { seq } => format!("known (seq {seq})"),
                Disposition::Refused { reason } => format!("refused ({})", reason.as_slug()),
            };
            println!("  {} → {}", hex(&o.record_hash.to_bytes()), disp);
        }
    }
    Ok(())
}
