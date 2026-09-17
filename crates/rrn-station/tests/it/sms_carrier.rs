//! T2.7.1 — SMS as a DTN carrier, end to end.
//!
//! Proves the SMS path a real deployment relies on:
//!
//! 1. [`cert_backed_spend_travels_only_over_sms_and_settles`] — a two-member,
//!    one-station community where a **cert-backed offline spend** reaches the
//!    station *only* over SMS (chunked through the [`SmsRelay`] + a lossy
//!    [`MockSmsGateway`], never the socket `bundle_submit`), is ingested, settles
//!    after the window, and whose signed delivery receipt makes the return trip over
//!    SMS and reassembles on the member side.
//! 2. [`sms_binding_admits_via_ingest_and_flips_the_registry`] — a member-signed
//!    `rrn.net.sms_binding` admitted through the normal DTN front door flips the
//!    station's log-derived sender registry, and a binding signed by the wrong key
//!    is refused (the number the registry trusts must be its owner's).
//! 3. [`sms_gateway_loop_bridges_inbound_to_ingest`] — the daemon bridge
//!    ([`rrn_station::station::sms_gateway_loop`]) wired over the mock gateway:
//!    inbound texts → ingest → receipt back over SMS, on its own timer.
//!
//! Injected clocks keep it to seconds of wall-clock; the carrier faults are seeded,
//! so the run is deterministic.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::escrow::CertId;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
};
use rrn_protocol::airtime::Priority;
use rrn_protocol::binding::SmsBinding;
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{OutboxEntry, SignedOutboxEntry};
use rrn_protocol::paper::{
    encode_chunks_with_budget, sms_chunk_budget_bytes, PaperKind, PaperReassembler,
};
use rrn_protocol::receipt::{self, Disposition};
use rrn_station::rpc::{BalanceResult, CertRequestResult};
use rrn_station::rpc_client::UnixClient;
use rrn_station::sms::{
    AllowedSenders, BoundSenders, MessageBudget, MockSmsGateway, Msisdn, SmsFaults, SmsRelay,
    SmsRelayConfig,
};
use rrn_station::station::{Station, StationParams, WALLET_FILE};
use rrn_station::Clock;

const PASSPHRASE: &str = "sms-carrier-passphrase";
const START: i64 = 1_000_000;
const WINDOW: u64 = 60;
const MEMBER: &str = "+15550100200";

fn addr(k: &Keypair) -> Address {
    Address::from_public_key(k.public_key())
}

fn write_config(dir: &Path) {
    let text = format!(
        "[network]\n\
         listen = \"127.0.0.1:0\"\n\n\
         [mobile]\n\
         advertise = false\n\
         listen = \"127.0.0.1:0\"\n\n\
         [settlement]\n\
         window_seconds = {WINDOW}\n\n\
         [timers]\n\
         sweep_interval_secs = 1\n\
         gossip_interval_secs = 1\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

fn outbox_entry<T: Clone + Into<dcbor::CBOR>>(
    device: &Keypair,
    position: u64,
    prev: Hash,
    record: &SignedPayload<T>,
    authored_at: i64,
) -> SignedOutboxEntry {
    let entry = OutboxEntry::wrapping(addr(device), position, prev, record, authored_at);
    SignedPayload::sign(entry, device)
}

async fn balance(client: &UnixClient, address: &str) -> i64 {
    let v = client
        .call("balance", serde_json::json!({ "address": address }))
        .await
        .unwrap();
    serde_json::from_value::<BalanceResult>(v)
        .unwrap()
        .balance_centi
}

/// Spins up a fresh station on a manual clock and returns it with its operator
/// keypair (recovered from the wallet file for in-test signing) and a socket client.
async fn spawn_station(dir: &Path) -> (Station, Keypair, UnixClient) {
    Station::init(dir, PASSPHRASE).unwrap();
    write_config(dir);
    let station = Station::open(StationParams {
        data_dir: dir.to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::manual(START),
    })
    .await
    .unwrap();
    let wallet = WalletContents::load_from_file(&dir.join(WALLET_FILE), PASSPHRASE).unwrap();
    let operator = Keypair::from_secret(wallet.secret_key.clone());
    let client = UnixClient::new(station.socket_path());
    (station, operator, client)
}

#[tokio::test]
async fn cert_backed_spend_travels_only_over_sms_and_settles() {
    tokio::time::timeout(Duration::from_secs(55), run_cert_spend_over_sms())
        .await
        .expect("SMS cert-backed spend must finish well under the timeout");
}

async fn run_cert_spend_over_sms() {
    let dir = tempfile::tempdir().unwrap();
    let (station, operator, client) = spawn_station(dir.path()).await;
    let clock = station.clock();
    let a_addr = addr(&operator);
    let b = Keypair::generate();
    let b_addr = addr(&b);

    // The operator issues itself a 500-cap certificate (operator nonce 0).
    let cert: CertRequestResult = serde_json::from_value(
        client
            .call("cert_request", serde_json::json!({ "cap_centi": 500 }))
            .await
            .unwrap(),
    )
    .unwrap();
    let cert_id = CertId(Hash::from_hex(&cert.cert_id).unwrap());

    // A cert-backed 300 spend to B (operator nonce 1), and B's confirmation. Both
    // signed OFFLINE — they will reach the station only over SMS.
    let spend = SignedProposal::sign(
        TransactionProposal::new(a_addr, b_addr, 300, None, 1, clock.now(), cert.expires_at)
            .with_certificate(cert_id),
        &operator,
    );
    let conf = SignedConfirmation::sign(
        TransactionConfirmation {
            proposal_id: spend.payload.id,
            confirmer: b_addr,
            confirmed_at: clock.now(),
        },
        &b,
    );
    let bundle_bytes = Bundle::new(
        vec![
            EntryEnvelope::from_signed(&outbox_entry(
                &operator,
                0,
                Hash::from_bytes([0u8; 32]),
                &spend,
                clock.now(),
            )),
            EntryEnvelope::from_signed(&outbox_entry(
                &b,
                0,
                Hash::from_bytes([0u8; 32]),
                &conf,
                clock.now(),
            )),
        ],
        clock.now(),
    )
    .encode();

    // The member's phone chunks the bundle for SMS and texts it over a lossy carrier.
    let member = Msisdn::parse(MEMBER).unwrap();
    let chunks =
        encode_chunks_with_budget(PaperKind::Bundle, &bundle_bytes, sms_chunk_budget_bytes(4))
            .unwrap();
    assert!(
        chunks.len() > 1,
        "the bundle should span several SMS chunks"
    );

    let mut relay = SmsRelay::new(
        MockSmsGateway::new(SmsFaults {
            drop_prob: 0.2,
            dup_prob: 0.1,
            truncate_prob: 0.1,
            reorder: true,
            seed: 1,
        }),
        SmsRelayConfig {
            allowed_senders: AllowedSenders::Open,
            // Generous burst so pacing doesn't dominate the round count.
            message_budget: MessageBudget {
                messages_per_sec: 1.0,
                burst: 10_000,
            },
            ..SmsRelayConfig::default()
        },
        clock.now(),
    );
    let bound = BoundSenders::new(); // open mode

    // Drive re-send rounds until the station-signed receipt reassembles on the
    // member side. SMS has no ack: the member re-texts the bundle each round; the
    // station re-ingests idempotently and re-queues the (cached) receipt, which the
    // carrier eventually carries back intact. A persistent member-side reassembler
    // fed the *new* texts each round gets the HashMismatch-reset recovery a real
    // receiver has.
    let now = clock.now();
    let mut member_re = PaperReassembler::new();
    let mut consumed = 0usize;
    let mut receipt_bytes = None;
    for _round in 0..600 {
        for text in &chunks {
            relay.gateway().push_inbound(&member, text, now);
        }
        for c in relay.poll(now, &bound).unwrap() {
            assert_eq!(c.kind, PaperKind::Bundle);
            let receipt = station
                .core()
                .ingest_bundle_bytes(c.bytes)
                .await
                .expect("bundle ingests to a receipt");
            relay
                .queue_payload(&member, PaperKind::Receipt, &receipt, Priority::Economic)
                .unwrap();
        }
        relay.pump(now);
        // Feed only the newly-arrived station→member texts into the reassembler.
        let sent = relay.gateway().sent_to(&member);
        for line in sent.iter().skip(consumed) {
            if let Ok(Some((kind, bytes))) = member_re.accept(line) {
                if kind == PaperKind::Receipt {
                    receipt_bytes = Some(bytes);
                }
            }
        }
        consumed = sent.len();
        if receipt_bytes.is_some() {
            break;
        }
    }

    // The receipt returned over SMS, verifies, and reports both records admitted.
    let signed = receipt::decode_signed(&receipt_bytes.expect("receipt returns over SMS")).unwrap();
    assert!(signed.verify().is_ok(), "the returned receipt must verify");
    assert_eq!(signed.payload.outcomes.len(), 2);
    for o in &signed.payload.outcomes {
        assert!(
            matches!(o.disposition, Disposition::Admitted { .. }),
            "each record admitted over the SMS carrier"
        );
    }

    // The spend settles after the window — value moved, over SMS alone.
    clock.advance(WINDOW as i64 + 1);
    station.sweep().await;
    assert_eq!(balance(&client, &a_addr.to_string()).await, -300);
    assert_eq!(balance(&client, &b_addr.to_string()).await, 300);

    station.shutdown().await;
}

#[tokio::test]
async fn sms_binding_admits_via_ingest_and_flips_the_registry() {
    let dir = tempfile::tempdir().unwrap();
    let (station, _operator, _client) = spawn_station(dir.path()).await;
    let now = station.clock().now();
    let member = Msisdn::parse(MEMBER).unwrap();

    let b = Keypair::generate();
    let b_addr = addr(&b);

    // Before any binding, the registry is empty.
    assert!(station.core().sms_bound_senders().await.is_empty());

    // A binding signed by the WRONG key (Mallory tries to bind B's identity to
    // Mallory's own number) is refused — the register-me statement must be its
    // owner's. A distinct number so it is a distinct record, not a byte-identical
    // re-presentation of B's own binding below.
    let mallory = Keypair::generate();
    let forged = SignedPayload::sign(SmsBinding::new(b_addr, "+15558887777", now), &mallory);
    let forged_bundle = Bundle::new(
        vec![EntryEnvelope::from_signed(&outbox_entry(
            &mallory,
            0,
            Hash::from_bytes([0u8; 32]),
            &forged,
            now,
        ))],
        now,
    )
    .encode();
    let receipt = station
        .core()
        .ingest_bundle_bytes(forged_bundle)
        .await
        .unwrap();
    let signed = receipt::decode_signed(&receipt).unwrap();
    assert!(
        matches!(
            signed.payload.outcomes[0].disposition,
            Disposition::Refused { .. }
        ),
        "a binding signed by the wrong key must be refused"
    );
    assert!(station.core().sms_bound_senders().await.is_empty());

    // B self-signs its own binding; admitted through the normal DTN front door.
    let binding = SignedPayload::sign(SmsBinding::new(b_addr, MEMBER, now), &b);
    let bundle = Bundle::new(
        vec![EntryEnvelope::from_signed(&outbox_entry(
            &b,
            0,
            Hash::from_bytes([0u8; 32]),
            &binding,
            now,
        ))],
        now,
    )
    .encode();
    let first_receipt = station.core().ingest_bundle_bytes(bundle).await.unwrap();
    let signed = receipt::decode_signed(&first_receipt).unwrap();
    assert!(
        matches!(
            signed.payload.outcomes[0].disposition,
            Disposition::Admitted { .. }
        ),
        "a self-signed binding is admitted, got {:?}",
        signed.payload.outcomes[0].disposition
    );

    // The log-derived registry now names B's number.
    let bound = station.core().sms_bound_senders().await;
    assert!(bound.contains(&member), "the binding flips the registry");
    assert_eq!(bound.len(), 1);

    // Idempotent: re-ingesting the identical bundle re-admits nothing — it replays
    // the stored receipt byte-for-byte (ADR-0020 §3), and the registry (a HashSet
    // derived from the log) stays a single entry.
    let again = Bundle::new(
        vec![EntryEnvelope::from_signed(&outbox_entry(
            &b,
            0,
            Hash::from_bytes([0u8; 32]),
            &binding,
            now,
        ))],
        now,
    )
    .encode();
    let replay = station.core().ingest_bundle_bytes(again).await.unwrap();
    assert_eq!(
        replay, first_receipt,
        "a byte-identical re-ingest replays the cached receipt verbatim"
    );
    assert_eq!(station.core().sms_bound_senders().await.len(), 1);

    // A per-record `known` outcome: re-carry the same binding in a DIFFERENT
    // presentation (bundled with a fresh, second binding), so the ledger's dedup
    // answers `known` for the old record and admits only the new one.

    // Rebind: B binds a NEW number with a later `bound_at`, carried in one bundle
    // alongside its (already-admitted) first binding. Latest-wins per identity, so
    // the registry ends up naming the new number and dropping the old one; and the
    // re-carried first binding answers `known` while the new one is `admitted`.
    let new_number = "+15550999888";
    let first_entry = outbox_entry(&b, 0, Hash::from_bytes([0u8; 32]), &binding, now);
    let rebind = SignedPayload::sign(SmsBinding::new(b_addr, new_number, now + 10), &b);
    let rebind_entry = outbox_entry(&b, 1, first_entry.payload.entry_hash(), &rebind, now + 10);
    let rebind_bundle = Bundle::new(
        vec![
            EntryEnvelope::from_signed(&first_entry),
            EntryEnvelope::from_signed(&rebind_entry),
        ],
        now + 10,
    )
    .encode();
    let receipt = station
        .core()
        .ingest_bundle_bytes(rebind_bundle)
        .await
        .unwrap();
    let signed = receipt::decode_signed(&receipt).unwrap();
    assert!(
        matches!(
            signed.payload.outcomes[0].disposition,
            Disposition::Known { .. }
        ),
        "the re-carried first binding is known, got {:?}",
        signed.payload.outcomes[0].disposition
    );
    assert!(
        matches!(
            signed.payload.outcomes[1].disposition,
            Disposition::Admitted { .. }
        ),
        "the new binding is admitted, got {:?}",
        signed.payload.outcomes[1].disposition
    );
    let bound = station.core().sms_bound_senders().await;
    assert_eq!(bound.len(), 1, "one identity → one current number");
    assert!(
        bound.contains(&Msisdn::parse(new_number).unwrap()),
        "the later binding wins"
    );
    assert!(
        !bound.contains(&member),
        "the superseded number drops out of the registry"
    );

    station.shutdown().await;
}

#[tokio::test]
async fn sms_gateway_loop_bridges_inbound_to_ingest() {
    tokio::time::timeout(Duration::from_secs(30), run_gateway_loop_bridge())
        .await
        .expect("the SMS gateway loop must bridge inbound → ingest → receipt in time");
}

async fn run_gateway_loop_bridge() {
    let dir = tempfile::tempdir().unwrap();
    let (station, operator, _client) = spawn_station(dir.path()).await;
    let now = station.clock().now();
    let a_addr = addr(&operator);
    let b = Keypair::generate();
    let b_addr = addr(&b);
    let member = Msisdn::parse(MEMBER).unwrap();

    // A plain payment bundle (operator proposes 250 to B, B confirms), offline.
    let prop = SignedProposal::sign(
        TransactionProposal::new(
            a_addr,
            b_addr,
            250,
            None,
            0,
            now,
            START + 100 * WINDOW as i64,
        ),
        &operator,
    );
    let conf = SignedConfirmation::sign(
        TransactionConfirmation {
            proposal_id: prop.payload.id,
            confirmer: b_addr,
            confirmed_at: now,
        },
        &b,
    );
    let bundle = Bundle::new(
        vec![
            EntryEnvelope::from_signed(&outbox_entry(
                &operator,
                0,
                Hash::from_bytes([0u8; 32]),
                &prop,
                now,
            )),
            EntryEnvelope::from_signed(&outbox_entry(
                &b,
                0,
                Hash::from_bytes([0u8; 32]),
                &conf,
                now,
            )),
        ],
        now,
    )
    .encode();
    let chunks =
        encode_chunks_with_budget(PaperKind::Bundle, &bundle, sms_chunk_budget_bytes(4)).unwrap();

    // A shared, faultless gateway: the test holds one Arc handle to inject/inspect,
    // the relay owns another. Push the inbound bundle chunks, then spawn the bridge.
    let gateway = Arc::new(MockSmsGateway::new(SmsFaults::none(1)));
    for text in &chunks {
        gateway.push_inbound(&member, text, now);
    }
    let relay = SmsRelay::new(
        gateway.clone(),
        SmsRelayConfig {
            allowed_senders: AllowedSenders::Open,
            ..SmsRelayConfig::default()
        },
        now,
    );
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(rrn_station::station::sms_gateway_loop(
        relay,
        false, // open mode
        station.core(),
        station.clock(),
        sd_rx,
    ));

    // The loop should ingest and text the receipt back within a few 1s ticks.
    let mut receipt = None;
    for _ in 0..80 {
        let mut re = PaperReassembler::new();
        for line in gateway.sent_to(&member) {
            if let Ok(Some((kind, bytes))) = re.accept(&line) {
                if kind == PaperKind::Receipt {
                    receipt = Some(bytes);
                }
            }
        }
        if receipt.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = sd_tx.send(true);
    let _ = handle.await;

    let signed = receipt::decode_signed(&receipt.expect("the loop texts a receipt back")).unwrap();
    assert!(signed.verify().is_ok());
    assert_eq!(signed.payload.outcomes.len(), 2);
    for o in &signed.payload.outcomes {
        assert!(matches!(o.disposition, Disposition::Admitted { .. }));
    }

    station.shutdown().await;
}
