//! The mobile FFI's pairing functions reproduce the station's pairing-handshake
//! fixture byte-for-byte (ADR-0008, Clarification 2026-10-14;
//! `docs/spec/pairing.md`). The fixture is generated in `rrn-identity`
//! (`tests/it/cross_platform_pairing_v2.rs`) and read here from its committed
//! path, so the FFI cannot drift from the layouts the station checks.

use rrn_mobile_ffi::{
    pairing_code, pairing_commitment, pairing_finish_signed_bytes, pairing_nonce,
    pairing_offer_signed_bytes, pairing_start_signed_bytes, CryptoError,
};

fn fixture() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rrn-identity/tests/fixtures/cross_platform_pairing_v2.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).unwrap()
}

fn b(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).unwrap()
}

#[test]
fn ffi_pairing_reproduces_the_v2_fixture() {
    let f = fixture();
    let h = &f["handshake"];
    let commitment = pairing_commitment(b(&h["mobile_pk"]), b(&h["mobile_nonce"])).unwrap();
    assert_eq!(commitment, b(&h["commitment"]));
    assert_eq!(
        pairing_start_signed_bytes(
            b(&h["mobile_pk"]),
            commitment.clone(),
            h["requested_at"].as_i64().unwrap()
        )
        .unwrap(),
        b(&h["start_signed_bytes"])
    );
    assert_eq!(
        pairing_offer_signed_bytes(
            b(&h["station_pk"]),
            b(&h["mobile_pk"]),
            commitment.clone(),
            b(&h["station_nonce"])
        )
        .unwrap(),
        b(&h["offer_signed_bytes"])
    );
    assert_eq!(
        pairing_finish_signed_bytes(
            b(&h["station_pk"]),
            b(&h["mobile_pk"]),
            commitment,
            b(&h["station_nonce"]),
            b(&h["mobile_nonce"])
        )
        .unwrap(),
        b(&h["finish_signed_bytes"])
    );
    assert_eq!(
        pairing_code(
            b(&h["station_pk"]),
            b(&h["mobile_pk"]),
            b(&h["mobile_nonce"]),
            b(&h["station_nonce"])
        )
        .unwrap(),
        h["code"].as_str().unwrap()
    );

    for v in f["code_vectors"].as_array().unwrap() {
        assert_eq!(
            pairing_code(
                b(&v["station_pk"]),
                b(&v["mobile_pk"]),
                b(&v["mobile_nonce"]),
                b(&v["station_nonce"])
            )
            .unwrap(),
            v["code"].as_str().unwrap()
        );
    }
    for v in f["start_vectors"].as_array().unwrap() {
        assert_eq!(
            pairing_start_signed_bytes(
                b(&v["mobile_pk"]),
                b(&v["commitment"]),
                v["requested_at"].as_i64().unwrap()
            )
            .unwrap(),
            b(&v["start_signed_bytes"])
        );
    }
}

#[test]
fn ffi_pairing_refuses_wrong_lengths() {
    let short = vec![0u8; 31];
    let ok = vec![0u8; 32];
    assert!(matches!(
        pairing_commitment(short.clone(), ok.clone()),
        Err(CryptoError::WrongLength)
    ));
    assert!(matches!(
        pairing_start_signed_bytes(ok.clone(), vec![0u8; 33], 0),
        Err(CryptoError::WrongLength)
    ));
    assert!(matches!(
        pairing_code(ok.clone(), ok.clone(), ok, short),
        Err(CryptoError::WrongLength)
    ));
    assert_eq!(pairing_nonce().len(), 32);
}
