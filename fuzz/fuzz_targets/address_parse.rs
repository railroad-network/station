#![no_main]
//! Fuzz the bech32m address parser: an arbitrary string must parse to an
//! `Address` or return an `AddressParseError` — never panic. Bad checksums,
//! wrong HRPs, wrong lengths, and off-curve payloads are all expected,
//! handled outcomes.

use libfuzzer_sys::fuzz_target;
use rrn_identity::address::Address;
use std::str::FromStr;

fuzz_target!(|s: String| {
    let _ = Address::from_str(&s);
});
