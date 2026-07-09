//! Generates the uniffi FFI scaffolding from the UDL contract at build time.
//!
//! The generated `rrn_mobile_ffi.uniffi.rs` is pulled into `lib.rs` via
//! `uniffi::include_scaffolding!`. Regenerated whenever the `.udl` changes.

fn main() {
    uniffi::generate_scaffolding("src/rrn_mobile_ffi.udl")
        .expect("failed to generate uniffi scaffolding from rrn_mobile_ffi.udl");
}
