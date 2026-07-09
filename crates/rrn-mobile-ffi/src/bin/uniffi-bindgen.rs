//! In-crate uniffi binding generator (the standard uniffi convention).
//!
//! Produces the Swift / Kotlin foreign-language bindings from the compiled
//! library's metadata. The React Native TypeScript bindings are generated
//! separately by `uniffi-bindgen-react-native` (see ADR-0007), which reads the
//! same UDL contract.
//!
//! Usage:
//!   cargo run -p rrn-mobile-ffi --bin uniffi-bindgen -- \
//!       generate --library <path-to-dylib> --language swift --out-dir <dir>

fn main() {
    uniffi::uniffi_bindgen_main()
}
