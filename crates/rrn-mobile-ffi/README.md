# rrn-mobile-ffi

The **mobile FFI binding surface** for Railroad Network. A thin, curated
[uniffi](https://mozilla.github.io/uniffi-rs/) wrapper over `rrn-crypto` and
`rrn-identity`, per [ADR-0007](../../docs/adr/0007-rust-mobile-ffi-uniffi.md).

The mobile app (React Native) is the authoritative key-holder (ADR-0006), so the
Rust crypto core runs *on the device*. This crate is the one place the FFI lives:
`rrn-crypto` and `rrn-identity` stay pure Rust with `unsafe` forbidden, and all
of uniffi's build machinery and generated `unsafe` scaffolding is quarantined
here.

## The contract

[`src/rrn_mobile_ffi.udl`](src/rrn_mobile_ffi.udl) is the **single source of
truth** for the Swift, Kotlin, and React Native bindings — they are generated
from it, so they cannot drift from the Rust or from each other. Keep the surface
narrow: only what mobile actually performs.

Current surface (M1.1 T1.1.1): `Keypair`, `PublicKey`, `Signature`, `Hash`.
`SecretKey` is **deliberately not exposed** — the secret seed never crosses the
FFI boundary in the clear (no-export-secret rule, ADR-0006). Address parsing
(T1.1.3), the wallet file format (T1.1.5), and `SignedPayload`/dcbor (T1.1.7)
extend this UDL in their own tasks.

## Version pinning

`uniffi` is pinned to **0.31** to stay paired with
[`uniffi-bindgen-react-native`](https://github.com/jhugman/uniffi-bindgen-react-native)
0.31.x, the React Native wrapper the mobile app consumes. **Do not bump `uniffi`
independently of that wrapper** — they must match.

## Toolchain

```sh
# Rust iOS targets (device + both simulator arches)
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Xcode command-line tools (xcodebuild, lipo) — for the xcframework
xcode-select --install
```

Android (deferred in M1.1 — no JDK/SDK in the current dev environment): add
`aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`, install the
Android NDK, and generate the AAR with `uniffi-bindgen-react-native`.

## Building

```sh
cargo build -p rrn-mobile-ffi          # host build + generated scaffolding
cargo test  -p rrn-mobile-ffi          # marshalling smoke tests

# Swift + Kotlin bindings from the compiled library:
cargo run -p rrn-mobile-ffi --bin uniffi-bindgen -- \
    generate --library target/debug/librrn_mobile_ffi.dylib \
    --language swift --out-dir generated

# Full iOS artifact (xcframework + Swift glue) the mobile app consumes:
./build-ios.sh              # release
./build-ios.sh debug        # faster, for local checks
```

`build-ios.sh` sets `IPHONEOS_DEPLOYMENT_TARGET=13.0`: blake3's NEON objects are
compiled against the current iOS SDK and reference runtime symbols
(`___chkstk_darwin`) absent at Rust's default iOS 10 floor, so the device link
fails without a modern deployment target. Keep this in sync with the app's
minimum iOS version.

## How mobile consumes this

Station CI runs `build-ios.sh` and publishes `RrnMobileFfi.xcframework` + the
generated bindings as a **versioned release artifact**. The mobile repo pulls the
prebuilt binary — it needs no Rust toolchain of its own (the "prebuilt artifact"
decision). The `generated/` and `build/` directories here are throwaway and
git-ignored.
