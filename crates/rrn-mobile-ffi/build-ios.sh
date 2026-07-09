#!/usr/bin/env bash
# Builds the iOS artifacts the mobile app consumes (ADR-0007):
#   * an .xcframework wrapping the Rust static libs for device + simulator
#   * the generated Swift bindings + C headers
#
# This is the reproducible recipe behind M1.1 T1.1.0. Station CI runs it to
# publish a versioned artifact; the mobile repo pulls the result (it needs no
# Rust toolchain of its own — the "prebuilt artifact" decision).
#
# Prerequisites (see README.md):
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Usage:  ./build-ios.sh [debug|release]   (default: release)
set -euo pipefail

PROFILE="${1:-release}"
CARGO_FLAGS=(); [ "$PROFILE" = "release" ] && CARGO_FLAGS+=(--release)

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
LIB_NAME="librrn_mobile_ffi.a"
OUT="$CRATE_DIR/generated"
BUILD="$CRATE_DIR/build"

# blake3's NEON path (built against the current iOS SDK) references symbols that
# only exist at a modern deployment target; the Rust default (iOS 10) is too old
# and fails to link. Pin a floor. Keep in sync with the app's minimum iOS.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}"

cd "$WORKSPACE_DIR"
rm -rf "$OUT" "$BUILD"; mkdir -p "$OUT" "$BUILD"

echo ">> Building Rust static libs ($PROFILE, deployment target $IPHONEOS_DEPLOYMENT_TARGET)"
for TARGET in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo build -p rrn-mobile-ffi --target "$TARGET" ${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"}
done

# The simulator slice is a fat lib of arm64 + x86_64; device stays single-arch.
# Each slice lives in its own dir so both keep the .a name xcodebuild requires.
echo ">> Combining simulator architectures with lipo"
mkdir -p "$BUILD/sim" "$BUILD/device"
cp "target/aarch64-apple-ios/$PROFILE/$LIB_NAME" "$BUILD/device/$LIB_NAME"
lipo -create \
    "target/aarch64-apple-ios-sim/$PROFILE/$LIB_NAME" \
    "target/x86_64-apple-ios/$PROFILE/$LIB_NAME" \
    -output "$BUILD/sim/$LIB_NAME"

echo ">> Generating Swift bindings + headers"
cargo run -q -p rrn-mobile-ffi --bin uniffi-bindgen -- generate \
    --library "target/aarch64-apple-ios/$PROFILE/$LIB_NAME" \
    --language swift --out-dir "$OUT"
# uniffi emits a per-module .modulemap; the xcframework wants it named module.modulemap.
HEADERS="$BUILD/headers"; mkdir -p "$HEADERS"
cp "$OUT"/*.h "$HEADERS/"
cp "$OUT"/*.modulemap "$HEADERS/module.modulemap"

echo ">> Assembling xcframework"
rm -rf "$OUT/RrnMobileFfi.xcframework"
xcodebuild -create-xcframework \
    -library "$BUILD/device/$LIB_NAME" -headers "$HEADERS" \
    -library "$BUILD/sim/$LIB_NAME" -headers "$HEADERS" \
    -output "$OUT/RrnMobileFfi.xcframework"

echo ">> Done."
echo "   xcframework: $OUT/RrnMobileFfi.xcframework"
echo "   swift glue:  $OUT/rrn_mobile_ffi.swift"
