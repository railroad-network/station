#!/usr/bin/env python3
"""Generate cross-implementation Shamir reference vectors for rrn-identity.

The committed output (`shamir_vectors.json`) lets `tests/shamir_reference_vectors.rs`
check our own Shamir implementation byte-for-byte against an *independent*,
*published* one — Trezor's `shamir-mnemonic`, the reference implementation of
SLIP-0039 — without any Python dependency at test time.

Two independent oracles back the vectors:

  * `shamir_mnemonic.shamir._interpolate(shares, x)` — Trezor's published GF(256)
    Lagrange interpolation, used directly (Section 2 / "slip0039") and used to
    *certify* the small Horner evaluator below (Section 3 / "cross_impl").
  * `shamir_mnemonic.shamir._split_secret(...)` — Trezor's published SLIP-0039
    split (secret pinned at index 255), used to produce reconstruction vectors.

Both use the *same field we do*: GF(256) under the Rijndael polynomial
`x^8 + x^4 + x^3 + x + 1` (0x11B) with generator `x + 1`. This script asserts
that equivalence before emitting anything.

Regenerate with:

    python3 -m venv venv && ./venv/bin/pip install 'shamir-mnemonic==0.3.0'
    ./venv/bin/python generate_shamir_vectors.py > shamir_vectors.json

`cross_impl` vectors are fully deterministic (fixed RNG seed). `slip0039`
vectors call the reference split's CSPRNG, so regenerating produces *different
but equally valid* vectors; that is fine — the committed file is what the test
reads.
"""

import json
import random

import shamir_mnemonic.shamir as S
from shamir_mnemonic.shamir import RawShare, _interpolate

SECRET_LEN = 32
SECRET_INDEX = S.SECRET_INDEX  # 255 in SLIP-0039

# --- Confirm shamir-mnemonic's field is the Rijndael field we implement -------
# Rebuild the EXP/LOG tables from the field definition and compare to the
# library's, so a future library change to a different field is caught here.
def _ref_tables():
    exp = [0] * 255
    log = [0] * 256
    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i
        poly = (poly << 1) ^ poly  # multiply by x + 1
        if poly & 0x100:
            poly ^= 0x11B  # reduce by the Rijndael polynomial
    return exp, log


_exp, _log = _ref_tables()
assert _exp == list(S.EXP_TABLE), "shamir-mnemonic EXP table is not the Rijndael field"
assert _log == list(S.LOG_TABLE), "shamir-mnemonic LOG table is not the Rijndael field"

EXP, LOG = S.EXP_TABLE, S.LOG_TABLE


def gmul(a, b):
    """GF(256) multiply over shamir-mnemonic's (published) tables."""
    if a == 0 or b == 0:
        return 0
    return EXP[(LOG[a] + LOG[b]) % 255]


def horner_eval(secret, coeffs, x):
    """Evaluate f_i(x) = secret[i] + sum_d coeffs[d][i]*x^(d+1) for all 32 i.

    `coeffs[d]` is the degree-(d+1) coefficient (one byte per position) — exactly
    the layout `rrn_identity::recovery::shamir::split_with_coefficients` consumes.
    """
    out = bytearray(SECRET_LEN)
    for i in range(SECRET_LEN):
        acc = 0
        for d in range(len(coeffs) - 1, -1, -1):
            acc = gmul(acc, x) ^ coeffs[d][i]
        acc = gmul(acc, x) ^ secret[i]
        out[i] = acc
    return bytes(out)


def make_cross_impl_case(rng, secret, k, n):
    """One Section-3 vector: explicit coefficients -> expected shards, certified
    against the published `_interpolate`."""
    coeffs = [bytes(rng.randrange(256) for _ in range(SECRET_LEN)) for _ in range(k - 1)]
    shards = [(x, horner_eval(secret, coeffs, x)) for x in range(1, n + 1)]

    # Certify the Horner output against Trezor's published interpolation: any K
    # shards must interpolate back to the secret at x=0, and to each remaining
    # shard at its own index.
    raw = [RawShare(x, data) for (x, data) in shards]
    chosen = raw[:k]
    assert _interpolate(chosen, 0) == secret, "Horner disagrees with _interpolate at x=0"
    for (x, data) in shards:
        assert _interpolate(chosen, x) == data, f"Horner disagrees with _interpolate at x={x}"

    return {
        "threshold": k,
        "total": n,
        "secret": secret.hex(),
        "coefficients": [c.hex() for c in coeffs],
        "shards": [{"index": x, "data": data.hex()} for (x, data) in shards],
    }


def make_slip0039_case(secret, k, n):
    """One Section-2 vector: Trezor's reference SLIP-0039 split (secret at index
    255). Reconstruction re-indexes member shares by XOR 255 so the secret lands
    at x=0, the convention our `reconstruct_secret` uses."""
    member = S._split_secret(k, n, secret)
    # Sanity: the reference recovers the secret by interpolating at index 255.
    assert _interpolate([RawShare(s.x, s.data) for s in member[:k]], SECRET_INDEX) == secret
    return {
        "threshold": k,
        "total": n,
        "secret_index": SECRET_INDEX,
        "secret": secret.hex(),
        "member_shares": [{"index": s.x, "data": s.data.hex()} for s in member],
    }


def main():
    rng = random.Random(0x5EED)  # fixed seed -> deterministic cross_impl vectors

    cross = []
    # Required edge cases first, with explicit small secrets.
    cross.append(make_cross_impl_case(rng, bytes(range(1, 33)), 2, 2))
    cross.append(make_cross_impl_case(rng, bytes(range(32, 0, -1)), 2, 3))
    cross.append(make_cross_impl_case(rng, bytes([0xA5] * 32), 3, 5))
    # 50+ randomized cases spanning thresholds and totals.
    for _ in range(60):
        k = rng.randint(2, 6)
        n = rng.randint(k, 16)
        secret = bytes(rng.randrange(256) for _ in range(SECRET_LEN))
        cross.append(make_cross_impl_case(rng, secret, k, n))

    slip = []
    for (k, n) in [(2, 2), (2, 3), (3, 5), (3, 4), (5, 8)]:
        secret = bytes(random.randrange(256) for _ in range(SECRET_LEN))
        slip.append(make_slip0039_case(secret, k, n))

    doc = {
        "_comment": (
            "Shamir reference vectors for rrn-identity. Generated by "
            "generate_shamir_vectors.py against Trezor shamir-mnemonic 0.3.0 "
            "(the SLIP-0039 reference). Field: GF(256), Rijndael 0x11B, "
            "generator x+1. cross_impl = explicit-coefficient split certified "
            "against _interpolate; slip0039 = reference SLIP-0039 split, "
            "reconstructed at x=0 by re-indexing member shares ^255."
        ),
        "field": {"polynomial": "0x11B", "generator": "x+1"},
        "cross_impl": cross,
        "slip0039": slip,
    }
    print(json.dumps(doc, indent=2))


if __name__ == "__main__":
    main()
