# Shamir reference vectors

`shamir_vectors.json` cross-validates our own Shamir's Secret Sharing
implementation (`rrn_identity::recovery::shamir`, see
[ADR-0004](../../../../docs/adr/0004-own-shamir-implementation.md)) against an
**independent, published** implementation, so the test
([`tests/shamir_reference_vectors.rs`](../shamir_reference_vectors.rs)) has **no
Python dependency at test time** — it reads the committed JSON.

## Reference implementation used

| Reference | Version | Role |
|---|---|---|
| Trezor [`shamir-mnemonic`](https://github.com/trezor/python-shamir-mnemonic) | **0.3.0** (PyPI) | The SLIP-0039 reference implementation. Its published `_interpolate` (GF(256) Lagrange interpolation) and `_split_secret` (SLIP-0039 split, secret pinned at index 255) are the oracle. |
| Hand computation | — | A handful of tiny vectors worked out directly with GF(256) arithmetic, hard-coded as literals in the test (Section 1). |

All parties operate in the **same field**: GF(256) under the Rijndael polynomial
`x^8 + x^4 + x^3 + x + 1` (`0x11B`) with generator `x + 1`. The generator script
rebuilds the `EXP`/`LOG` tables from that definition and asserts they equal
`shamir-mnemonic`'s before emitting anything — so a future library change to a
different field would fail loudly rather than silently producing bad vectors.

## What each section validates

- **`cross_impl`** (63 vectors, incl. the required K=2/N=2, K=2/N=3, K=3/N=5
  edge cases plus 60 randomized) — each pins an explicit set of polynomial
  coefficients and lists the expected shards. The expected shards are produced by
  a small Horner evaluator in the generator that is **certified against
  `shamir-mnemonic`'s `_interpolate`**: every case asserts that interpolating a
  threshold of the produced shards returns the secret at `x=0` and returns each
  remaining shard at its own index. Our `split_with_coefficients` must reproduce
  the shards **byte-for-byte**. Deterministic (fixed RNG seed `0x5EED`).

- **`slip0039`** (5 vectors) — member shares produced by `shamir-mnemonic`'s
  reference SLIP-0039 split `_split_secret`, which pins the secret at index 255.
  Our `reconstruct_secret` interpolates at `x=0`, so the test re-indexes each
  member share by `^255` (field addition of the constant 255): the polynomial
  `g(t) = f(t + 255)` then has `g(0) = f(255) = secret`, which our interpolation
  recovers. These vectors call the reference CSPRNG, so regeneration produces
  *different but equally valid* shares.

## Regenerating

```sh
cd crates/rrn-identity/tests/fixtures
python3 -m venv venv
./venv/bin/pip install 'shamir-mnemonic==0.3.0'
./venv/bin/python generate_shamir_vectors.py > shamir_vectors.json
```

The generator ([`generate_shamir_vectors.py`](generate_shamir_vectors.py)) is
committed and self-documenting. `cross_impl` output is reproducible bit-for-bit
across runs (fixed seed); `slip0039` output changes per run by design. After
regenerating, `cargo test --test shamir_reference_vectors -p rrn-identity` must
still pass.

> Note on scope: we validate only the **raw Shamir step**, not full SLIP-0039
> compatibility — we do not implement SLIP-0039's wrapper layers (RS1024
> checksum, identifier/encoding, the passphrase encryption pass). See ADR-0004.
