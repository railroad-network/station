#![no_main]
//! Fuzz Shamir reconstruction: arbitrary bytes are sliced into raw shards and
//! fed to `reconstruct_secret`. The interpolation must reject malformed shard
//! sets (too few, duplicate or zero indices) with an error and must never
//! panic — even though arbitrary shards almost never reconstruct to a
//! meaningful secret. This exercises the GF(256) arithmetic and Lagrange
//! interpolation against adversarial field points (see ADR-0004).

use libfuzzer_sys::fuzz_target;
use rrn_identity::recovery::shamir::{reconstruct_secret, RawShard, ShardIndex};

// One index byte + 32 data bytes per shard, matching `RawShard`'s shape.
const SHARD_LEN: usize = 1 + 32;

fuzz_target!(|data: &[u8]| {
    let mut shards = Vec::new();
    for chunk in data.chunks(SHARD_LEN) {
        if chunk.len() < SHARD_LEN {
            break;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&chunk[1..SHARD_LEN]);
        shards.push(RawShard {
            index: ShardIndex(chunk[0]),
            data: bytes,
        });
    }
    let _ = reconstruct_secret(&shards);
});
