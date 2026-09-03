//! Carrier-agnostic chunking and reassembly (ADR-0013, ADR-0020 §3).
//!
//! A [`crate::bundle::Bundle`] is routinely larger than a carrier's frame — LoRa
//! moves a couple hundred bytes at a time — so a payload is split into fixed-size
//! **chunks**, each carried as one [`FrameTransport`](crate::transport::FrameTransport)
//! frame, and reassembled at the far end. This module is that split/merge, proven
//! against loss, reordering, duplication, and corruption by the mock transports in
//! [`crate::transport::mock`]. It knows nothing about *which* carrier moves the
//! frames.
//!
//! # The chunk header is unauthenticated plumbing
//!
//! The [`HEADER_LEN`]-byte chunk header is a plain, manually big-endian-encoded
//! struct — **not** dCBOR. That is deliberate: framing is carrier plumbing, not
//! signed content. Nothing in the header is trusted. Integrity is enforced two
//! ways, neither of which relies on the header being honest:
//!
//! - a **CRC-32** over each chunk's payload catches carrier bit-flips cheaply and
//!   is verified before a chunk is ever stored;
//! - the **payload id is `Blake3(payload)`**, verified over the fully reassembled
//!   bytes — the authoritative check. A payload only reassembles if its bytes hash
//!   to the id every chunk claimed.
//!
//! So a forged or corrupted header can, at worst, waste bounded reassembly memory
//! (capped by [`ReassemblerConfig`]) or get a frame rejected — it can never
//! produce wrong bytes that pass as a real payload, and the signed records *inside*
//! the payload (ADR-0008/0020) are a further, independent integrity layer.
//!
//! # Header layout ([`HEADER_LEN`] = 76 bytes, big-endian)
//!
//! ```text
//! magic "RRNF"      4     payload_len   u32     chunk_len     u16
//! version u8 (=1)   1     chunk_index   u16     payload_crc32 u32
//! payload_id [u8;32] 32   chunk_count   u16     reserved      [u8;25]
//! ```
//!
//! Then `chunk_len` payload bytes follow the header. Every chunk of a payload is
//! `max_frame_bytes - HEADER_LEN` bytes except the last.

use rrn_crypto::hash::Hash;

/// The frame-header magic, ASCII `"RRNF"`.
pub const MAGIC: [u8; 4] = *b"RRNF";

/// The framing version carried in the header (bumped only on a wire change).
pub const FRAMING_VERSION: u8 = 1;

/// The fixed chunk-header length in bytes. A frame is this header followed by up
/// to `max_frame_bytes - HEADER_LEN` payload bytes.
pub const HEADER_LEN: usize = 76;

/// The most chunks one payload may be split into. Bounds `chunk_count` and the
/// per-payload reassembly slot vector.
pub const MAX_CHUNKS: usize = 4096;

// Header field offsets (big-endian). Kept as named constants so the golden-bytes
// test and the codec cannot drift apart.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_PAYLOAD_ID: usize = 5;
const OFF_PAYLOAD_LEN: usize = 37;
const OFF_CHUNK_INDEX: usize = 41;
const OFF_CHUNK_COUNT: usize = 43;
const OFF_CHUNK_LEN: usize = 45;
const OFF_CRC: usize = 47;
const OFF_RESERVED: usize = 51;
// OFF_RESERVED + 25 == HEADER_LEN (76).

/// An error chunking a payload or accepting a frame.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum FramingError {
    /// `max_frame_bytes` did not leave room for even one payload byte after the
    /// header (`max_frame_bytes <= HEADER_LEN`).
    #[error("max_frame_bytes {max_frame_bytes} does not exceed the {header}-byte header")]
    FrameTooSmall {
        /// The offending frame budget.
        max_frame_bytes: usize,
        /// [`HEADER_LEN`].
        header: usize,
    },
    /// Splitting the payload at this frame size would need more than [`MAX_CHUNKS`]
    /// chunks.
    #[error("payload needs {needed} chunks, over the {max} cap")]
    TooManyChunks {
        /// Chunks the payload would require.
        needed: usize,
        /// [`MAX_CHUNKS`].
        max: usize,
    },
    /// A payload length exceeded the reassembler's configured cap (or `u32`).
    #[error("payload is {found} bytes, over the {max}-byte cap")]
    PayloadTooLarge {
        /// The payload length seen.
        found: usize,
        /// The cap.
        max: usize,
    },
    /// The frame was shorter than the header, or shorter than the header's
    /// declared `chunk_len` payload.
    #[error("frame is {found} bytes, need at least {need}")]
    ShortFrame {
        /// Bytes present.
        found: usize,
        /// Bytes required.
        need: usize,
    },
    /// The frame did not begin with the [`MAGIC`] bytes — not a framing frame.
    #[error("frame does not carry the RRNF magic")]
    BadMagic,
    /// The header's version is not [`FRAMING_VERSION`].
    #[error("unsupported framing version {found}")]
    UnsupportedVersion {
        /// The version byte found.
        found: u8,
    },
    /// The chunk's CRC-32 did not match its payload — carrier corruption. The
    /// frame is rejected and nothing is stored.
    #[error("chunk CRC mismatch (carrier corruption)")]
    ChunkCrc,
    /// A header field was self-inconsistent, or inconsistent with an earlier frame
    /// for the same payload (a corrupted `chunk_count`/`payload_len`/`chunk_index`).
    #[error("inconsistent chunk header: {0}")]
    HeaderInconsistent(&'static str),
    /// A second, *different* chunk arrived for an already-filled index. The first
    /// is kept and this frame refused — a tamper/corruption tripwire.
    #[error("conflicting content for an already-seen chunk index")]
    ChunkConflict,
    /// All chunks arrived but the reassembled bytes did not hash to the claimed
    /// `payload_id`. The partial is discarded so a clean carriage can rebuild it.
    #[error("reassembled payload does not match its Blake3 id")]
    PayloadHashMismatch,
}

/// CRC-32 (IEEE 802.3 / zlib polynomial `0xEDB88320`) of `data`. Inlined — a
/// dozen lines — so this wire-format crate takes no CRC dependency.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The decoded fields of a chunk header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChunkHeader {
    payload_id: [u8; 32],
    payload_len: u32,
    chunk_index: u16,
    chunk_count: u16,
    chunk_len: u16,
    payload_crc32: u32,
}

impl ChunkHeader {
    /// Encodes the header to its fixed [`HEADER_LEN`] big-endian bytes.
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[OFF_MAGIC..OFF_VERSION].copy_from_slice(&MAGIC);
        buf[OFF_VERSION] = FRAMING_VERSION;
        buf[OFF_PAYLOAD_ID..OFF_PAYLOAD_LEN].copy_from_slice(&self.payload_id);
        buf[OFF_PAYLOAD_LEN..OFF_CHUNK_INDEX].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[OFF_CHUNK_INDEX..OFF_CHUNK_COUNT].copy_from_slice(&self.chunk_index.to_be_bytes());
        buf[OFF_CHUNK_COUNT..OFF_CHUNK_LEN].copy_from_slice(&self.chunk_count.to_be_bytes());
        buf[OFF_CHUNK_LEN..OFF_CRC].copy_from_slice(&self.chunk_len.to_be_bytes());
        buf[OFF_CRC..OFF_RESERVED].copy_from_slice(&self.payload_crc32.to_be_bytes());
        // reserved [OFF_RESERVED..HEADER_LEN] stays zero.
        buf
    }

    /// Decodes a header from the front of `frame`, validating magic and version.
    fn decode(frame: &[u8]) -> Result<ChunkHeader, FramingError> {
        if frame.len() < HEADER_LEN {
            return Err(FramingError::ShortFrame {
                found: frame.len(),
                need: HEADER_LEN,
            });
        }
        if frame[OFF_MAGIC..OFF_VERSION] != MAGIC {
            return Err(FramingError::BadMagic);
        }
        if frame[OFF_VERSION] != FRAMING_VERSION {
            return Err(FramingError::UnsupportedVersion {
                found: frame[OFF_VERSION],
            });
        }
        let payload_id: [u8; 32] = frame[OFF_PAYLOAD_ID..OFF_PAYLOAD_LEN]
            .try_into()
            .expect("32-byte slice");
        let u32_at =
            |o: usize| u32::from_be_bytes(frame[o..o + 4].try_into().expect("4-byte slice"));
        let u16_at =
            |o: usize| u16::from_be_bytes(frame[o..o + 2].try_into().expect("2-byte slice"));
        Ok(ChunkHeader {
            payload_id,
            payload_len: u32_at(OFF_PAYLOAD_LEN),
            chunk_index: u16_at(OFF_CHUNK_INDEX),
            chunk_count: u16_at(OFF_CHUNK_COUNT),
            chunk_len: u16_at(OFF_CHUNK_LEN),
            payload_crc32: u32_at(OFF_CRC),
        })
    }
}

/// Splits `payload` into frames sized for a carrier delivering at most
/// `max_frame_bytes` per frame.
///
/// Every frame is a [`HEADER_LEN`] header plus up to `max_frame_bytes -
/// HEADER_LEN` payload bytes; every chunk is that full size except the last. An
/// empty payload yields exactly one zero-length chunk. Refuses a `max_frame_bytes`
/// that leaves no room for payload ([`FramingError::FrameTooSmall`]) or a split
/// needing more than [`MAX_CHUNKS`] chunks ([`FramingError::TooManyChunks`]).
pub fn chunk(payload: &[u8], max_frame_bytes: usize) -> Result<Vec<Vec<u8>>, FramingError> {
    if max_frame_bytes <= HEADER_LEN {
        return Err(FramingError::FrameTooSmall {
            max_frame_bytes,
            header: HEADER_LEN,
        });
    }
    if payload.len() > u32::MAX as usize {
        return Err(FramingError::PayloadTooLarge {
            found: payload.len(),
            max: u32::MAX as usize,
        });
    }
    let cap = max_frame_bytes - HEADER_LEN; // ≥ 1
    let chunk_count = payload.len().div_ceil(cap).max(1);
    if chunk_count > MAX_CHUNKS {
        return Err(FramingError::TooManyChunks {
            needed: chunk_count,
            max: MAX_CHUNKS,
        });
    }
    let payload_id = Hash::of(payload).to_bytes();
    let payload_len = payload.len() as u32;
    let mut frames = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count {
        let start = index * cap;
        let end = (start + cap).min(payload.len());
        let body = &payload[start..end];
        let header = ChunkHeader {
            payload_id,
            payload_len,
            chunk_index: index as u16,
            chunk_count: chunk_count as u16,
            chunk_len: body.len() as u16,
            payload_crc32: crc32(body),
        };
        let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(body);
        frames.push(frame);
    }
    Ok(frames)
}

/// Tuning for a [`Reassembler`].
#[derive(Clone, Copy, Debug)]
pub struct ReassemblerConfig {
    /// Largest payload the reassembler will assemble; a frame claiming more is
    /// refused. Defaults to [`crate::bundle::MAX_BUNDLE_BYTES`] (4 MiB).
    pub max_payload_bytes: usize,
    /// Most payloads reassembled concurrently. Adding one beyond this evicts the
    /// oldest in-flight payload (bounding memory under a flood of new ids).
    pub max_inflight_payloads: usize,
    /// A partial payload untouched for this many seconds is pruned. Defaults to 7
    /// days — a courier may take a long time to carry every chunk.
    pub ttl_secs: i64,
}

impl Default for ReassemblerConfig {
    fn default() -> Self {
        Self {
            max_payload_bytes: crate::bundle::MAX_BUNDLE_BYTES,
            max_inflight_payloads: 64,
            ttl_secs: 7 * 24 * 60 * 60,
        }
    }
}

/// How many recently-completed payload ids to remember, so a late duplicate chunk
/// of an already-delivered payload is ignored instead of rebuilding it.
const RECENT_COMPLETED_CAP: usize = 1024;

/// One in-flight payload being reassembled.
struct Partial {
    payload_len: u32,
    chunk_count: u16,
    /// One slot per chunk index; `Some` once that chunk's bytes have arrived.
    chunks: Vec<Option<Vec<u8>>>,
    seen_count: usize,
    /// Admission-clock reading when the first chunk arrived (for TTL/LRU).
    first_seen_at: i64,
}

/// Reassembles chunked payloads (see the module docs). Order-independent,
/// duplicate-idempotent, and bounded in memory by its [`ReassemblerConfig`].
pub struct Reassembler {
    config: ReassemblerConfig,
    partials: std::collections::HashMap<[u8; 32], Partial>,
    recent_completed: RecentCompleted,
}

impl Reassembler {
    /// A reassembler with the given config.
    pub fn new(config: ReassemblerConfig) -> Self {
        Self {
            config,
            partials: std::collections::HashMap::new(),
            recent_completed: RecentCompleted::new(RECENT_COMPLETED_CAP),
        }
    }

    /// Feeds one received frame.
    ///
    /// Returns `Ok(Some(payload))` when this frame completes a payload whose CRC
    /// (per chunk) and Blake3 id (over the whole) both verify; `Ok(None)` when the
    /// payload is still incomplete, the frame was a duplicate, or it belonged to an
    /// already-completed payload. An `Err` describes why the frame was rejected —
    /// the reassembler's other state is untouched by a rejected frame, except that
    /// a [`FramingError::PayloadHashMismatch`] discards that payload's partial so a
    /// clean carriage can rebuild it.
    pub fn accept(&mut self, frame: &[u8], now: i64) -> Result<Option<Vec<u8>>, FramingError> {
        let header = ChunkHeader::decode(frame)?;
        let body_end = HEADER_LEN + header.chunk_len as usize;
        if frame.len() < body_end {
            return Err(FramingError::ShortFrame {
                found: frame.len(),
                need: body_end,
            });
        }
        let body = &frame[HEADER_LEN..body_end];
        // Cheap corruption guard first: a bad CRC means carrier damage; drop the
        // frame before it can touch reassembly state.
        if crc32(body) != header.payload_crc32 {
            return Err(FramingError::ChunkCrc);
        }
        // A late duplicate of a payload already delivered: ignore, do not rebuild.
        if self.recent_completed.contains(&header.payload_id) {
            return Ok(None);
        }
        // Structural validation of the (untrusted) header.
        let count = header.chunk_count as usize;
        if count == 0 || count > MAX_CHUNKS {
            return Err(FramingError::HeaderInconsistent("chunk_count out of range"));
        }
        if header.chunk_index as usize >= count {
            return Err(FramingError::HeaderInconsistent(
                "chunk_index >= chunk_count",
            ));
        }
        if header.payload_len as usize > self.config.max_payload_bytes {
            return Err(FramingError::PayloadTooLarge {
                found: header.payload_len as usize,
                max: self.config.max_payload_bytes,
            });
        }

        // Locate or create the partial, checking cross-frame consistency so a
        // corrupted chunk_count/payload_len cannot poison an in-flight payload.
        if let Some(existing) = self.partials.get(&header.payload_id) {
            if existing.chunk_count != header.chunk_count
                || existing.payload_len != header.payload_len
            {
                return Err(FramingError::HeaderInconsistent(
                    "chunk_count/payload_len differ from an earlier frame",
                ));
            }
        } else {
            // Bound memory: evict the oldest in-flight payload if at capacity.
            if self.partials.len() >= self.config.max_inflight_payloads {
                self.evict_oldest();
            }
            self.partials.insert(
                header.payload_id,
                Partial {
                    payload_len: header.payload_len,
                    chunk_count: header.chunk_count,
                    chunks: vec![None; count],
                    seen_count: 0,
                    first_seen_at: now,
                },
            );
        }
        let partial = self
            .partials
            .get_mut(&header.payload_id)
            .expect("partial just ensured");

        // Place the chunk. A byte-identical repeat is idempotent; a *different*
        // payload for a filled slot is a conflict (keep the first).
        let slot = &mut partial.chunks[header.chunk_index as usize];
        match slot {
            Some(existing) if existing.as_slice() == body => return Ok(None),
            Some(_) => return Err(FramingError::ChunkConflict),
            None => {
                *slot = Some(body.to_vec());
                partial.seen_count += 1;
            }
        }

        if partial.seen_count < count {
            return Ok(None);
        }

        // Complete: concatenate in index order and verify the authoritative hash.
        let mut assembled = Vec::with_capacity(partial.payload_len as usize);
        for chunk in &partial.chunks {
            assembled.extend_from_slice(chunk.as_deref().expect("all chunks present"));
        }
        if assembled.len() != partial.payload_len as usize
            || Hash::of(&assembled).to_bytes() != header.payload_id
        {
            // A chunk landed at the wrong index (its own CRC passed) or lengths do
            // not add up: discard so a clean carriage rebuilds it.
            self.partials.remove(&header.payload_id);
            return Err(FramingError::PayloadHashMismatch);
        }
        self.partials.remove(&header.payload_id);
        self.recent_completed.insert(header.payload_id);
        Ok(Some(assembled))
    }

    /// The chunk indexes still missing for an in-flight payload — the primitive a
    /// transport's retransmit-request uses. `None` if the payload is unknown or
    /// already completed.
    pub fn missing(&self, payload_id: &[u8; 32]) -> Option<Vec<u16>> {
        let partial = self.partials.get(payload_id)?;
        Some(
            partial
                .chunks
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.is_none().then_some(i as u16))
                .collect(),
        )
    }

    /// Prunes in-flight payloads: first any older than [`ReassemblerConfig::ttl_secs`],
    /// then, if still over [`ReassemblerConfig::max_inflight_payloads`], the oldest
    /// until within the cap. Returns the number evicted.
    pub fn prune(&mut self, now: i64) -> usize {
        let ttl = self.config.ttl_secs;
        let before = self.partials.len();
        if ttl > 0 {
            self.partials
                .retain(|_, p| now.saturating_sub(p.first_seen_at) < ttl);
        }
        while self.partials.len() > self.config.max_inflight_payloads {
            self.evict_oldest();
        }
        before - self.partials.len()
    }

    /// The number of payloads currently being reassembled (test/introspection).
    pub fn inflight(&self) -> usize {
        self.partials.len()
    }

    /// Removes the oldest-started in-flight payload (by `first_seen_at`). An O(n)
    /// scan, but `n` is bounded by `max_inflight_payloads` (default 64), so even a
    /// prune that must evict several is trivially cheap — no ordered index needed.
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .partials
            .iter()
            .min_by_key(|(_, p)| p.first_seen_at)
            .map(|(id, _)| *id)
        {
            self.partials.remove(&oldest);
        }
    }
}

/// A bounded, insertion-ordered set of recently-completed payload ids. Oldest is
/// evicted first once full — a fixed-memory guard against late-duplicate rebuilds.
struct RecentCompleted {
    cap: usize,
    order: std::collections::VecDeque<[u8; 32]>,
    set: std::collections::HashSet<[u8; 32]>,
}

impl RecentCompleted {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            order: std::collections::VecDeque::new(),
            set: std::collections::HashSet::new(),
        }
    }

    fn contains(&self, id: &[u8; 32]) -> bool {
        self.set.contains(id)
    }

    fn insert(&mut self, id: [u8; 32]) {
        if self.set.insert(id) {
            self.order.push_back(id);
            if self.order.len() > self.cap {
                if let Some(evicted) = self.order.pop_front() {
                    self.set.remove(&evicted);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact 76-byte header layout, pinned. A wire change to any field's
    /// offset or width breaks this — the mobile FFI (T2.4.2) decodes these bytes.
    #[test]
    fn header_golden_bytes() {
        let header = ChunkHeader {
            payload_id: [0xAB; 32],
            payload_len: 5,
            chunk_index: 1,
            chunk_count: 3,
            chunk_len: 2,
            payload_crc32: 0xDEAD_BEEF,
        };
        let expected = {
            let mut s = String::new();
            s.push_str("52524e46"); // "RRNF"
            s.push_str("01"); // version
            s.push_str(&"ab".repeat(32)); // payload_id
            s.push_str("00000005"); // payload_len = 5
            s.push_str("0001"); // chunk_index = 1
            s.push_str("0003"); // chunk_count = 3
            s.push_str("0002"); // chunk_len = 2
            s.push_str("deadbeef"); // crc32
            s.push_str(&"00".repeat(25)); // reserved [u8;25]
            s
        };
        assert_eq!(hex::encode(header.encode()), expected);
        assert_eq!(header.encode().len(), HEADER_LEN);
        // And it round-trips through decode.
        let mut frame = header.encode().to_vec();
        frame.extend_from_slice(&[0u8; 2]); // a 2-byte body to satisfy chunk_len
        assert_eq!(ChunkHeader::decode(&frame).unwrap(), header);
    }

    #[test]
    fn single_chunk_roundtrip() {
        let payload = b"hi".to_vec();
        let frames = chunk(&payload, 128).unwrap();
        assert_eq!(frames.len(), 1);
        // The header's payload_id is Blake3 of the payload.
        let h = ChunkHeader::decode(&frames[0]).unwrap();
        assert_eq!(h.payload_id, Hash::of(&payload).to_bytes());
        assert_eq!(h.chunk_count, 1);
        assert_eq!(h.payload_len, 2);

        let mut r = Reassembler::new(ReassemblerConfig::default());
        assert_eq!(r.accept(&frames[0], 0).unwrap(), Some(payload));
    }

    #[test]
    fn empty_payload_is_one_empty_chunk() {
        let frames = chunk(&[], 128).unwrap();
        assert_eq!(frames.len(), 1);
        let mut r = Reassembler::new(ReassemblerConfig::default());
        assert_eq!(r.accept(&frames[0], 0).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn multi_chunk_last_is_short() {
        // 10-byte payload, chunk capacity 4 → chunks of 4, 4, 2.
        let payload: Vec<u8> = (0..10).collect();
        let frames = chunk(&payload, HEADER_LEN + 4).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(ChunkHeader::decode(&frames[0]).unwrap().chunk_len, 4);
        assert_eq!(ChunkHeader::decode(&frames[2]).unwrap().chunk_len, 2);

        let mut r = Reassembler::new(ReassemblerConfig::default());
        assert_eq!(r.accept(&frames[0], 0).unwrap(), None);
        assert_eq!(r.accept(&frames[1], 0).unwrap(), None);
        assert_eq!(r.accept(&frames[2], 0).unwrap(), Some(payload));
    }

    #[test]
    fn frame_too_small_is_refused() {
        assert_eq!(
            chunk(b"x", HEADER_LEN),
            Err(FramingError::FrameTooSmall {
                max_frame_bytes: HEADER_LEN,
                header: HEADER_LEN,
            })
        );
    }

    #[test]
    fn oversize_chunk_count_is_refused() {
        // Capacity 1 byte/chunk, a payload just over MAX_CHUNKS bytes.
        let payload = vec![7u8; MAX_CHUNKS + 1];
        assert_eq!(
            chunk(&payload, HEADER_LEN + 1),
            Err(FramingError::TooManyChunks {
                needed: MAX_CHUNKS + 1,
                max: MAX_CHUNKS,
            })
        );
    }

    #[test]
    fn duplicate_chunk_is_idempotent_and_conflict_is_refused() {
        let payload: Vec<u8> = (0..8).collect();
        let frames = chunk(&payload, HEADER_LEN + 4).unwrap(); // two chunks
        let mut r = Reassembler::new(ReassemblerConfig::default());
        assert_eq!(r.accept(&frames[0], 0).unwrap(), None);
        // The same chunk again: idempotent, no completion.
        assert_eq!(r.accept(&frames[0], 0).unwrap(), None);

        // A frame at index 0 with different content: conflict, first kept.
        let mut forged = frames[0].clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        // Fix the CRC so we reach the conflict check, not the CRC check.
        let body = &forged[HEADER_LEN..];
        let crc = crc32(body);
        forged[OFF_CRC..OFF_RESERVED].copy_from_slice(&crc.to_be_bytes());
        assert_eq!(r.accept(&forged, 0), Err(FramingError::ChunkConflict));

        // The genuine second chunk still completes it.
        assert_eq!(r.accept(&frames[1], 0).unwrap(), Some(payload));
    }

    #[test]
    fn a_corrupted_chunk_payload_is_rejected_by_crc() {
        let frames = chunk(b"payload-bytes", 128).unwrap();
        let mut corrupt = frames[0].clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x01; // flip a payload byte, leave the CRC field alone
        let mut r = Reassembler::new(ReassemblerConfig::default());
        assert_eq!(r.accept(&corrupt, 0), Err(FramingError::ChunkCrc));
    }

    #[test]
    fn bad_magic_and_version_are_refused() {
        let mut frame = chunk(b"x", 128).unwrap().remove(0);
        let good = frame.clone();
        frame[0] = b'X';
        let mut r = Reassembler::new(ReassemblerConfig::default());
        assert_eq!(r.accept(&frame, 0), Err(FramingError::BadMagic));
        let mut ver = good;
        ver[OFF_VERSION] = 2;
        assert_eq!(
            r.accept(&ver, 0),
            Err(FramingError::UnsupportedVersion { found: 2 })
        );
    }

    #[test]
    fn missing_reports_exactly_the_absent_indexes() {
        let payload: Vec<u8> = (0..12).collect();
        let frames = chunk(&payload, HEADER_LEN + 4).unwrap(); // 3 chunks
        let id = Hash::of(&payload).to_bytes();
        let mut r = Reassembler::new(ReassemblerConfig::default());
        r.accept(&frames[1], 0).unwrap(); // deliver only the middle chunk
        assert_eq!(r.missing(&id), Some(vec![0, 2]));
        // Unknown payload → None.
        assert_eq!(r.missing(&[0u8; 32]), None);
        // Completed payload → None (delivered, nothing missing).
        r.accept(&frames[0], 0).unwrap();
        assert_eq!(r.accept(&frames[2], 0).unwrap(), Some(payload));
        assert_eq!(r.missing(&id), None);
    }

    #[test]
    fn ttl_prune_evicts_stale_partials() {
        let payload: Vec<u8> = (0..8).collect();
        let frames = chunk(&payload, HEADER_LEN + 4).unwrap();
        let cfg = ReassemblerConfig {
            ttl_secs: 100,
            ..ReassemblerConfig::default()
        };
        let mut r = Reassembler::new(cfg);
        r.accept(&frames[0], 1_000).unwrap();
        assert_eq!(r.inflight(), 1);
        // Before TTL: kept.
        assert_eq!(r.prune(1_099), 0);
        assert_eq!(r.inflight(), 1);
        // At/after TTL: evicted.
        assert_eq!(r.prune(1_100), 1);
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn inflight_cap_evicts_oldest() {
        // Cap of 2 in-flight payloads; start three distinct incomplete payloads.
        let cfg = ReassemblerConfig {
            max_inflight_payloads: 2,
            ..ReassemblerConfig::default()
        };
        let mut r = Reassembler::new(cfg);
        // Three distinct 2-chunk payloads, one chunk each (all incomplete).
        for (i, ts) in [10i64, 20, 30].into_iter().enumerate() {
            let payload: Vec<u8> = vec![i as u8; 8];
            let frames = chunk(&payload, HEADER_LEN + 4).unwrap();
            r.accept(&frames[0], ts).unwrap();
        }
        // Inserting the third evicted the oldest at insert time: never exceeds cap.
        assert_eq!(r.inflight(), 2);
        // The oldest (ts=10) is the one gone; a prune is a no-op now.
        assert_eq!(r.prune(31), 0);
    }

    #[test]
    fn a_late_duplicate_of_a_completed_payload_is_ignored() {
        let payload: Vec<u8> = (0..4).collect();
        let frames = chunk(&payload, 128).unwrap(); // single chunk
        let mut r = Reassembler::new(ReassemblerConfig::default());
        assert_eq!(r.accept(&frames[0], 0).unwrap(), Some(payload));
        // The same chunk arriving again does not rebuild — it is remembered done.
        assert_eq!(r.accept(&frames[0], 0).unwrap(), None);
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn a_misindexed_chunk_fails_the_hash_and_discards() {
        // Two 4-byte chunks. Forge the second frame's index to 0 (a header
        // corruption its own CRC cannot catch), so index 1 never fills and index 0
        // holds the wrong bytes → at completion the Blake3 fails.
        let payload: Vec<u8> = (0..8).collect();
        let frames = chunk(&payload, HEADER_LEN + 4).unwrap();
        let mut r = Reassembler::new(ReassemblerConfig::default());
        r.accept(&frames[0], 0).unwrap();
        // Re-point frame[1] to index 0 with different content → conflict (index 0
        // already filled), which keeps the first and refuses the frame.
        let mut mis = frames[1].clone();
        mis[OFF_CHUNK_INDEX..OFF_CHUNK_COUNT].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(r.accept(&mis, 0), Err(FramingError::ChunkConflict));

        // A cleaner mis-index case: a *fresh* payload where index 1's frame claims
        // index 0, so the real index-0 slot is filled with index-1 bytes and index
        // 1 is filled by the true index-1: hash mismatch at completion.
        let payload2: Vec<u8> = (100..108).collect();
        let f2 = chunk(&payload2, HEADER_LEN + 4).unwrap();
        let mut r2 = Reassembler::new(ReassemblerConfig::default());
        let mut swapped = f2[1].clone();
        swapped[OFF_CHUNK_INDEX..OFF_CHUNK_COUNT].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(r2.accept(&swapped, 0).unwrap(), None); // fills slot 0 wrongly
                                                           // The true index-1 frame fills slot 1; both slots now full → hash checked.
        assert_eq!(r2.accept(&f2[1], 0), Err(FramingError::PayloadHashMismatch));
        // The partial was discarded, so a clean carriage can rebuild.
        assert_eq!(r2.inflight(), 0);
    }
}
