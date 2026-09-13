//! The Volume Master Key (VMK) and its member-held custody (ADR-0024).
//!
//! The encrypted container is unlocked by a random 32-byte VMK that is **never
//! persisted in the clear anywhere**. Custody reuses ADR-0016's machinery
//! wholesale: the VMK is generated as an ed25519 seed, Shamir-split among `N`
//! member holders at threshold `K` with [`RecoveryPackage::create`], each shard
//! sealed to a holder's identity key and handed out as the identical
//! `rrnrecovery:` payload members already use for wallet and station-key shards
//! (the "seed-reuse with a labelling caveat" path the ADR ratified). This module
//! adds no new signed record kind and no CBOR wire fixture.
//!
//! What lives where:
//! - the full [`RecoveryPackage`] (with holder identities) is persisted **inside
//!   the container** (needed post-unlock for status/redelivery/refresh);
//! - only a tiny [`VmkDescriptor`] — the VMK's derived address and `K`/`N`, and
//!   nothing else — lives on the unencrypted boot dir, because it is all
//!   [`begin_unlock`] needs and it deliberately does not name the holders (a
//!   coercion-target map a seizer must not get from an imaged card).
//!
//! The boot ceremony is **wallet-free**: no station keypair exists pre-unlock, so
//! the authenticated mobile channel cannot run. The station mints an ephemeral key,
//! shows a **console fingerprint** holders confirm out-of-band (the fingerprint,
//! not the unsigned request, is the authenticator), collects sealed
//! `rrnrecover-resp:` shares, and reconstructs the VMK in memory — verified against
//! the descriptor's address, so wrong or insufficient shards fail loudly.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use zeroize::Zeroizing;

use dcbor::prelude::*;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_identity::address::Address;
use rrn_identity::recovery::ceremony::{self, RecoveryRequest};
use rrn_identity::recovery::flow::{reconstruct_wallet_for_address, RecoveryPackage};
use rrn_identity::recovery::shamir::RawShard;
use rrn_identity::wallet::WalletContents;

use crate::recovery::{HolderShard, REQUEST_QR_PREFIX, RESPONSE_PREFIX, SHARD_QR_PREFIX};

/// A reconstructed (or freshly generated) Volume Master Key.
///
/// Held as a [`SecretKey`], which is `ZeroizeOnDrop` and redacts itself in `Debug`
/// — so the VMK is wiped when this value drops and never lands in a log line. The
/// raw bytes leave this type only through [`key_bytes`](Vmk::key_bytes), into a
/// [`Zeroizing`] buffer the caller hands to the kernel mount helper by file
/// descriptor and drops immediately.
pub struct Vmk(SecretKey);

impl Vmk {
    /// Generates a fresh random VMK (a 32-byte ed25519 seed).
    pub fn generate() -> Self {
        Vmk(Keypair::generate().secret_key().clone())
    }

    /// The VMK's derived `rrn1…` address — the integrity tag recorded in the
    /// descriptor and the recovery package, and checked at reconstruction.
    pub fn address(&self) -> Address {
        Address::from_public_key(Keypair::from_secret(self.0.clone()).public_key())
    }

    /// The raw 32-byte volume key, in a zeroizing buffer. The caller passes it to
    /// the mount helper by fd and drops it; it is wiped on drop.
    pub fn key_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Wraps the VMK seed as a [`WalletContents`] so the ADR-0016 split/reconstruct
    /// path can be reused unchanged. `created_at` is irrelevant — `create` stamps
    /// its own — and the metadata is empty.
    fn as_wallet(&self) -> WalletContents {
        WalletContents {
            secret_key: self.0.clone(),
            address: self.address(),
            created_at: 0,
            metadata: std::collections::BTreeMap::new(),
        }
    }
}

/// The unencrypted boot-dir descriptor: everything a locked node needs to *begin*
/// an unlock ceremony, and nothing more.
///
/// It carries the VMK's derived address (so [`begin_unlock`] can build the recovery
/// request and reconstruction can verify) and `K`/`N` (so the console can tell the
/// operator how many holders to gather). It deliberately **omits the holder set** —
/// serialising holder addresses here would hand a seizer a coercion-target map from
/// an imaged card (ADR-0024).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmkDescriptor {
    /// The VMK's derived `rrn1…` address.
    pub vmk_address: Address,
    /// `K` — holders required to reconstruct.
    pub threshold: u8,
    /// `N` — total holders.
    pub total: u8,
}

impl VmkDescriptor {
    /// Canonical CBOR bytes: `{ "addr": <32 pubkey bytes>, "k": K, "n": N }`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert(
            "addr",
            CBOR::to_byte_string(self.vmk_address.public_key().to_bytes()),
        );
        m.insert("k", self.threshold);
        m.insert("n", self.total);
        to_canonical_bytes(CBOR::from(m))
    }

    /// Parses canonical descriptor bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let cbor: CBOR = from_canonical_bytes(bytes).context("parse VMK descriptor CBOR")?;
        let map = match cbor.into_case() {
            CBORCase::Map(m) => m,
            _ => bail!("VMK descriptor is not a CBOR map"),
        };
        let addr_bytes = map
            .extract::<&str, CBOR>("addr")
            .context("descriptor missing \"addr\"")?
            .try_into_byte_string()
            .context("descriptor \"addr\" not a byte string")?
            .as_slice()
            .to_vec();
        let arr: [u8; 32] = addr_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("descriptor address is not 32 bytes"))?;
        let public = PublicKey::from_bytes(arr)
            .map_err(|e| anyhow::anyhow!("descriptor carried an invalid VMK key: {e}"))?;
        let threshold = map
            .extract::<&str, u8>("k")
            .context("descriptor missing \"k\"")?;
        let total = map
            .extract::<&str, u8>("n")
            .context("descriptor missing \"n\"")?;
        Ok(VmkDescriptor {
            vmk_address: Address::from_public_key(public),
            threshold,
            total,
        })
    }

    /// Writes the descriptor to `path` (plain — it is non-secret).
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_canonical_bytes())
            .with_context(|| format!("write VMK descriptor to {}", path.display()))
    }

    /// Reads a descriptor back from `path`.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read VMK descriptor at {}", path.display()))?;
        Self::from_canonical_bytes(&bytes)
    }
}

/// Validates a holder set and threshold the way [`crate::recovery::setup`] does,
/// returning the parsed holder public keys in order. Rejects fewer than 2 holders,
/// `K` outside `2..=N`, and duplicate holders (a holder must not hold two shards,
/// which would silently weaken the threshold).
fn parse_holders(holders: &[String], threshold: u8) -> Result<Vec<PublicKey>> {
    if holders.len() < 2 {
        bail!("the VMK needs at least 2 holders (got {})", holders.len());
    }
    if threshold < 2 || (threshold as usize) > holders.len() {
        bail!(
            "threshold must be between 2 and the number of holders ({}), got {threshold}",
            holders.len()
        );
    }
    let mut pubkeys = Vec::with_capacity(holders.len());
    let mut seen = BTreeSet::new();
    for addr in holders {
        let parsed: Address = addr
            .parse()
            .with_context(|| format!("invalid holder address {addr:?}"))?;
        if !seen.insert(addr.clone()) {
            bail!("holder {addr} listed more than once");
        }
        pubkeys.push(*parsed.public_key());
    }
    Ok(pubkeys)
}

/// Encodes a raw shard payload as the `rrnrecovery:<base64>` string a holder's
/// phone scans (identical framing to a wallet/station-key shard).
fn shard_qr(payload: &[u8]) -> String {
    format!(
        "{SHARD_QR_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(payload)
    )
}

/// Splits `vmk` among `holders` at threshold `K`, returning the recovery package
/// (persist it inside the container), the boot-dir [`VmkDescriptor`], and the
/// per-holder `rrnrecovery:` shard payloads to hand out.
pub fn arm(
    vmk: &Vmk,
    holders: &[String],
    threshold: u8,
) -> Result<(RecoveryPackage, VmkDescriptor, Vec<HolderShard>)> {
    let pubkeys = parse_holders(holders, threshold)?;
    let package = RecoveryPackage::create(&vmk.as_wallet(), &pubkeys, threshold)
        .context("split the volume master key")?;
    let descriptor = VmkDescriptor {
        vmk_address: vmk.address(),
        threshold: package.threshold,
        total: package.total,
    };
    let shards = holder_shards(&package)?;
    Ok((package, descriptor, shards))
}

/// Re-splits the **same** VMK to a (possibly changed) holder set, revoking the old
/// shards — ADR-0016 `RecoveryPackage::refresh`. Needs the VMK in userspace, so it
/// runs inside an unlock (or is itself a quorum ceremony), never in the background.
pub fn refresh(
    vmk: &Vmk,
    package: &RecoveryPackage,
    new_holders: &[String],
    new_threshold: u8,
) -> Result<(RecoveryPackage, VmkDescriptor, Vec<HolderShard>)> {
    let pubkeys = parse_holders(new_holders, new_threshold)?;
    let refreshed = package
        .refresh(&vmk.as_wallet(), &pubkeys, new_threshold)
        .context("re-split the volume master key to the new holder set")?;
    let descriptor = VmkDescriptor {
        vmk_address: vmk.address(),
        threshold: refreshed.threshold,
        total: refreshed.total,
    };
    let shards = holder_shards(&refreshed)?;
    Ok((refreshed, descriptor, shards))
}

/// Collects a package's holder shards as `rrnrecovery:` payload strings.
fn holder_shards(package: &RecoveryPackage) -> Result<Vec<HolderShard>> {
    let mut out = Vec::with_capacity(package.shards.len());
    for (i, shard) in package.shards.iter().enumerate() {
        let payload = package.shard_payload(i).context("build shard payload")?;
        out.push(HolderShard {
            address: shard.holder.to_string(),
            qr_payload: shard_qr(&payload),
        });
    }
    Ok(out)
}

/// An in-progress boot ceremony: the ephemeral key holders seal their shares to,
/// and the VMK address being reconstructed. Held in memory for one `station unlock`
/// run and discarded after — a captured set of responses is useless without it.
pub struct UnlockSession {
    recovery: Keypair,
    vmk_address: Address,
}

impl UnlockSession {
    /// The VMK address this ceremony reconstructs.
    pub fn vmk_address(&self) -> &Address {
        &self.vmk_address
    }
}

/// Begins a boot ceremony from the boot-dir descriptor: mints an ephemeral recovery
/// key and returns the session, the `rrnrecover-req:` request string to show
/// holders as a QR, and the **console fingerprint** the operator reads aloud so
/// holders can confirm they are responding to *this* station and not a seizer who
/// imaged the descriptor and minted their own ephemeral key.
pub fn begin_unlock(descriptor: &VmkDescriptor) -> (UnlockSession, String, String) {
    let recovery = Keypair::generate();
    let request = RecoveryRequest {
        recovery_pubkey: recovery.public_key(),
        target_address: descriptor.vmk_address,
    };
    let qr = format!(
        "{REQUEST_QR_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(request.to_bytes())
    );
    let fingerprint = ceremony_fingerprint(&recovery.public_key(), &descriptor.vmk_address);
    (
        UnlockSession {
            recovery,
            vmk_address: descriptor.vmk_address,
        },
        qr,
        fingerprint,
    )
}

/// Completes a boot ceremony from a set of holders' `rrnrecover-resp:` responses:
/// opens each with the session's ephemeral secret, reconstructs the VMK (verified
/// against the session's VMK address, so too few or wrong responses fail loudly),
/// and returns it. Nothing is written to disk.
pub fn finish_unlock(session: &UnlockSession, responses: &[String]) -> Result<Vmk> {
    let mut shards: Vec<RawShard> = Vec::with_capacity(responses.len());
    for resp in responses {
        let body = resp
            .trim()
            .strip_prefix(RESPONSE_PREFIX)
            .with_context(|| format!("a response is not an {RESPONSE_PREFIX} string"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .context("a response is not valid base64")?;
        let shard = ceremony::open_response(&bytes, session.recovery.secret_key())
            .context("open a holder response (wrong ceremony, or corrupt)")?;
        shards.push(shard);
    }

    let wallet = reconstruct_wallet_for_address(&shards, &session.vmk_address).context(
        "reconstruct the volume key — gather responses from more holders (need the threshold), \
         or a response did not belong to this ceremony",
    )?;
    Ok(Vmk(wallet.secret_key.clone()))
}

/// A short, human-comparable fingerprint of a ceremony, derived from the ephemeral
/// recovery public key and the VMK address. Two groups of five base32 characters
/// (`ABCDE-FGHIJ`) — enough to distinguish this ceremony from a seizer's forged one
/// when a holder confirms it out-of-band against the operator's console.
pub fn ceremony_fingerprint(recovery_pubkey: &PublicKey, vmk_address: &Address) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(&recovery_pubkey.to_bytes());
    input.extend_from_slice(&vmk_address.public_key().to_bytes());
    let digest = Hash::of(&input).to_bytes();
    let chars: String = digest
        .iter()
        .take(10)
        .map(|b| ALPHABET[(*b % 32) as usize] as char)
        .collect();
    format!("{}-{}", &chars[..5], &chars[5..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds `n` holder keypairs and their addresses.
    fn holders(n: usize) -> (Vec<Keypair>, Vec<String>) {
        let kps: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        let addrs = kps
            .iter()
            .map(|k| Address::from_public_key(k.public_key()).to_string())
            .collect();
        (kps, addrs)
    }

    /// Produce each listed holder's `rrnrecover-resp:` response for a request QR.
    fn responses_for(
        request_qr: &str,
        shards: &[HolderShard],
        who: &[(usize, &Keypair)],
    ) -> Vec<String> {
        let req_body = request_qr.strip_prefix(REQUEST_QR_PREFIX).unwrap();
        let req_bytes = base64::engine::general_purpose::STANDARD
            .decode(req_body)
            .unwrap();
        let request = RecoveryRequest::from_bytes(&req_bytes).unwrap();
        who.iter()
            .map(|(i, kp)| {
                let stored = base64::engine::general_purpose::STANDARD
                    .decode(shards[*i].qr_payload.strip_prefix(SHARD_QR_PREFIX).unwrap())
                    .unwrap();
                let resp = ceremony::build_response(&stored, kp.secret_key(), &request).unwrap();
                format!(
                    "{RESPONSE_PREFIX}{}",
                    base64::engine::general_purpose::STANDARD.encode(resp)
                )
            })
            .collect()
    }

    #[test]
    fn k_holders_reconstruct_the_exact_vmk() {
        let vmk = Vmk::generate();
        let want = vmk.key_bytes();
        let (kps, addrs) = holders(5);
        let (_pkg, descriptor, shards) = arm(&vmk, &addrs, 3).unwrap();
        assert_eq!(descriptor.threshold, 3);
        assert_eq!(descriptor.total, 5);
        assert_eq!(descriptor.vmk_address, vmk.address());

        let (session, req_qr, _fp) = begin_unlock(&descriptor);
        // Three of five holders respond.
        let resp = responses_for(
            &req_qr,
            &shards,
            &[(0, &kps[0]), (2, &kps[2]), (4, &kps[4])],
        );
        let recovered = finish_unlock(&session, &resp).unwrap();
        assert_eq!(&*recovered.key_bytes(), &*want, "VMK reconstructed exactly");
    }

    #[test]
    fn k_minus_one_holders_fail_to_unlock() {
        let vmk = Vmk::generate();
        let (kps, addrs) = holders(5);
        let (_pkg, descriptor, shards) = arm(&vmk, &addrs, 3).unwrap();
        let (session, req_qr, _fp) = begin_unlock(&descriptor);
        // Only two of the three required respond — must fail, no partial key.
        let resp = responses_for(&req_qr, &shards, &[(0, &kps[0]), (1, &kps[1])]);
        assert!(
            finish_unlock(&session, &resp).is_err(),
            "K-1 shares must not reconstruct"
        );
    }

    #[test]
    fn responses_from_a_different_ceremony_are_rejected() {
        // Responses are sealed to a specific ephemeral key. Shares gathered for one
        // ceremony cannot be replayed into another session's unlock — the ephemeral
        // secret differs, so open_response fails before reconstruction is reached.
        let vmk = Vmk::generate();
        let (kps, addrs) = holders(3);
        let (_pkg, descriptor, shards) = arm(&vmk, &addrs, 2).unwrap();

        let (_session_a, req_a, _fp_a) = begin_unlock(&descriptor);
        let (session_b, _req_b, _fp_b) = begin_unlock(&descriptor);
        // Holders respond to ceremony A's request…
        let resp_a = responses_for(&req_a, &shards, &[(0, &kps[0]), (1, &kps[1])]);
        // …but we try to finish ceremony B with them.
        assert!(
            finish_unlock(&session_b, &resp_a).is_err(),
            "cross-ceremony responses must not unlock"
        );
    }

    #[test]
    fn descriptor_never_carries_the_holder_set() {
        // The boot-dir descriptor must disclose only the VMK address and K/N — a
        // seizer who images the card must not learn who the holders are.
        let vmk = Vmk::generate();
        let (kps, addrs) = holders(4);
        let (_pkg, descriptor, _shards) = arm(&vmk, &addrs, 2).unwrap();
        let bytes = descriptor.to_canonical_bytes();

        for (kp, addr) in kps.iter().zip(&addrs) {
            let pk = kp.public_key().to_bytes();
            assert!(
                !contains_subslice(&bytes, &pk),
                "descriptor leaks holder pubkey bytes"
            );
            assert!(
                !bytes.windows(addr.len()).any(|w| w == addr.as_bytes()),
                "descriptor leaks holder address string"
            );
        }
        // Round-trips, and carries exactly the three intended fields.
        let back = VmkDescriptor::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, descriptor);
        assert_eq!(back.vmk_address, vmk.address());
    }

    #[test]
    fn descriptor_round_trips_through_a_file() {
        let vmk = Vmk::generate();
        let (_kps, addrs) = holders(3);
        let (_pkg, descriptor, _shards) = arm(&vmk, &addrs, 2).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vmk.descriptor");
        descriptor.save_to_file(&path).unwrap();
        let back = VmkDescriptor::load_from_file(&path).unwrap();
        assert_eq!(back, descriptor);
    }

    #[test]
    fn arm_rejects_bad_parameters() {
        let vmk = Vmk::generate();
        let (_kps, addrs) = holders(3);
        assert!(arm(&vmk, &addrs, 1).is_err(), "K<2 rejected");
        assert!(arm(&vmk, &addrs, 4).is_err(), "K>N rejected");
        let (_kps1, one) = holders(1);
        assert!(arm(&vmk, &one, 2).is_err(), "N<2 rejected");
        let (_kps2, addrs2) = holders(3);
        let dup = vec![addrs2[0].clone(), addrs2[0].clone(), addrs2[1].clone()];
        assert!(arm(&vmk, &dup, 2).is_err(), "duplicate holder rejected");
    }

    #[test]
    fn refresh_keeps_the_same_vmk_new_holders() {
        let vmk = Vmk::generate();
        let want = vmk.key_bytes();
        let (_kps, addrs) = holders(3);
        let (pkg, _desc, _shards) = arm(&vmk, &addrs, 2).unwrap();

        // Refresh to a fresh holder set at a new threshold.
        let (kps2, addrs2) = holders(5);
        let (_pkg2, desc2, shards2) = refresh(&vmk, &pkg, &addrs2, 3).unwrap();
        assert_eq!(desc2.vmk_address, vmk.address(), "same VMK after refresh");
        assert_eq!(desc2.threshold, 3);
        assert_eq!(desc2.total, 5);

        // The refreshed shards reconstruct the same VMK.
        let (session, req_qr, _fp) = begin_unlock(&desc2);
        let resp = responses_for(
            &req_qr,
            &shards2,
            &[(0, &kps2[0]), (1, &kps2[1]), (2, &kps2[2])],
        );
        let recovered = finish_unlock(&session, &resp).unwrap();
        assert_eq!(&*recovered.key_bytes(), &*want);
    }

    #[test]
    fn fingerprint_is_deterministic_and_binds_both_inputs() {
        let vmk = Vmk::generate();
        let eph = Keypair::generate();
        let fp1 = ceremony_fingerprint(&eph.public_key(), &vmk.address());
        let fp2 = ceremony_fingerprint(&eph.public_key(), &vmk.address());
        assert_eq!(fp1, fp2, "deterministic");
        assert_eq!(fp1.len(), 11, "AAAAA-BBBBB shape");
        // A different ephemeral key (a seizer's forged ceremony) yields a
        // different fingerprint holders would catch.
        let other = Keypair::generate();
        assert_ne!(
            fp1,
            ceremony_fingerprint(&other.public_key(), &vmk.address())
        );
    }

    #[test]
    fn vmk_debug_is_redacted() {
        // The VMK's Debug (via SecretKey) must not print key bytes into a log.
        let vmk = Vmk::generate();
        let shown = format!("{:?}", vmk.0);
        assert!(
            shown.contains("REDACTED"),
            "secret must be redacted: {shown}"
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
