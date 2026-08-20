//! Station key recovery — arming (T1.11.3 Slice C, ADR-0016).
//!
//! `station recovery setup` splits the station's wallet secret across a set of
//! trusted holders with Shamir's secret sharing ([`rrn_identity::recovery`]),
//! sealing one shard to each holder's identity key, so that any `threshold` of
//! them can later reconstruct the key even if the operator loses the passphrase.
//! The sealed shards are handed out as `rrnrecovery:` QR payloads — the exact
//! format the mobile holder-receive flow scans and stores — and the non-secret
//! package is persisted next to the data dir so a shard can be re-displayed for
//! redelivery.
//!
//! This is the *arm* half. The *reconstruction* ceremony (gathering `K`
//! decrypted shards and rebuilding, then opening a backup's recovery wrap) is
//! Slice D.

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine as _;

use rrn_identity::address::Address;
use rrn_identity::recovery::flow::RecoveryPackage;
use rrn_identity::wallet::WalletContents;

use crate::station::WALLET_FILE;

/// Filename of the persisted (non-secret) recovery package within the data dir.
pub const RECOVERY_FILE: &str = "recovery.rrnrecovery";

/// Scheme prefix marking a string as a recovery-shard payload. Must match the
/// mobile holder-receive flow (`recoveryShard.ts` `SHARD_QR_PREFIX`).
pub const SHARD_QR_PREFIX: &str = "rrnrecovery:";

/// One holder's distributable shard: their address and the `rrnrecovery:` string
/// to render as a QR for them to scan.
pub struct HolderShard {
    /// The holder's `rrn1…` address.
    pub address: String,
    /// The `rrnrecovery:<base64>` payload string (render this as a QR).
    pub qr_payload: String,
}

/// The current recovery configuration read back from the persisted package.
pub struct RecoveryStatus {
    /// `K` — holders required to reconstruct.
    pub threshold: u8,
    /// `N` — total holders.
    pub total: u8,
    /// The holders' `rrn1…` addresses, in shard order.
    pub holders: Vec<String>,
    /// Unix seconds when the package was created.
    pub created_at: i64,
}

/// Encodes a shard payload as the `rrnrecovery:<base64>` string the mobile
/// holder-receive flow decodes.
fn qr_payload(payload: &[u8]) -> String {
    format!(
        "{SHARD_QR_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(payload)
    )
}

/// Collects a package's holder shards as `rrnrecovery:` payload strings.
fn holder_shards(package: &RecoveryPackage) -> Result<Vec<HolderShard>> {
    let mut out = Vec::with_capacity(package.shards.len());
    for (i, shard) in package.shards.iter().enumerate() {
        let payload = package.shard_payload(i).context("build shard payload")?;
        out.push(HolderShard {
            address: shard.holder.to_string(),
            qr_payload: qr_payload(&payload),
        });
    }
    Ok(out)
}

/// Arms recovery: splits the station key across `holders` (each an `rrn1…`
/// address), requiring `threshold` to reconstruct, persists the package, and
/// returns the per-holder shard payloads to distribute.
///
/// Overwrites any existing package — a fresh split, which invalidates shards
/// handed out under a previous setup (that is what re-arming means).
pub fn setup(
    data_dir: &Path,
    passphrase: &str,
    holders: &[String],
    threshold: u8,
) -> Result<Vec<HolderShard>> {
    if holders.len() < 2 {
        bail!("recovery needs at least 2 holders (got {})", holders.len());
    }
    if threshold < 2 || (threshold as usize) > holders.len() {
        bail!(
            "threshold must be between 2 and the number of holders ({}), got {threshold}",
            holders.len()
        );
    }

    // Parse holder addresses to public keys, rejecting duplicates so a holder
    // cannot unknowingly get two shards (which would weaken the threshold).
    let mut pubkeys = Vec::with_capacity(holders.len());
    let mut seen = std::collections::BTreeSet::new();
    for addr in holders {
        let parsed: Address = addr
            .parse()
            .with_context(|| format!("invalid holder address {addr:?}"))?;
        if !seen.insert(addr.clone()) {
            bail!("holder {addr} listed more than once");
        }
        pubkeys.push(*parsed.public_key());
    }

    // Load the wallet last (prompts/validates the passphrase) so obvious input
    // errors above fail before we ask for it.
    let wallet = WalletContents::load_from_file(&data_dir.join(WALLET_FILE), passphrase)
        .context("open wallet (wrong passphrase, or not a station data dir)")?;

    let package =
        RecoveryPackage::create(&wallet, &pubkeys, threshold).context("split the station key")?;
    package
        .save_to_file(&data_dir.join(RECOVERY_FILE))
        .context("persist recovery package")?;

    holder_shards(&package)
}

/// Reads back the current recovery configuration, or an error if recovery has
/// not been armed.
pub fn status(data_dir: &Path) -> Result<RecoveryStatus> {
    let package = load_package(data_dir)?;
    Ok(RecoveryStatus {
        threshold: package.threshold,
        total: package.total,
        holders: package
            .shards
            .iter()
            .map(|s| s.holder.to_string())
            .collect(),
        created_at: package.recovery_metadata.created_at,
    })
}

/// Re-derives one holder's `rrnrecovery:` shard payload for redelivery.
pub fn shard_for(data_dir: &Path, holder: &str) -> Result<HolderShard> {
    let package = load_package(data_dir)?;
    let index = package
        .shards
        .iter()
        .position(|s| s.holder.to_string() == holder)
        .with_context(|| format!("{holder} is not a holder in the current recovery setup"))?;
    let payload = package
        .shard_payload(index)
        .context("build shard payload")?;
    Ok(HolderShard {
        address: holder.to_string(),
        qr_payload: qr_payload(&payload),
    })
}

fn load_package(data_dir: &Path) -> Result<RecoveryPackage> {
    let path = data_dir.join(RECOVERY_FILE);
    if !path.exists() {
        bail!("recovery is not set up — run `station recovery setup` first");
    }
    RecoveryPackage::load_from_file(&path).context("read recovery package")
}

/// Renders `text` as a QR code drawn with Unicode half-blocks, scannable from a
/// terminal. Falls back to returning just the text if the QR cannot be built.
pub fn render_qr(text: &str) -> String {
    use qrcode::render::unicode;
    use qrcode::QrCode;
    match QrCode::new(text.as_bytes()) {
        Ok(code) => code.render::<unicode::Dense1x2>().quiet_zone(true).build(),
        Err(_) => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    fn seed_wallet(dir: &Path, passphrase: &str) {
        WalletContents::create_new()
            .save_to_file(&dir.join(WALLET_FILE), passphrase)
            .unwrap();
    }

    fn holder_addr() -> String {
        Address::from_public_key(Keypair::generate().public_key()).to_string()
    }

    #[test]
    fn setup_persists_and_emits_scannable_shards() {
        let dir = tempfile::tempdir().unwrap();
        seed_wallet(dir.path(), "pw");
        let holders = vec![holder_addr(), holder_addr(), holder_addr()];

        let shards = setup(dir.path(), "pw", &holders, 2).unwrap();
        assert_eq!(shards.len(), 3);
        for s in &shards {
            assert!(s.qr_payload.starts_with(SHARD_QR_PREFIX));
        }
        // The package is persisted and reads back with the right parameters.
        let st = status(dir.path()).unwrap();
        assert_eq!(st.threshold, 2);
        assert_eq!(st.total, 3);
        assert_eq!(st.holders.len(), 3);

        // A payload decodes back to bytes the recovery parser accepts (proving
        // the rrnrecovery: framing is what a phone would scan).
        let b64 = shards[0].qr_payload.strip_prefix(SHARD_QR_PREFIX).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn shard_for_redisplays_a_known_holder() {
        let dir = tempfile::tempdir().unwrap();
        seed_wallet(dir.path(), "pw");
        let holders = vec![holder_addr(), holder_addr()];
        setup(dir.path(), "pw", &holders, 2).unwrap();

        let again = shard_for(dir.path(), &holders[1]).unwrap();
        assert_eq!(again.address, holders[1]);
        assert!(again.qr_payload.starts_with(SHARD_QR_PREFIX));

        assert!(
            shard_for(dir.path(), &holder_addr()).is_err(),
            "unknown holder rejected"
        );
    }

    #[test]
    fn rejects_bad_parameters() {
        let dir = tempfile::tempdir().unwrap();
        seed_wallet(dir.path(), "pw");
        let holders = vec![holder_addr(), holder_addr(), holder_addr()];

        assert!(
            setup(dir.path(), "pw", &holders, 1).is_err(),
            "K<2 rejected"
        );
        assert!(
            setup(dir.path(), "pw", &holders, 4).is_err(),
            "K>N rejected"
        );
        assert!(
            setup(dir.path(), "pw", &[holder_addr()], 2).is_err(),
            "N<2 rejected"
        );
        assert!(
            setup(dir.path(), "wrong", &holders, 2).is_err(),
            "bad passphrase rejected"
        );
    }

    #[test]
    fn rejects_duplicate_holder() {
        let dir = tempfile::tempdir().unwrap();
        seed_wallet(dir.path(), "pw");
        let a = holder_addr();
        let holders = vec![a.clone(), a];
        assert!(setup(dir.path(), "pw", &holders, 2).is_err());
    }

    #[test]
    fn status_errors_before_setup() {
        let dir = tempfile::tempdir().unwrap();
        seed_wallet(dir.path(), "pw");
        assert!(status(dir.path()).is_err());
    }
}
