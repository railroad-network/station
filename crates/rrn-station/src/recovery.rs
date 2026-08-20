//! Station key recovery — arming and reconstruction (T1.11.3, ADR-0016).
//!
//! **Arming** ([`setup`]): split the station's wallet secret across a set of
//! trusted holders with Shamir's secret sharing ([`rrn_identity::recovery`]),
//! sealing one shard to each holder's identity key, so any `threshold` of them
//! can later reconstruct the key even if the operator loses the passphrase. The
//! sealed shards are handed out as `rrnrecovery:` QR payloads — the exact format
//! the mobile holder-receive flow scans and stores — and the non-secret package
//! is persisted so a shard can be re-displayed for redelivery.
//!
//! **Reconstruction** ([`begin_restore`] / [`finish_restore`]): mint an
//! ephemeral recovery key, publish it in a `rrnrecover-req:` request, and
//! collect holders' `rrnrecover-resp:` responses (each a raw share re-sealed to
//! that key — see [`rrn_identity::recovery::ceremony`]). Once a threshold is
//! gathered the key is rebuilt and the station re-keyed under a new passphrase,
//! either in place (an intact data dir) or by reopening a backup archive.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine as _;

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_identity::recovery::ceremony::{self, RecoveryRequest};
use rrn_identity::recovery::flow::{reconstruct_wallet_for_address, RecoveryPackage};
use rrn_identity::wallet::WalletContents;

use crate::station::WALLET_FILE;

/// Filename of the persisted (non-secret) recovery package within the data dir.
pub const RECOVERY_FILE: &str = "recovery.rrnrecovery";

/// Scheme prefix marking a string as a recovery-shard payload. Must match the
/// mobile holder-receive flow (`recoveryShard.ts` `SHARD_QR_PREFIX`).
pub const SHARD_QR_PREFIX: &str = "rrnrecovery:";

/// Scheme prefix for a recovery *request* the operator shows holders.
pub const REQUEST_QR_PREFIX: &str = "rrnrecover-req:";

/// Scheme prefix for a holder's sealed *response*.
pub const RESPONSE_PREFIX: &str = "rrnrecover-resp:";

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .context("not valid base64")
}

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

/// An in-progress recovery: the ephemeral key holders seal their shares to, the
/// identity being recovered, and (for the total-loss path) the backup archive to
/// reopen. Held in memory for the life of one `station recovery restore` run and
/// discarded after — a captured set of responses is useless without it.
pub struct RestoreSession {
    recovery: Keypair,
    target: Address,
    from_backup: Option<PathBuf>,
}

impl RestoreSession {
    /// The identity this ceremony reconstructs.
    pub fn target(&self) -> &Address {
        &self.target
    }
}

/// Begins a recovery: works out which identity is being recovered (from the
/// persisted package for an in-place recovery, or from a backup archive's
/// clear-text envelope for a total-loss one), mints an ephemeral recovery key,
/// and returns the session plus the `rrnrecover-req:` request string to show
/// each holder as a QR.
pub fn begin_restore(
    data_dir: &Path,
    from_backup: Option<&Path>,
) -> Result<(RestoreSession, String)> {
    let target = match from_backup {
        Some(archive) => crate::backup::archive_address(archive)
            .context("read the station identity from the backup archive")?,
        None => load_package(data_dir)?.recovery_metadata.original_address,
    };
    let recovery = Keypair::generate();
    let request = RecoveryRequest {
        recovery_pubkey: recovery.public_key(),
        target_address: target,
    };
    let qr = format!("{REQUEST_QR_PREFIX}{}", b64_encode(&request.to_bytes()));
    Ok((
        RestoreSession {
            recovery,
            target,
            from_backup: from_backup.map(Path::to_path_buf),
        },
        qr,
    ))
}

/// Completes a recovery from a set of holders' `rrnrecover-resp:` responses:
/// opens each with the session's recovery secret, reconstructs the key (which
/// verifies against the target address, so too few or wrong responses fail),
/// and rewrites the station under `new_passphrase` — in place, or by reopening
/// the backup archive with the recovered key. Returns the restored address.
pub fn finish_restore(
    session: &RestoreSession,
    responses: &[String],
    new_passphrase: &str,
    data_dir: &Path,
    force: bool,
) -> Result<Address> {
    let mut shards = Vec::with_capacity(responses.len());
    for resp in responses {
        let body = resp
            .trim()
            .strip_prefix(RESPONSE_PREFIX)
            .with_context(|| format!("a response is not an {RESPONSE_PREFIX} string"))?;
        let bytes = b64_decode(body)?;
        let shard = ceremony::open_response(&bytes, session.recovery.secret_key())
            .context("open a holder response (wrong ceremony, or corrupt)")?;
        shards.push(shard);
    }

    let wallet = reconstruct_wallet_for_address(&shards, &session.target).context(
        "reconstruct the key — gather responses from more holders (need the threshold), \
         or a response did not belong to this recovery",
    )?;

    match &session.from_backup {
        Some(archive) => {
            // Restore the ledger and companion files from the archive using the
            // recovered key, then write a fresh wallet under the new passphrase.
            crate::backup::restore_with_secret(archive, data_dir, &wallet.secret_key, force)
                .context("restore the ledger from the backup")?;
        }
        None => {
            // In place: the data dir (and its cleartext DB) survive; only the
            // wallet was locked by the lost passphrase. Re-key it.
            if !force && !data_dir.join(WALLET_FILE).exists() {
                bail!(
                    "no wallet at {} to recover in place — pass --from-backup <archive> for a \
                     fresh machine, or --force",
                    data_dir.display()
                );
            }
        }
    }

    std::fs::create_dir_all(data_dir).ok();
    wallet
        .save_to_file(&data_dir.join(WALLET_FILE), new_passphrase)
        .context("write the recovered wallet under the new passphrase")?;
    Ok(wallet.address)
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

    // --- restore ceremony ---------------------------------------------------

    /// Given a request QR string and the setup shards, produce each listed
    /// holder's `rrnrecover-resp:` response string.
    fn holder_responses(
        request_qr: &str,
        shards: &[HolderShard],
        holders: &[(usize, &Keypair)],
    ) -> Vec<String> {
        let req_bytes = b64_decode(request_qr.strip_prefix(REQUEST_QR_PREFIX).unwrap()).unwrap();
        let request = RecoveryRequest::from_bytes(&req_bytes).unwrap();
        holders
            .iter()
            .map(|(i, kp)| {
                let stored =
                    b64_decode(shards[*i].qr_payload.strip_prefix(SHARD_QR_PREFIX).unwrap())
                        .unwrap();
                let resp = ceremony::build_response(&stored, kp.secret_key(), &request).unwrap();
                format!("{RESPONSE_PREFIX}{}", b64_encode(&resp))
            })
            .collect()
    }

    /// Arms a fresh station over `holders` and returns (data_dir, station addr,
    /// the shards handed out).
    fn arm(
        passphrase: &str,
        holders: &[Keypair],
    ) -> (tempfile::TempDir, Address, Vec<HolderShard>) {
        let dir = tempfile::tempdir().unwrap();
        let wallet = WalletContents::create_new();
        let addr = wallet.address;
        wallet
            .save_to_file(&dir.path().join(WALLET_FILE), passphrase)
            .unwrap();
        let addrs: Vec<String> = holders
            .iter()
            .map(|k| Address::from_public_key(k.public_key()).to_string())
            .collect();
        let shards = setup(dir.path(), passphrase, &addrs, 2).unwrap();
        (dir, addr, shards)
    }

    #[test]
    fn in_place_recovery_rekeys_the_wallet() {
        let holders = [
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        ];
        let (dir, station_addr, shards) = arm("old-pass", &holders);

        let (session, req_qr) = begin_restore(dir.path(), None).unwrap();
        assert_eq!(session.target(), &station_addr);

        // Two of the three holders respond.
        let responses = holder_responses(&req_qr, &shards, &[(0, &holders[0]), (2, &holders[2])]);
        let recovered =
            finish_restore(&session, &responses, "new-pass", dir.path(), false).unwrap();
        assert_eq!(recovered, station_addr);

        // The wallet now opens under the NEW passphrase, not the old.
        assert!(
            WalletContents::load_from_file(&dir.path().join(WALLET_FILE), "new-pass").is_ok(),
            "opens under the new passphrase"
        );
        assert!(WalletContents::load_from_file(&dir.path().join(WALLET_FILE), "old-pass").is_err());
    }

    #[test]
    fn from_backup_recovery_restores_ledger_and_rekeys() {
        let holders = [Keypair::generate(), Keypair::generate()];
        let (src, station_addr, shards) = arm("old-pass", &holders);
        // Give the source a database so the backup carries a ledger.
        rrn_storage::db::Database::open(&src.path().join(crate::station::DB_FILE)).unwrap();

        let archive = src.path().join("backup.rrnbak");
        crate::backup::create_backup(src.path(), "old-pass", &archive).unwrap();

        // Total loss: recover into a fresh, empty directory from the archive.
        let dest = tempfile::tempdir().unwrap();
        let (session, req_qr) = begin_restore(dest.path(), Some(&archive)).unwrap();
        assert_eq!(session.target(), &station_addr);

        let responses = holder_responses(&req_qr, &shards, &[(0, &holders[0]), (1, &holders[1])]);
        let recovered =
            finish_restore(&session, &responses, "new-pass", dest.path(), false).unwrap();
        assert_eq!(recovered, station_addr);

        // Ledger restored and wallet readable under the new passphrase.
        assert!(dest.path().join(crate::station::DB_FILE).exists());
        assert!(WalletContents::load_from_file(&dest.path().join(WALLET_FILE), "new-pass").is_ok());
    }

    #[test]
    fn too_few_responses_cannot_reconstruct() {
        let holders = [
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        ];
        let (dir, _addr, shards) = arm("old-pass", &holders);
        let (session, req_qr) = begin_restore(dir.path(), None).unwrap();
        // Only one response for a 2-of-3 split.
        let responses = holder_responses(&req_qr, &shards, &[(0, &holders[0])]);
        assert!(finish_restore(&session, &responses, "new-pass", dir.path(), false).is_err());
    }
}
