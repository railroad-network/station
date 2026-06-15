//! The identity wallet: one secret key plus metadata, encrypted at rest under
//! a passphrase.
//!
//! A wallet holds a single identity (one keypair) for Phase 0. On disk it is a
//! `.rrnwallet` file: the canonical-CBOR encoding of an [`EncryptedWallet`],
//! whose ciphertext is the wallet's secret material sealed with
//! XChaCha20-Poly1305 under a key derived from the user's passphrase via
//! argon2id. Lose the file *and* there is no social recovery (M0.4) → the
//! identity is gone; that is by design.
//!
//! # The encryption scheme
//!
//! ```text
//! key        = argon2id(passphrase, salt, {m_cost, t_cost, p_cost})   // 32 bytes
//! ciphertext = XChaCha20Poly1305(key, nonce).encrypt(canonical_cbor(secret_fields))
//! ```
//!
//! XChaCha20-Poly1305's 24-byte nonce is large enough that a random nonce per
//! encryption is safe. A wrong passphrase derives the wrong key, the Poly1305
//! tag fails, and [`EncryptedWallet::decrypt`] returns
//! [`WalletError::Decrypt`] — it never returns garbage plaintext.
//!
//! # What is in the ciphertext
//!
//! Only the secret-bearing fields are sealed: the 32-byte secret-key seed,
//! `created_at`, and `metadata`. The [`Address`] is *not* stored — it is
//! re-derived from the secret key on decrypt, so a tampered address can never
//! disagree with the key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use dcbor::prelude::*;
use rand_core::{OsRng, RngCore};
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::address::Address;

/// Current wallet file-format version. Bumping this is how the KDF parameters
/// or layout are migrated upward in future.
pub const WALLET_VERSION: u32 = 1;

/// File extension for a saved wallet.
pub const WALLET_EXTENSION: &str = "rrnwallet";

/// Argon2id memory cost in KiB (64 MiB).
const DEFAULT_M_COST: u32 = 64 * 1024;
/// Argon2id iterations.
const DEFAULT_T_COST: u32 = 3;
/// Argon2id parallelism.
const DEFAULT_P_COST: u32 = 4;
/// Derived AEAD key length.
const KEY_LEN: usize = 32;

/// Errors from wallet encryption, decryption, and file I/O.
#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    /// No wallet file exists at the requested path.
    #[error("no wallet file at {0}")]
    NotFound(PathBuf),
    /// Decryption failed: wrong passphrase, or the ciphertext/AEAD tag was
    /// altered. Deliberately does not distinguish the two.
    #[error("wallet decryption failed (wrong passphrase or corrupt wallet)")]
    Decrypt,
    /// The file's declared version is not supported by this build.
    #[error("unsupported wallet version {0} (this build supports {WALLET_VERSION})")]
    UnsupportedVersion(u32),
    /// The file is structurally invalid — not canonical CBOR, or missing/wrong
    /// fields.
    #[error("corrupt wallet file: {0}")]
    Corrupt(String),
    /// Argon2id key derivation failed (e.g. invalid parameters).
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// An underlying filesystem error.
    #[error("wallet io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for wallet results.
pub type Result<T> = std::result::Result<T, WalletError>;

/// Argon2id parameters captured alongside the ciphertext, so a wallet can be
/// decrypted with the exact parameters it was encrypted under (even after the
/// defaults are tuned upward in a later version).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Argon2idParams {
    salt: [u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Argon2idParams {
    /// The current default parameters with a freshly generated random salt.
    fn generate() -> Self {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        Self {
            salt,
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }

    /// Derives the 32-byte AEAD key from a passphrase under these parameters.
    ///
    /// The returned key is secret material; callers zeroize it after use.
    fn derive_key(&self, passphrase: &str) -> Result<[u8; KEY_LEN]> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| WalletError::Kdf(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; KEY_LEN];
        argon
            .hash_password_into(passphrase.as_bytes(), &self.salt, &mut key)
            .map_err(|e| WalletError::Kdf(e.to_string()))?;
        Ok(key)
    }
}

impl From<Argon2idParams> for CBOR {
    fn from(p: Argon2idParams) -> Self {
        let mut m = Map::new();
        m.insert("salt", CBOR::to_byte_string(p.salt));
        m.insert("m_cost", p.m_cost);
        m.insert("t_cost", p.t_cost);
        m.insert("p_cost", p.p_cost);
        m.into()
    }
}

impl TryFrom<CBOR> for Argon2idParams {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let salt: [u8; 32] = map
            .extract::<&str, CBOR>("salt")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(Self {
            salt,
            m_cost: map.extract::<&str, u32>("m_cost")?,
            t_cost: map.extract::<&str, u32>("t_cost")?,
            p_cost: map.extract::<&str, u32>("p_cost")?,
        })
    }
}

/// A wallet sealed for storage: KDF parameters, AEAD nonce, and ciphertext.
/// Contains no secret material in the clear.
#[derive(Clone, Debug)]
pub struct EncryptedWallet {
    version: u32,
    kdf_params: Argon2idParams,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl EncryptedWallet {
    /// Seals `contents` under `passphrase` with fresh random salt and nonce.
    pub fn encrypt(contents: &WalletContents, passphrase: &str) -> Result<Self> {
        let kdf_params = Argon2idParams::generate();
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let mut key = kdf_params.derive_key(passphrase)?;
        let mut plaintext = contents.to_secret_cbor();
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key is a valid AEAD key");
        let result = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| WalletError::Decrypt);
        // Wipe the derived key and plaintext (which held the secret seed)
        // regardless of whether encryption succeeded.
        key.zeroize();
        plaintext.zeroize();
        let ciphertext = result?;

        Ok(Self {
            version: WALLET_VERSION,
            kdf_params,
            nonce,
            ciphertext,
        })
    }

    /// Opens the wallet with `passphrase`, returning its decrypted contents.
    ///
    /// Returns [`WalletError::Decrypt`] for a wrong passphrase or tampered
    /// ciphertext, and never produces garbage on failure.
    pub fn decrypt(&self, passphrase: &str) -> Result<WalletContents> {
        if self.version != WALLET_VERSION {
            return Err(WalletError::UnsupportedVersion(self.version));
        }
        let mut key = self.kdf_params.derive_key(passphrase)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key is a valid AEAD key");
        let plaintext = cipher.decrypt(XNonce::from_slice(&self.nonce), self.ciphertext.as_slice());
        key.zeroize();
        let mut plaintext = plaintext.map_err(|_| WalletError::Decrypt)?;
        let contents = WalletContents::from_secret_cbor(&plaintext);
        plaintext.zeroize();
        contents
    }
}

impl From<EncryptedWallet> for CBOR {
    fn from(w: EncryptedWallet) -> Self {
        let mut m = Map::new();
        m.insert("version", w.version);
        m.insert("kdf", w.kdf_params);
        m.insert("nonce", CBOR::to_byte_string(w.nonce));
        m.insert("ciphertext", CBOR::to_byte_string(w.ciphertext));
        m.into()
    }
}

impl TryFrom<CBOR> for EncryptedWallet {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let nonce: [u8; 24] = map
            .extract::<&str, CBOR>("nonce")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(Self {
            version: map.extract::<&str, u32>("version")?,
            kdf_params: map.extract::<&str, Argon2idParams>("kdf")?,
            nonce,
            ciphertext: map
                .extract::<&str, CBOR>("ciphertext")?
                .try_into_byte_string()?,
        })
    }
}

/// The decrypted, in-memory contents of a wallet: the secret key and its
/// metadata. The secret key is zeroized on drop.
pub struct WalletContents {
    /// The identity's Ed25519 secret key.
    pub secret_key: SecretKey,
    /// The address derived from the secret key (cached for convenience).
    pub address: Address,
    /// Unix seconds when the identity was created.
    pub created_at: i64,
    /// Arbitrary user metadata (labels, display name, …). Not secret.
    pub metadata: BTreeMap<String, String>,
}

impl WalletContents {
    /// Generates a brand-new identity: a fresh keypair, its address, and an
    /// empty metadata map. `created_at` is the current Unix time.
    pub fn create_new() -> Self {
        let keypair = Keypair::generate();
        Self::from_keypair(keypair, now_secs())
    }

    /// Builds contents from an existing keypair and creation time.
    fn from_keypair(keypair: Keypair, created_at: i64) -> Self {
        let address = Address::from_public_key(keypair.public_key());
        Self {
            secret_key: keypair.secret_key().clone(),
            address,
            created_at,
            metadata: BTreeMap::new(),
        }
    }

    /// Encrypts and writes the wallet to `path`, atomically.
    ///
    /// Writes to a sibling `*.tmp` file, fsyncs it, sets `0o600` permissions,
    /// then renames it over `path` — `rename` is atomic within a filesystem, so
    /// a crash mid-write never leaves a half-written wallet at `path`.
    pub fn save_to_file(&self, path: &Path, passphrase: &str) -> Result<()> {
        let encrypted = EncryptedWallet::encrypt(self, passphrase)?;
        let bytes = to_canonical_bytes(encrypted);

        let tmp = tmp_path(path);
        write_private(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Reads and decrypts the wallet at `path`.
    ///
    /// Returns [`WalletError::NotFound`] if the file does not exist — the caller
    /// decides whether to create a new identity.
    pub fn load_from_file(path: &Path, passphrase: &str) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(WalletError::NotFound(path.to_path_buf()))
            }
            Err(e) => return Err(WalletError::Io(e)),
        };
        let encrypted: EncryptedWallet =
            from_canonical_bytes(&bytes).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        encrypted.decrypt(passphrase)
    }

    /// Encodes the secret-bearing fields to canonical CBOR (the AEAD plaintext).
    /// The address is intentionally omitted — it is re-derived on decrypt.
    fn to_secret_cbor(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("sk", CBOR::to_byte_string(self.secret_key.to_bytes()));
        m.insert("created_at", self.created_at);
        let mut meta = Map::new();
        for (k, v) in &self.metadata {
            meta.insert(k.clone(), v.clone());
        }
        m.insert("metadata", meta);
        to_canonical_bytes(m)
    }

    /// Decodes the secret-bearing fields and re-derives the address from the
    /// secret key.
    fn from_secret_cbor(bytes: &[u8]) -> Result<Self> {
        let cbor = CBOR::try_from_data(bytes).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(WalletError::Corrupt("wallet plaintext is not a map".into())),
        };

        let sk_bytes: [u8; 32] = map
            .extract::<&str, CBOR>("sk")
            .and_then(|c| c.try_into_byte_string())
            .map_err(|e| WalletError::Corrupt(e.to_string()))?
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::Corrupt("secret key is not 32 bytes".into()))?;
        let created_at = map
            .extract::<&str, i64>("created_at")
            .map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let meta_map = map
            .extract::<&str, CBOR>("metadata")
            .map_err(|e| WalletError::Corrupt(e.to_string()))?;

        let mut metadata = BTreeMap::new();
        if let CBORCase::Map(meta) = meta_map.into_case() {
            for (k, v) in meta.iter() {
                let key = k
                    .clone()
                    .try_into_text()
                    .map_err(|e| WalletError::Corrupt(e.to_string()))?;
                let value = v
                    .clone()
                    .try_into_text()
                    .map_err(|e| WalletError::Corrupt(e.to_string()))?;
                metadata.insert(key, value);
            }
        } else {
            return Err(WalletError::Corrupt("metadata is not a map".into()));
        }

        let keypair = Keypair::from_secret(SecretKey::from_bytes(sk_bytes));
        let address = Address::from_public_key(keypair.public_key());
        Ok(Self {
            secret_key: keypair.secret_key().clone(),
            address,
            created_at,
            metadata,
        })
    }
}

impl core::fmt::Debug for WalletContents {
    /// Redacts the secret key; shows only the non-secret fields.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalletContents")
            .field("secret_key", &"[REDACTED]")
            .field("address", &self.address)
            .field("created_at", &self.created_at)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Zeroize for WalletContents {
    fn zeroize(&mut self) {
        // The secret key is the only sensitive field; the address (a public
        // key), creation time, and metadata are not secret.
        self.secret_key.zeroize();
    }
}

impl Drop for WalletContents {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for WalletContents {}

/// `path` with a `.tmp` suffix appended, for atomic write-then-rename.
fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Writes `bytes` to `path`, fsyncs, and restricts permissions to owner
/// read/write (`0o600`) on Unix.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";

    fn sample_contents() -> WalletContents {
        let mut c = WalletContents::create_new();
        c.created_at = 1_700_000_000;
        c.metadata.insert("label".into(), "primary".into());
        c.metadata.insert("zeta".into(), "last".into());
        c
    }

    fn assert_same_identity(a: &WalletContents, b: &WalletContents) {
        assert_eq!(a.secret_key.to_bytes(), b.secret_key.to_bytes());
        assert_eq!(a.address, b.address);
        assert_eq!(a.created_at, b.created_at);
        assert_eq!(a.metadata, b.metadata);
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let contents = sample_contents();
        let wallet = EncryptedWallet::encrypt(&contents, PASS).unwrap();
        let restored = wallet.decrypt(PASS).unwrap();
        assert_same_identity(&contents, &restored);
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let contents = sample_contents();
        let wallet = EncryptedWallet::encrypt(&contents, PASS).unwrap();
        let err = wallet.decrypt("wrong passphrase").unwrap_err();
        assert!(matches!(err, WalletError::Decrypt), "{err:?}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let contents = sample_contents();
        let mut wallet = EncryptedWallet::encrypt(&contents, PASS).unwrap();
        *wallet.ciphertext.last_mut().unwrap() ^= 0x01;
        let err = wallet.decrypt(PASS).unwrap_err();
        assert!(matches!(err, WalletError::Decrypt), "{err:?}");
    }

    #[test]
    fn canonical_cbor_roundtrip_of_envelope() {
        let contents = sample_contents();
        let wallet = EncryptedWallet::encrypt(&contents, PASS).unwrap();
        let bytes = to_canonical_bytes(wallet.clone());
        let decoded: EncryptedWallet = from_canonical_bytes(&bytes).unwrap();
        // Re-encoding the decoded envelope yields identical bytes.
        assert_eq!(bytes, to_canonical_bytes(decoded.clone()));
        // And it still decrypts.
        assert_same_identity(&contents, &decoded.decrypt(PASS).unwrap());
    }

    #[test]
    fn save_then_load_yields_identical_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.rrnwallet");
        let contents = sample_contents();
        contents.save_to_file(&path, PASS).unwrap();

        let loaded = WalletContents::load_from_file(&path, PASS).unwrap();
        assert_same_identity(&contents, &loaded);
    }

    #[test]
    fn load_missing_file_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.rrnwallet");
        let err = WalletContents::load_from_file(&path, PASS).unwrap_err();
        assert!(matches!(err, WalletError::NotFound(_)), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.rrnwallet");
        sample_contents().save_to_file(&path, PASS).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn create_new_address_matches_secret_key() {
        let c = WalletContents::create_new();
        let derived =
            Address::from_public_key(Keypair::from_secret(c.secret_key.clone()).public_key());
        assert_eq!(c.address, derived);
    }
}
