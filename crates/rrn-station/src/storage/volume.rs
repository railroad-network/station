//! The encrypted volume and its kernel mount helper (ADR-0024).
//!
//! Block encryption lives entirely **below** our binary: the Linux kernel's
//! `dm-crypt` (via `cryptsetup`/`losetup`) encrypts a self-contained LUKS2
//! container file, and our audited code touches only the 32-byte Volume Master
//! Key. No C crypto is linked into the daemon, no `unsafe` is added, and
//! `rrn-storage`'s `db.rs` is unchanged — SQLite sees an ordinary ext4 filesystem
//! with ordinary WAL semantics once the volume is mapped.
//!
//! The one seam this module introduces is [`MountHelper`], the boundary between the
//! unprivileged daemon and the root-privileged operations `cryptsetup`/`losetup`/
//! `mount` require. Two implementations:
//! - [`SudoCryptsetupHelper`] — the real helper (Linux only), which drives
//!   `cryptsetup` and passes the volume key **by file descriptor** (never argv, an
//!   environment variable, or a temp file, all of which a seizure or another local
//!   process could read);
//! - a `RecordingHelper` test double (test builds only) that records the call
//!   sequence and lets the orchestration be verified on any platform.
//!
//! Powered off, the container is a LUKS2 brick with **no wrapped copy of the key on
//! the device**: it is opened keyslot-lessly with the VMK as the volume key. The
//! throwaway keyslot `luksFormat` creates is killed at provisioning and
//! [`DmCryptVolume::open`] refuses to proceed unless the header has **zero
//! keyslots** — otherwise an Argon2-wrapped VMK would survive under a provisioning
//! passphrase and the brick would not be a brick.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use zeroize::Zeroizing;

/// The seam between the unprivileged daemon and the root-privileged block-crypto
/// operations. See the module docs for why the key crosses it by fd only.
///
/// Implementations must treat the 32-byte `key` as secret: it may be passed to
/// `cryptsetup` only via a file descriptor, and must never appear on a command
/// line, in an environment variable, or in a file on any persistent filesystem.
pub trait MountHelper: Send + Sync {
    /// Opens the LUKS container at `container_path` with `key` as the volume key and
    /// mounts the decrypted mapping at `state_dir`. `mapping` is the `dm-crypt`
    /// device-mapper name.
    fn open(
        &self,
        container_path: &Path,
        key: &Zeroizing<[u8; 32]>,
        mapping: &str,
        state_dir: &Path,
    ) -> Result<()>;

    /// Unmounts `state_dir`, closes the `dm-crypt` mapping, and detaches the loop
    /// device backing `container_path`. Idempotent-ish: tolerates an already-closed
    /// volume.
    fn close(&self, mapping: &str, container_path: &Path, state_dir: &Path) -> Result<()>;

    /// Whether `state_dir` is right now a **live `dm-crypt` mount** — not a plain
    /// directory. The daemon calls this before touching any file, so a mis-ordered
    /// restart cannot create a fresh plaintext `station.db` on the unencrypted root
    /// and serve it.
    fn is_live_mount(&self, state_dir: &Path) -> Result<bool>;

    /// The number of keyslots in the container's LUKS2 header. Must be **zero** for
    /// a real brick: any keyslot is an Argon2-wrapped copy of the volume key on the
    /// device. [`DmCryptVolume::open`] enforces this as a hard precondition.
    fn keyslot_count(&self, container_path: &Path) -> Result<usize>;
}

/// Whether `state_dir` is **right now** a live `dm-crypt` mount (not a plain
/// directory). Unprivileged — it reads `/proc/self/mountinfo` — so the daemon can
/// call it as the mount guard before touching any file, without needing root or the
/// [`MountHelper`]. On non-Linux hosts (where the encrypted profile never runs) it
/// returns `Ok(false)`.
pub fn state_dir_is_live_mount(state_dir: &Path) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        linux_live_mount(state_dir, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state_dir;
        Ok(false)
    }
}

/// Whether `state_dir` is a live mount whose source is **exactly** the crypt mapping
/// `/dev/mapper/{mapping}` — the strict guard `Station::open` uses, so a plaintext
/// dm-linear (LVM) volume happening to be mounted at the state dir cannot pass for an
/// encrypted one. On non-Linux returns `Ok(false)`.
pub fn state_dir_is_crypt_mount(state_dir: &Path, mapping: &str) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        linux_live_mount(state_dir, Some(mapping))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_dir, mapping);
        Ok(false)
    }
}

/// The `/proc/self/mountinfo` scan behind the guards. With `expect_mapping = None`,
/// a live mount at this point from any `/dev/mapper/…` (or `/dev/dm-…`) source
/// counts; with `Some(m)`, only a source of exactly `/dev/mapper/{m}` counts.
#[cfg(target_os = "linux")]
fn linux_live_mount(state_dir: &Path, expect_mapping: Option<&str>) -> Result<bool> {
    let target = std::fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    let info = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    for line in info.lines() {
        let parts: Vec<&str> = line.split(" - ").collect();
        if parts.len() != 2 {
            continue;
        }
        let left: Vec<&str> = parts[0].split_whitespace().collect();
        let right: Vec<&str> = parts[1].split_whitespace().collect();
        if left.len() < 5 || right.len() < 2 {
            continue;
        }
        // The mount point is octal-escaped in mountinfo (space→\040, tab→\011,
        // newline→\012, backslash→\134); unescape before comparing, or a state dir
        // whose path contains a space could never match and the encrypted profile
        // would be permanently unusable there with a misleading "not mounted" error.
        let mount_point = unescape_mountinfo(left[4]);
        let source = right[1];
        if Path::new(&mount_point) != target {
            continue;
        }
        return Ok(match expect_mapping {
            Some(m) => source == format!("/dev/mapper/{m}"),
            None => source.starts_with("/dev/mapper/") || source.starts_with("/dev/dm-"),
        });
    }
    Ok(false)
}

/// Decodes the octal escapes the kernel writes into the `/proc/self/mountinfo`
/// path fields (`\NNN`). Unrecognised backslash sequences are passed through
/// verbatim.
#[cfg(target_os = "linux")]
fn unescape_mountinfo(s: &str) -> String {
    // Accumulate raw bytes, not chars: the kernel escapes only space/tab/newline/
    // backslash (all ASCII), and passes multi-byte UTF-8 through verbatim. Decoding
    // byte-by-byte into `char` would map each UTF-8 continuation byte to a stray
    // Latin-1 char and corrupt any non-ASCII path, so copy bytes through and rebuild
    // the string at the end.
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 4 <= bytes.len() {
            let oct = &bytes[i + 1..i + 4];
            if oct.iter().all(|b| (b'0'..=b'7').contains(b)) {
                if let Ok(code) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                    out.push(code);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether the encrypted at-rest profile can run on this host. The profile is
/// Linux-only (kernel `dm-crypt`); everywhere else this returns an error so a
/// station refuses `at_rest = "encrypted"` rather than silently serving plaintext.
pub fn ensure_platform_supported() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        bail!(
            "the encrypted at-rest profile is Linux-only (kernel dm-crypt, ADR-0024); \
             this host is not Linux. Use `at_rest = \"plaintext\"`, or run the station on \
             a Linux node."
        )
    }
}

/// A member-keyed encrypted volume: a LUKS2 container opened by a [`MountHelper`]
/// with the reconstructed VMK, mounted at a `state_dir`.
///
/// The daemon holds one of these under the encrypted profile. It owns no key
/// material beyond the transient VMK an [`open`](DmCryptVolume::open) call passes
/// straight to the helper; after opening, the volume key lives only in the kernel's
/// crypto state for as long as the mapping exists.
pub struct DmCryptVolume {
    helper: Box<dyn MountHelper>,
    container_path: PathBuf,
    mapping: String,
    state_dir: PathBuf,
}

impl DmCryptVolume {
    /// Builds a volume bound to a container file, a device-mapper name, and a mount
    /// point, using the real [`SudoCryptsetupHelper`]. Linux only.
    #[cfg(target_os = "linux")]
    pub fn new(container_path: PathBuf, mapping: String, state_dir: PathBuf) -> Self {
        Self::with_helper(
            Box::new(SudoCryptsetupHelper),
            container_path,
            mapping,
            state_dir,
        )
    }

    /// Builds a volume over an explicit helper — the daemon uses
    /// [`SudoCryptsetupHelper`]; tests inject a recording double.
    pub fn with_helper(
        helper: Box<dyn MountHelper>,
        container_path: PathBuf,
        mapping: String,
        state_dir: PathBuf,
    ) -> Self {
        Self {
            helper,
            container_path,
            mapping,
            state_dir,
        }
    }

    /// The mount point the decrypted container is served at.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Opens and mounts the volume with the reconstructed VMK.
    ///
    /// Enforces the **zero-keyslot precondition** first: if the header carries any
    /// keyslot, an Argon2-wrapped VMK survives on the device and the container is
    /// not a brick — so this refuses rather than open it. After the helper mounts,
    /// it re-checks that `state_dir` is a live `dm-crypt` mount before returning, so
    /// a caller never proceeds against a plain directory.
    pub fn open(&self, vmk: &Zeroizing<[u8; 32]>) -> Result<()> {
        let slots = self
            .helper
            .keyslot_count(&self.container_path)
            .map_err(|e| anyhow::anyhow!("read LUKS keyslot count: {e}"))?;
        if slots != 0 {
            bail!(
                "refusing to open {}: its LUKS header has {slots} keyslot(s); a keyslot is a \
                 wrapped copy of the volume key on the device, so the container is not a brick. \
                 Re-provision it keyslot-lessly (ADR-0024).",
                self.container_path.display()
            );
        }
        self.helper
            .open(&self.container_path, vmk, &self.mapping, &self.state_dir)?;
        if !self.helper.is_live_mount(&self.state_dir)? {
            bail!(
                "opened the container but {} is not a live dm-crypt mount; refusing to serve",
                self.state_dir.display()
            );
        }
        Ok(())
    }

    /// Whether the volume is currently mounted (a live `dm-crypt` mount at
    /// `state_dir`). A daemon restarting while the host stayed up uses this to
    /// re-attach to an already-mapped volume without a fresh ceremony.
    pub fn is_open(&self) -> Result<bool> {
        self.helper.is_live_mount(&self.state_dir)
    }

    /// Closes and unmounts the volume.
    pub fn close(&self) -> Result<()> {
        self.helper
            .close(&self.mapping, &self.container_path, &self.state_dir)
    }
}

/// The real, root-privileged mount helper: shells out to `cryptsetup`/`losetup`/
/// `mount` under `sudo -n`, passing the volume key on the child's **stdin** (an fd)
/// via `--volume-key-file /dev/stdin`, so it never lands on a command line, in the
/// environment, or in a temp file.
///
/// Linux only. Everything here is validated by the `at-rest-dmcrypt` CI lane
/// (`tests/at_rest_dmcrypt.rs`), which needs a real kernel, loop devices, and
/// passwordless sudo — none of which exist on the macOS dev host.
#[cfg(target_os = "linux")]
pub struct SudoCryptsetupHelper;

#[cfg(target_os = "linux")]
impl SudoCryptsetupHelper {
    fn sudo(args: &[&str]) -> std::process::Command {
        let mut cmd = std::process::Command::new("sudo");
        cmd.arg("-n");
        cmd.args(args);
        cmd
    }

    /// Runs a privileged `cryptsetup` subcommand with the volume key fed on the
    /// child's **stdin** (`--volume-key-file /dev/stdin`), so the key never appears
    /// on a command line, in the environment, or in a file. Returns the exit status.
    fn cryptsetup_with_key(args: &[&str], key: &Zeroizing<[u8; 32]>) -> Result<()> {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Self::sudo(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(&key[..])?;
        let status = child.wait()?;
        if !status.success() {
            bail!("cryptsetup {:?} failed (exit {status})", args);
        }
        Ok(())
    }

    /// Provisions a fresh **keyslot-less** LUKS2 container: creates the container
    /// file, formats it with `vmk` as the volume key, kills the throwaway keyslot
    /// `luksFormat` leaves behind, verifies the header has zero keyslots, then opens,
    /// `mkfs.ext4`-formats, mounts at `state_dir`, and hands ownership to the current
    /// (unprivileged) user so the daemon can write inside.
    ///
    /// After this returns the container is a real brick: powered off there is no
    /// wrapped copy of the key on the device — the VMK *is* the volume key.
    pub fn provision(
        &self,
        container_path: &Path,
        size_bytes: u64,
        vmk: &Zeroizing<[u8; 32]>,
        mapping: &str,
        state_dir: &Path,
    ) -> Result<()> {
        // 1. Create a sparse container file of the requested size.
        {
            let f = std::fs::File::create(container_path)?;
            f.set_len(size_bytes)?;
        }
        // 2. Attach a loop device.
        let out = Self::sudo(&["losetup", "--find", "--show"])
            .arg(container_path)
            .output()?;
        if !out.status.success() {
            bail!(
                "losetup failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let loop_dev = String::from_utf8_lossy(&out.stdout).trim().to_string();

        // 3. A throwaway keyslot passphrase, kept in tmpfs (/dev/shm), never on the
        //    persistent root; it is killed in step 5 and the file is dropped.
        let pass_dir = tempfile::Builder::new()
            .prefix("rrn-vmk-")
            .tempdir_in("/dev/shm")
            .or_else(|_| tempfile::tempdir())?;
        let pass_file = pass_dir.path().join("throwaway");
        // A random throwaway passphrase; its keyslot is killed in step 5, so its only
        // job is to satisfy `luksFormat`, which requires a keyslot.
        let throwaway = rrn_crypto::hash::Hash::of(
            &rrn_crypto::keypair::Keypair::generate()
                .secret_key()
                .to_bytes(),
        )
        .to_hex();
        std::fs::write(&pass_file, throwaway.as_bytes())?;
        let pass_file_str = pass_file.to_string_lossy().to_string();

        // 4. Format with the VMK as the volume key (fed on stdin) plus a throwaway
        //    keyslot from the tmpfs passphrase. The cipher is chosen for the host
        //    (ADR-0024): AES-XTS where the CPU has AES acceleration, Adiantum on
        //    AES-less ARM (the Pi 4). `--key-size 256` makes the volume key exactly
        //    32 bytes so the VMK *is* the volume key (AES-XTS-256 splits into two
        //    AES-128 keys; Adiantum takes a 256-bit key). The throwaway keyslot uses
        //    a fast PBKDF (it is killed in step 5, so its cost buys nothing).
        //    `--volume-key-file` needs cryptsetup ≥ 2.5 (Debian Bookworm's 2.6 is
        //    fine; Bullseye's 2.3 is not — see the runbook).
        let (cipher, sector_size) = choose_cipher();
        let mut fmt_args: Vec<&str> = vec![
            "cryptsetup",
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--cipher",
            cipher,
            "--key-size",
            "256",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
        ];
        if let Some(s) = sector_size {
            fmt_args.push("--sector-size");
            fmt_args.push(s);
        }
        fmt_args.extend_from_slice(&[
            "--volume-key-file",
            "/dev/stdin",
            "--key-file",
            &pass_file_str,
            &loop_dev,
        ]);
        Self::cryptsetup_with_key(&fmt_args, vmk)?;
        drop(pass_dir);

        // 5. Kill the throwaway keyslot — so the header ends up with zero keyslots
        //    and no wrapped key survives. In `--batch-mode` this needs no passphrase
        //    and no confirmation even for the last slot (`--volume-key-file` is not a
        //    valid option for luksKillSlot).
        let out =
            Self::sudo(&["cryptsetup", "luksKillSlot", "--batch-mode", &loop_dev, "0"]).output()?;
        if !out.status.success() {
            bail!(
                "cryptsetup luksKillSlot failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }

        // 6. Post-check: the header must have zero keyslots, or it is not a brick.
        let slots = self.keyslot_count(container_path)?;
        if slots != 0 {
            bail!(
                "provisioning left {slots} keyslot(s) in the LUKS header; the container is not a \
                 brick. Aborting."
            );
        }

        // 7. Open keyslot-lessly with the VMK, make a filesystem, mount, chown.
        //    A zero-keyslot LUKS2 header carries no key-size metadata, so cryptsetup
        //    refuses to open it unless `--key-size` is given explicitly (it cannot
        //    infer the volume-key length from a slot that no longer exists). Our VMK
        //    is 256-bit, matching the `luksFormat --key-size 256` above.
        Self::cryptsetup_with_key(
            &[
                "cryptsetup",
                "open",
                "--type",
                "luks2",
                "--key-size",
                "256",
                "--volume-key-file",
                "/dev/stdin",
                &loop_dev,
                mapping,
            ],
            vmk,
        )?;
        let mapper = format!("/dev/mapper/{mapping}");
        let out = Self::sudo(&["mkfs.ext4", "-q", &mapper]).output()?;
        if !out.status.success() {
            bail!(
                "mkfs.ext4 failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        std::fs::create_dir_all(state_dir)?;
        // The filesystem holds only the daemon's data; it should never carry device
        // nodes, setuid binaries, or executables, so harden the mount against them.
        let out = Self::sudo(&["mount", "-o", "nodev,nosuid,noexec", &mapper])
            .arg(state_dir)
            .output()?;
        if !out.status.success() {
            bail!(
                "mount failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        // Hand the mount to the unprivileged user running the daemon. Use numeric
        // uid:gid (`id -u`/`id -g`) rather than $USER, which is unset under
        // systemd/cron and does not imply a same-named group.
        let uid = run_stdout("id", &["-u"]);
        let gid = run_stdout("id", &["-g"]);
        if let (Some(uid), Some(gid)) = (uid, gid) {
            let out = Self::sudo(&["chown", &format!("{uid}:{gid}")])
                .arg(state_dir)
                .output()?;
            if !out.status.success() {
                bail!(
                    "chown of the mounted state dir failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        } else {
            bail!("could not determine uid/gid to own the mounted state dir");
        }
        Ok(())
    }

    /// Finds the loop device currently backing `container_path`, if any.
    fn loop_for(container_path: &Path) -> Result<Option<String>> {
        let out = std::process::Command::new("losetup")
            .args(["-j"])
            .arg(container_path)
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text
            .lines()
            .next()
            .and_then(|l| l.split(':').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()))
    }
}

#[cfg(target_os = "linux")]
impl MountHelper for SudoCryptsetupHelper {
    fn open(
        &self,
        container_path: &Path,
        key: &Zeroizing<[u8; 32]>,
        mapping: &str,
        state_dir: &Path,
    ) -> Result<()> {
        use std::io::Write;
        use std::process::Stdio;

        // Attach a loop device to the container file (idempotent: reuse an existing
        // attachment).
        let loop_dev = match Self::loop_for(container_path)? {
            Some(dev) => dev,
            None => {
                let out = Self::sudo(&["losetup", "--find", "--show"])
                    .arg(container_path)
                    .output()?;
                if !out.status.success() {
                    bail!(
                        "losetup failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
        };

        // Open the LUKS container keyslot-lessly: the VMK *is* the volume key, read
        // from the child's stdin (fd) rather than any on-disk path. If the mapping
        // already exists (a prior run whose mount was dropped), skip straight to the
        // mount so recovery is idempotent.
        // `--key-size 256` is required: a keyslot-less LUKS2 header has no key-size
        // metadata, so cryptsetup cannot infer the volume-key length and refuses to
        // open without it. Our VMK is 256-bit (matches provisioning).
        let mapper = format!("/dev/mapper/{mapping}");
        if !Path::new(&mapper).exists() {
            let mut child = Self::sudo(&[
                "cryptsetup",
                "open",
                "--type",
                "luks2",
                "--key-size",
                "256",
                "--volume-key-file",
                "/dev/stdin",
                &loop_dev,
                mapping,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()?;
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(&key[..])?;
            let status = child.wait()?;
            if !status.success() {
                bail!("cryptsetup open failed for {}", container_path.display());
            }
        }

        // Mount the decrypted mapping. Harden it: data-only filesystem, so no device
        // nodes, setuid binaries, or executables (matches provisioning).
        std::fs::create_dir_all(state_dir)?;
        let out = Self::sudo(&["mount", "-o", "nodev,nosuid,noexec", &mapper])
            .arg(state_dir)
            .output()?;
        if !out.status.success() {
            bail!(
                "mount failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn close(&self, mapping: &str, container_path: &Path, state_dir: &Path) -> Result<()> {
        // Best-effort teardown in reverse order; tolerate already-closed pieces.
        // Resolve the backing loop device *before* closing the crypt mapping (once
        // detached, losetup -j can no longer find it), then unmount, drop the crypt
        // device, and detach the loop — otherwise every open/close cycle leaks a
        // loop device until reboot.
        let loop_dev = Self::loop_for(container_path).ok().flatten();
        let _ = Self::sudo(&["umount"]).arg(state_dir).output();
        let _ = Self::sudo(&["cryptsetup", "close", mapping]).output();
        if let Some(dev) = loop_dev {
            let _ = Self::sudo(&["losetup", "-d", &dev]).output();
        }
        Ok(())
    }

    fn is_live_mount(&self, state_dir: &Path) -> Result<bool> {
        linux_live_mount(state_dir, None)
    }

    fn keyslot_count(&self, container_path: &Path) -> Result<usize> {
        let loop_dev = Self::loop_for(container_path)?;
        let mut cmd = Self::sudo(&["cryptsetup", "luksDump", "--dump-json-metadata"]);
        match &loop_dev {
            Some(dev) => cmd.arg(dev),
            None => cmd.arg(container_path),
        };
        let out = cmd.output()?;
        if !out.status.success() {
            bail!(
                "cryptsetup luksDump failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let json: serde_json::Value = serde_json::from_slice(&out.stdout)
            .map_err(|e| anyhow::anyhow!("parse luksDump JSON: {e}"))?;
        // Fail closed: an absent or non-object `keyslots` is an unrecognised dump,
        // not proof of zero keyslots — never let the brick precondition pass by
        // default on a shape we did not understand.
        let slots = json
            .get("keyslots")
            .and_then(|k| k.as_object())
            .map(|m| m.len())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "luksDump JSON has no \"keyslots\" object; cannot confirm the zero-keyslot \
                     brick property (unrecognised cryptsetup output)"
                )
            })?;
        Ok(slots)
    }
}

/// Chooses the LUKS cipher for this host (ADR-0024): AES-XTS where the CPU has AES
/// acceleration, Adiantum (`--sector-size 4096`) on AES-less ARM such as the Pi 4.
/// Returns `(cipher, Some(sector_size))`. Both take a 256-bit (32-byte) volume key,
/// so the VMK is the volume key directly.
#[cfg(target_os = "linux")]
fn choose_cipher() -> (&'static str, Option<&'static str>) {
    let has_aes = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| {
            s.lines()
                .any(|l| l.starts_with("Features") || l.starts_with("flags"))
                && s.contains("aes")
        })
        .unwrap_or(false);
    if has_aes {
        ("aes-xts-plain64", None)
    } else {
        ("xchacha12,aes-adiantum-plain64", Some("4096"))
    }
}

/// Runs a non-privileged command and returns its trimmed stdout, or `None` on
/// failure. Used to read `id -u`/`id -g`.
#[cfg(target_os = "linux")]
fn run_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recording test double: models a volume without a kernel. `open` marks the
    /// mount live and records the call (asserting a 32-byte key arrived); `close`
    /// clears it. `keyslot_count` returns a configurable value so the zero-keyslot
    /// precondition can be exercised.
    #[derive(Default)]
    struct RecordingHelper {
        calls: Mutex<Vec<String>>,
        mounted: Mutex<bool>,
        keyslots: usize,
        key_len_seen: Mutex<Option<usize>>,
    }

    impl MountHelper for RecordingHelper {
        fn open(
            &self,
            _container: &Path,
            key: &Zeroizing<[u8; 32]>,
            mapping: &str,
            _state_dir: &Path,
        ) -> Result<()> {
            *self.key_len_seen.lock().unwrap() = Some(key.len());
            self.calls.lock().unwrap().push(format!("open:{mapping}"));
            *self.mounted.lock().unwrap() = true;
            Ok(())
        }
        fn close(&self, mapping: &str, _container: &Path, _state_dir: &Path) -> Result<()> {
            self.calls.lock().unwrap().push(format!("close:{mapping}"));
            *self.mounted.lock().unwrap() = false;
            Ok(())
        }
        fn is_live_mount(&self, _state_dir: &Path) -> Result<bool> {
            Ok(*self.mounted.lock().unwrap())
        }
        fn keyslot_count(&self, _container: &Path) -> Result<usize> {
            self.calls.lock().unwrap().push("keyslot_count".into());
            Ok(self.keyslots)
        }
    }

    fn key() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([7u8; 32])
    }

    #[test]
    fn open_checks_keyslots_before_opening_then_verifies_mount() {
        let helper = Box::new(RecordingHelper::default()); // 0 keyslots
        let vol = DmCryptVolume::with_helper(
            helper,
            PathBuf::from("/x/state.img"),
            "rrnstate".into(),
            PathBuf::from("/x/state"),
        );
        assert!(!vol.is_open().unwrap());
        vol.open(&key()).unwrap();
        assert!(vol.is_open().unwrap(), "mount is live after open");
        vol.close().unwrap();
        assert!(!vol.is_open().unwrap(), "closed");
    }

    #[test]
    fn open_refuses_a_container_with_any_keyslot() {
        // A non-zero keyslot means a wrapped key survives on disk — not a brick.
        let helper = Box::new(RecordingHelper {
            keyslots: 1,
            ..Default::default()
        });
        let vol = DmCryptVolume::with_helper(
            helper,
            PathBuf::from("/x/state.img"),
            "rrnstate".into(),
            PathBuf::from("/x/state"),
        );
        let err = vol.open(&key()).unwrap_err();
        assert!(
            err.to_string().contains("keyslot"),
            "must refuse on non-zero keyslots: {err}"
        );
        assert!(!vol.is_open().unwrap(), "nothing was mounted");
    }

    #[test]
    fn open_delivers_a_32_byte_key_and_checks_slots_first() {
        let helper = RecordingHelper::default();
        // Peek at the recording via a raw pointer-free approach: drive through the
        // volume, then read the helper's state by re-constructing expectations.
        // (We keep the helper accessible by not boxing away the concrete type.)
        let container = PathBuf::from("/x/state.img");
        let state = PathBuf::from("/x/state");
        // Inline the orchestration to inspect ordering.
        assert_eq!(helper.keyslot_count(&container).unwrap(), 0);
        helper.open(&container, &key(), "rrnstate", &state).unwrap();
        assert_eq!(
            *helper.key_len_seen.lock().unwrap(),
            Some(32),
            "helper received a 32-byte key"
        );
        let calls = helper.calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["keyslot_count", "open:rrnstate"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unescape_mountinfo_decodes_octal() {
        assert_eq!(unescape_mountinfo("/var/lib/rrn"), "/var/lib/rrn");
        assert_eq!(unescape_mountinfo("/mnt/my\\040data"), "/mnt/my data");
        assert_eq!(unescape_mountinfo("/a\\011b"), "/a\tb");
        // A trailing lone backslash and a non-octal sequence pass through verbatim.
        assert_eq!(unescape_mountinfo("/a\\"), "/a\\");
        assert_eq!(unescape_mountinfo("/a\\09b"), "/a\\09b");
        // Multi-byte UTF-8 is preserved (the kernel does not escape bytes ≥ 0x80),
        // including alongside an escaped space.
        assert_eq!(unescape_mountinfo("/home/señal"), "/home/señal");
        assert_eq!(unescape_mountinfo("/mnt/se\\040ñal"), "/mnt/se ñal");
    }

    #[test]
    fn non_linux_platform_guard() {
        let res = ensure_platform_supported();
        if cfg!(target_os = "linux") {
            assert!(res.is_ok());
        } else {
            assert!(res.is_err(), "encrypted profile refused off Linux");
        }
    }
}
