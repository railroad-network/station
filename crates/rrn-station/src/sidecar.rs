//! Supervised Reticulum daemon (`rnsd`) sidecar — ADR-0013.
//!
//! ADR-0013 committed to Reticulum as the federation/collapse-mode carrier and,
//! critically, to running it as an **external, supervised, version-pinned OS
//! service** — "treated like `tor` or `postgres`, not like a library" — because
//! the LoRa/RNode and LXMF capabilities that motivate the whole adoption live
//! only in the Python reference today. This module is that supervisor: it runs
//! `rnsd` as an appliance-style managed child.
//!
//! # Carrier only (ADR-0013 non-goals)
//!
//! The sidecar is a **dumb carrier**. Nothing here leaks a Reticulum identity
//! into RRN identity, and nothing trusts Reticulum's transport crypto for
//! integrity — the bytes it moves are already sealed and signed at the app layer
//! (ADR-0002/0008/0020). A compromise of `rnsd` is exactly a compromised carrier:
//! it can drop, delay, reorder, or observe traffic metadata, but it cannot forge
//! a record, because it never holds an RRN key. See the threat model's
//! Reticulum-transport section.
//!
//! # Appliance discipline
//!
//! - **Version-pinned.** On start the supervisor runs `rnsd --version` and
//!   refuses to manage a build that does not match the configured pin — it runs
//!   *degraded, without the sidecar*, rather than with an unpinned one. The
//!   [`allow_version_drift`](crate::config::SidecarSection::allow_version_drift)
//!   knob is a development-only escape hatch.
//! - **Never fatal.** Every failure — missing binary, version drift, a config it
//!   cannot write, a child that will not stay up — degrades to "sidecar
//!   unavailable". The daemon never exits because the sidecar failed; its loss is
//!   a connectivity event, exactly like an unreachable peer (T2.4.1).
//! - **Supervised.** The child's stdout/stderr are captured into `tracing`, it is
//!   restarted with exponential backoff on exit, and it is stopped cleanly
//!   (SIGTERM, then SIGKILL after a grace period) on daemon shutdown.
//!
//! This ticket (T2.6.1) delivers the supervisor and the integration spike. The
//! `FrameTransport` impl over the sidecar and announce-budget tuning are T2.6.2;
//! the RNode/LoRa interface template is T2.6.3.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;

use crate::gossip::ConnectivityState;

/// The `rnsd` version this station is validated against by default, as a
/// dotted-prefix pin (`"1.5"` accepts any `1.5.x`). Set from the version the
/// T2.6.1 spike pins — `rns` 1.5.2 (PyPI, 2026-08-29) with `lxmf` 1.1.1;
/// overridable per-station via
/// [`[sidecar] pinned_version`](crate::config::SidecarSection::pinned_version).
pub const DEFAULT_PINNED_RNSD_VERSION: &str = "1.5";

/// The generated Reticulum config file name within the sidecar's config dir.
/// (`rnsd --config <dir>` reads `<dir>/config`.)
pub const RETICULUM_CONFIG_FILE: &str = "config";

/// A child that has stayed up at least this long is treated as healthy, so its
/// eventual exit restarts at the base backoff rather than a climbed one.
const HEALTHY_AFTER_SECS: u64 = 30;
/// Grace between SIGTERM and SIGKILL when stopping the child on shutdown.
const SHUTDOWN_GRACE_SECS: u64 = 10;
/// The backoff ceiling (ADR-0013 appliance framing; ticket: doubling, cap 300).
const BACKOFF_CAP_SECS: u64 = 300;

/// The supervisor's live state, mirrored into the `status` RPC's connectivity
/// block (T2.4.1) so an operator can read the sidecar's posture at a glance.
/// Purely derived degradation-legibility state — nothing here is signed or
/// persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarState {
    /// Not configured to run (`[sidecar] enabled = false`), the default.
    Disabled,
    /// Running a managed `rnsd` of the given version.
    Running {
        /// The `rnsd` version string the supervisor validated at start.
        version: String,
    },
    /// Not running, and will not be retried this run: version drift (with drift
    /// disallowed), a missing/unrunnable binary, or a config that could not be
    /// written. The daemon runs on without the carrier.
    Degraded {
        /// A human-readable reason, surfaced in `status`.
        reason: String,
    },
    /// The child exited and the supervisor is waiting out its backoff before the
    /// next spawn attempt.
    Restarting {
        /// The consecutive-failure count (1 = first restart).
        attempt: u32,
        /// Whole seconds of backoff before the next attempt.
        backoff_secs: u64,
    },
}

impl SidecarState {
    /// Flattens the state into `(tag, version, reason)` for the status wire form,
    /// keeping this module independent of the RPC types.
    pub fn describe(&self) -> (&'static str, Option<String>, Option<String>) {
        match self {
            SidecarState::Disabled => ("disabled", None, None),
            SidecarState::Running { version } => ("running", Some(version.clone()), None),
            SidecarState::Degraded { reason } => ("degraded", None, Some(reason.clone())),
            SidecarState::Restarting {
                attempt,
                backoff_secs,
            } => (
                "restarting",
                None,
                Some(format!("attempt {attempt}, next in {backoff_secs}s")),
            ),
        }
    }
}

/// Resolved supervisor inputs, assembled by [`Station::open`](crate::station::Station::open)
/// from the `[sidecar]` config and the data dir (the config carries paths and
/// whole seconds; this carries resolved paths and `Duration`s so tests can drive
/// it with sub-second backoff).
#[derive(Clone, Debug)]
pub struct SidecarConfig {
    /// The `rnsd` binary (path or bare name resolved via `PATH`).
    pub rnsd_path: PathBuf,
    /// The directory holding the generated Reticulum `config`.
    pub config_dir: PathBuf,
    /// The version pin (see [`DEFAULT_PINNED_RNSD_VERSION`]).
    pub pinned_version: String,
    /// Whether a version mismatch is permitted (development only).
    pub allow_version_drift: bool,
    /// The base restart backoff; doubles per consecutive failure, capped at
    /// [`BACKOFF_CAP_SECS`].
    pub restart_backoff: Duration,
    /// The TCP server interface (`host:port`) to template, if any.
    pub tcp_listen: Option<String>,
    /// The TCP client interfaces (`host:port`) to template.
    pub tcp_peers: Vec<String>,
}

impl SidecarConfig {
    /// The healthy-uptime threshold above which an exit resets the backoff.
    fn healthy_after(&self) -> Duration {
        Duration::from_secs(HEALTHY_AFTER_SECS)
    }

    /// The SIGTERM→SIGKILL grace on shutdown.
    fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(SHUTDOWN_GRACE_SECS)
    }
}

/// Runs the sidecar supervisor until `shutdown` is signalled.
///
/// Validates the `rnsd` version pin and generates the Reticulum config once, then
/// supervises the child: capturing its output, restarting it with backoff on
/// exit, and stopping it cleanly on shutdown. Any startup failure degrades to
/// [`SidecarState::Degraded`] and returns without ever propagating an error to
/// the daemon (ADR-0013: the sidecar's loss is a connectivity event, not fatal).
pub async fn supervise(
    cfg: SidecarConfig,
    state: Arc<ConnectivityState>,
    mut shutdown: watch::Receiver<bool>,
) {
    // 1. Version pin. A mismatch (or an unrunnable binary) degrades and returns:
    // appliance discipline runs *without* the carrier rather than with an
    // unpinned one.
    let version = match check_version(&cfg.rnsd_path).await {
        Ok(v) if matches_pin(&v, &cfg.pinned_version) => v,
        Ok(v) if cfg.allow_version_drift => {
            tracing::warn!(
                found = %v,
                pinned = %cfg.pinned_version,
                "rnsd version drift permitted by [sidecar] allow_version_drift; \
                 running an UNPINNED Reticulum carrier (development only)"
            );
            v
        }
        Ok(v) => {
            let reason = format!(
                "rnsd version {v} does not match pinned {} (set [sidecar] \
                 allow_version_drift for development)",
                cfg.pinned_version
            );
            tracing::warn!(%reason, "running degraded WITHOUT the Reticulum sidecar");
            state.set_sidecar(SidecarState::Degraded { reason });
            return;
        }
        Err(e) => {
            let reason = format!("cannot run `{} --version`: {e}", cfg.rnsd_path.display());
            tracing::warn!(%reason, "running degraded WITHOUT the Reticulum sidecar");
            state.set_sidecar(SidecarState::Degraded { reason });
            return;
        }
    };

    // 2. Generate the Reticulum config once (never overwrite an operator's edits).
    if let Err(e) =
        write_config_if_absent(&cfg.config_dir, cfg.tcp_listen.as_deref(), &cfg.tcp_peers)
    {
        let reason = format!(
            "cannot write Reticulum config in {}: {e}",
            cfg.config_dir.display()
        );
        tracing::warn!(%reason, "running degraded WITHOUT the Reticulum sidecar");
        state.set_sidecar(SidecarState::Degraded { reason });
        return;
    }

    // 3. Supervise loop: spawn, watch, restart with backoff, stop on shutdown.
    let mut attempt: u32 = 0;
    loop {
        if *shutdown.borrow() {
            break;
        }

        match spawn_rnsd(&cfg) {
            Ok(mut child) => {
                tracing::info!(
                    rnsd = %cfg.rnsd_path.display(),
                    version = %version,
                    config_dir = %cfg.config_dir.display(),
                    "Reticulum sidecar started"
                );
                state.set_sidecar(SidecarState::Running {
                    version: version.clone(),
                });
                capture_output(&mut child);
                let started = Instant::now();

                tokio::select! {
                    status = child.wait() => {
                        let ran = started.elapsed();
                        tracing::warn!(
                            ?status,
                            ran_secs = ran.as_secs(),
                            "rnsd exited; will restart after backoff"
                        );
                        // A child that stayed up counts as healthy: reset the
                        // backoff so a long-lived carrier that finally dies retries
                        // promptly, while a crash loop keeps climbing.
                        if ran >= cfg.healthy_after() {
                            attempt = 0;
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            stop_child(&mut child, cfg.shutdown_grace()).await;
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, rnsd = %cfg.rnsd_path.display(), "failed to spawn rnsd");
            }
        }

        // Back off before the next attempt, cut short by shutdown.
        attempt = attempt.saturating_add(1);
        let backoff = backoff_for(attempt, cfg.restart_backoff);
        state.set_sidecar(SidecarState::Restarting {
            attempt,
            backoff_secs: backoff.as_secs(),
        });
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    tracing::info!("Reticulum sidecar supervisor stopped");
}

/// Spawns `rnsd --config <dir>` with piped stdout/stderr, killed if the handle
/// drops.
fn spawn_rnsd(cfg: &SidecarConfig) -> std::io::Result<Child> {
    Command::new(&cfg.rnsd_path)
        .arg("--config")
        .arg(&cfg.config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
}

/// Drains the child's stdout and stderr into `tracing` on background tasks.
fn capture_output(child: &mut Child) {
    if let Some(out) = child.stdout.take() {
        tokio::spawn(drain(out, "stdout"));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(drain(err, "stderr"));
    }
}

/// Reads `reader` line by line into `tracing` at debug, tagged by `stream`.
async fn drain<R: AsyncRead + Unpin>(reader: R, stream: &'static str) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::debug!(target: "rnsd", stream, "{line}");
    }
}

/// Stops the child: SIGTERM for a graceful exit, then SIGKILL if it outlasts the
/// grace period.
async fn stop_child(child: &mut Child, grace: Duration) {
    tracing::info!(grace_secs = grace.as_secs(), "stopping Reticulum sidecar");
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
    }
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(_) => {}
        Err(_) => {
            tracing::warn!("rnsd did not exit within grace; sending SIGKILL");
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

/// Runs `rnsd --version` and extracts a dotted version. `rnsd` prints to stdout;
/// stderr is a fallback for builds that log it there.
async fn check_version(rnsd_path: &Path) -> std::io::Result<String> {
    let out = Command::new(rnsd_path).arg("--version").output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    extract_version(&stdout)
        .or_else(|| extract_version(&stderr))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "no version in `rnsd --version` output: {}",
                    stdout.trim().chars().take(200).collect::<String>()
                ),
            )
        })
}

/// Pulls the first dotted-numeric token (e.g. `0.9.6`) out of a `--version` line,
/// tolerating a leading `v` and trailing junk (`rnsd 0.9.6 (abc)` → `0.9.6`).
fn extract_version(text: &str) -> Option<String> {
    for tok in text.split_whitespace() {
        let v: String = tok
            .trim_start_matches('v')
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let mut parts = v.split('.');
        let major_ok = parts
            .next()
            .is_some_and(|f| !f.is_empty() && f.chars().all(|c| c.is_ascii_digit()));
        if major_ok && v.contains('.') {
            return Some(v);
        }
    }
    None
}

/// Whether `found` satisfies the `pin`. The pin is a dotted prefix — `"0.9"`
/// accepts any `0.9.x` — and a component of `x` or `*` is an explicit wildcard,
/// so `"0.9.x"` also accepts `0.9.6`. An empty pin accepts anything.
fn matches_pin(found: &str, pin: &str) -> bool {
    if pin.is_empty() {
        return true;
    }
    let fp: Vec<&str> = found.split('.').collect();
    let pp: Vec<&str> = pin.split('.').collect();
    if pp.len() > fp.len() {
        return false;
    }
    pp.iter()
        .zip(fp.iter())
        .all(|(p, f)| *p == "x" || *p == "*" || p == f)
}

/// The backoff for the `attempt`-th consecutive failure: `base * 2^(attempt-1)`,
/// capped at [`BACKOFF_CAP_SECS`].
fn backoff_for(attempt: u32, base: Duration) -> Duration {
    // Cap the shift below u32's 31-bit limit; `checked_mul` catches the rest and
    // the final `min` clamps to the ceiling regardless.
    let shift = attempt.saturating_sub(1).min(31);
    let scaled = base
        .checked_mul(1u32 << shift)
        .unwrap_or_else(|| Duration::from_secs(BACKOFF_CAP_SECS));
    scaled.min(Duration::from_secs(BACKOFF_CAP_SECS))
}

/// Writes the generated Reticulum config into `dir` if `dir/config` is absent,
/// creating `dir`. Returns the config path. Never overwrites an existing file —
/// an operator's hand-tuned config wins.
pub fn write_config_if_absent(
    dir: &Path,
    tcp_listen: Option<&str>,
    tcp_peers: &[String],
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(RETICULUM_CONFIG_FILE);
    if !path.exists() {
        std::fs::write(&path, render_reticulum_config(tcp_listen, tcp_peers))?;
    }
    Ok(path)
}

/// Renders a minimal Reticulum config (RNS ConfigObj format) with only the TCP
/// interfaces the station names — a server stanza for `tcp_listen` and one client
/// stanza per `tcp_peers` entry. The RNode/LoRa interface template is T2.6.3.
///
/// Transport forwarding and a shared instance are enabled: a station is a relay
/// node, and the shared instance's local control socket is what a later health
/// probe (`rnstatus`) and the T2.6.2 transport will speak to.
pub fn render_reticulum_config(tcp_listen: Option<&str>, tcp_peers: &[String]) -> String {
    let mut s = String::new();
    s.push_str(
        "# Generated by the Railroad Network station (T2.6.1, ADR-0013).\n\
         # Reticulum is a CARRIER ONLY: integrity and authenticity live in the\n\
         # app-layer sealed/signed envelopes, never in this transport. Edit to\n\
         # taste; the station regenerates this file only when it is absent.\n\n",
    );
    // Keys verified against the RNS 1.5 manual (using.html example config): a
    // relay node forwards (enable_transport), and the shared instance exposes the
    // local control socket that `rnstatus` and the T2.6.2 status probe query.
    s.push_str(
        "[reticulum]\n  \
         enable_transport = Yes\n  \
         share_instance = Yes\n  \
         shared_instance_port = 37428\n  \
         instance_control_port = 37429\n\n",
    );
    s.push_str("[logging]\n  loglevel = 4\n\n");
    s.push_str("[interfaces]\n\n");

    if let Some(listen) = tcp_listen {
        if let Some((ip, port)) = split_host_port(listen) {
            s.push_str(&format!(
                "  [[TCP Server Interface]]\n    \
                 type = TCPServerInterface\n    \
                 interface_enabled = True\n    \
                 listen_ip = {ip}\n    \
                 listen_port = {port}\n\n"
            ));
        }
    }

    for (i, peer) in tcp_peers.iter().enumerate() {
        if let Some((host, port)) = split_host_port(peer) {
            s.push_str(&format!(
                "  [[TCP Client Interface {n}]]\n    \
                 type = TCPClientInterface\n    \
                 interface_enabled = True\n    \
                 target_host = {host}\n    \
                 target_port = {port}\n\n",
                n = i + 1
            ));
        }
    }

    s
}

/// Splits `host:port` on the last colon, so IPv6 literals in brackets survive.
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- pure helpers ------------------------------------------------------

    #[test]
    fn extract_version_pulls_dotted_token() {
        assert_eq!(extract_version("rnsd 0.9.6").as_deref(), Some("0.9.6"));
        assert_eq!(extract_version("rnsd v0.9.6").as_deref(), Some("0.9.6"));
        assert_eq!(
            extract_version("Reticulum Network Stack 0.9.6 (rnsd)").as_deref(),
            Some("0.9.6")
        );
        assert_eq!(extract_version("0.9").as_deref(), Some("0.9"));
        // No dotted-numeric token.
        assert_eq!(extract_version("rnsd"), None);
        assert_eq!(extract_version(""), None);
    }

    #[test]
    fn pin_matching_is_a_dotted_prefix_with_wildcards() {
        assert!(matches_pin("0.9.6", "0.9"));
        assert!(matches_pin("0.9.6", "0.9.6"));
        assert!(matches_pin("0.9.6", "0.9.x"));
        assert!(matches_pin("0.9.6", "0.9.*"));
        assert!(matches_pin("0.9.6", "")); // empty pin accepts anything
                                           // Non-matches.
        assert!(!matches_pin("0.10.0", "0.9"));
        assert!(!matches_pin("0.9.6", "0.9.7"));
        assert!(!matches_pin("0.9", "0.9.6")); // pin longer than found
        assert!(!matches_pin("1.0.0", "0.9"));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let base = Duration::from_secs(5);
        assert_eq!(backoff_for(1, base), Duration::from_secs(5));
        assert_eq!(backoff_for(2, base), Duration::from_secs(10));
        assert_eq!(backoff_for(3, base), Duration::from_secs(20));
        assert_eq!(backoff_for(4, base), Duration::from_secs(40));
        // Climbs to the 300s ceiling and stays there (no overflow at high attempt).
        assert_eq!(backoff_for(20, base), Duration::from_secs(BACKOFF_CAP_SECS));
        assert_eq!(backoff_for(64, base), Duration::from_secs(BACKOFF_CAP_SECS));
    }

    // --- config template (step 2) -----------------------------------------

    #[test]
    fn config_template_renders_named_interfaces() {
        let cfg = render_reticulum_config(
            Some("0.0.0.0:4242"),
            &[
                "203.0.113.7:4242".to_string(),
                "198.51.100.9:5000".to_string(),
            ],
        );
        // Section headers RNS expects.
        assert!(cfg.contains("[reticulum]"));
        assert!(cfg.contains("[interfaces]"));
        assert!(cfg.contains("enable_transport = Yes"));
        // The server interface.
        assert!(cfg.contains("[[TCP Server Interface]]"));
        assert!(cfg.contains("type = TCPServerInterface"));
        assert!(cfg.contains("listen_ip = 0.0.0.0"));
        assert!(cfg.contains("listen_port = 4242"));
        // Both client interfaces.
        assert!(cfg.contains("type = TCPClientInterface"));
        assert!(cfg.contains("target_host = 203.0.113.7"));
        assert!(cfg.contains("target_port = 4242"));
        assert!(cfg.contains("target_host = 198.51.100.9"));
        assert!(cfg.contains("target_port = 5000"));
    }

    #[test]
    fn config_template_omits_absent_interfaces() {
        let cfg = render_reticulum_config(None, &[]);
        assert!(cfg.contains("[interfaces]"));
        assert!(!cfg.contains("TCPServerInterface"));
        assert!(!cfg.contains("TCPClientInterface"));
    }

    #[test]
    fn write_config_is_idempotent_and_never_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let cfgdir = dir.path().join("reticulum");
        let path = write_config_if_absent(&cfgdir, Some("0.0.0.0:4242"), &[]).unwrap();
        assert!(path.exists());
        assert_eq!(path.file_name().unwrap(), RETICULUM_CONFIG_FILE);
        // An operator edit survives a second call (absent-only write).
        std::fs::write(&path, "OPERATOR EDIT").unwrap();
        let again = write_config_if_absent(&cfgdir, Some("0.0.0.0:4242"), &[]).unwrap();
        assert_eq!(again, path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "OPERATOR EDIT");
    }

    // --- supervisor, against a fake `rnsd` shell script --------------------

    /// Writes an executable shell script standing in for `rnsd`.
    #[cfg(unix)]
    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.flush().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    fn test_cfg(rnsd: PathBuf, config_dir: PathBuf) -> SidecarConfig {
        SidecarConfig {
            rnsd_path: rnsd,
            config_dir,
            pinned_version: "1.5".to_string(),
            allow_version_drift: false,
            // Sub-second base so restart tests run in tens of milliseconds.
            restart_backoff: Duration::from_millis(20),
            tcp_listen: Some("127.0.0.1:4242".to_string()),
            tcp_peers: vec![],
        }
    }

    #[cfg(unix)]
    fn state_for() -> Arc<ConnectivityState> {
        Arc::new(ConnectivityState::new(vec![], "127.0.0.1:0".into(), false))
    }

    /// Spawns the supervisor and returns its join handle plus the shutdown sender.
    #[cfg(unix)]
    fn run_supervisor(
        cfg: SidecarConfig,
        state: Arc<ConnectivityState>,
    ) -> (tokio::task::JoinHandle<()>, watch::Sender<bool>) {
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(supervise(cfg, state, rx));
        (handle, tx)
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn version_mismatch_degrades_without_running() {
        let dir = tempfile::tempdir().unwrap();
        // A fake rnsd whose version does not match the "0.9" pin.
        let rnsd = write_script(
            dir.path(),
            "rnsd",
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"rnsd 0.1.0\"; exit 0; fi\nsleep 3600\n",
        );
        let state = state_for();
        let (handle, _tx) =
            run_supervisor(test_cfg(rnsd, dir.path().join("reticulum")), state.clone());
        // It should return promptly, having degraded.
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned")
            .unwrap();
        match state.sidecar_snapshot() {
            SidecarState::Degraded { reason } => assert!(reason.contains("0.1.0")),
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_binary_degrades() {
        let dir = tempfile::tempdir().unwrap();
        let rnsd = dir.path().join("does-not-exist");
        let state = state_for();
        let (handle, _tx) =
            run_supervisor(test_cfg(rnsd, dir.path().join("reticulum")), state.clone());
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned")
            .unwrap();
        assert!(matches!(
            state.sidecar_snapshot(),
            SidecarState::Degraded { .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drift_allowed_runs_and_writes_config() {
        let dir = tempfile::tempdir().unwrap();
        let rnsd = write_script(
            dir.path(),
            "rnsd",
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"rnsd 0.1.0\"; exit 0; fi\nsleep 3600\n",
        );
        let cfgdir = dir.path().join("reticulum");
        let mut cfg = test_cfg(rnsd, cfgdir.clone());
        cfg.allow_version_drift = true;
        let state = state_for();
        let (handle, tx) = run_supervisor(cfg, state.clone());
        // Wait for it to reach Running.
        wait_for(&state, Duration::from_secs(5), |s| {
            matches!(s, SidecarState::Running { .. })
        })
        .await;
        // The config was generated.
        assert!(cfgdir.join(RETICULUM_CONFIG_FILE).exists());
        // Clean shutdown.
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor stopped")
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crash_loop_backs_off_and_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("starts.log");
        // A fake rnsd that reports a matching version, records each run start,
        // then exits non-zero — a crash loop.
        let body = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"rnsd 1.5.2\"; exit 0; fi\n\
             echo start >> \"{}\"\nexit 1\n",
            counter.display()
        );
        let rnsd = write_script(dir.path(), "rnsd", &body);
        let state = state_for();
        let (handle, tx) =
            run_supervisor(test_cfg(rnsd, dir.path().join("reticulum")), state.clone());
        // Poll until the crash loop has restarted at least once (spawning real
        // shell processes is slow under a loaded test run, so wait rather than
        // fix a sleep). The 20ms base backoff keeps this well under the bound.
        let start = Instant::now();
        let mut starts = 0;
        while start.elapsed() < Duration::from_secs(10) {
            starts = std::fs::read_to_string(&counter)
                .map(|s| s.lines().count())
                .unwrap_or(0);
            if starts >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor stopped")
            .unwrap();
        assert!(
            starts >= 2,
            "expected the crash loop to restart at least once, saw {starts} start(s)"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_shutdown_stops_a_running_child() {
        let dir = tempfile::tempdir().unwrap();
        let rnsd = write_script(
            dir.path(),
            "rnsd",
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"rnsd 1.5.2\"; exit 0; fi\n\
             echo up\nwhile true; do sleep 0.05; done\n",
        );
        let state = state_for();
        let (handle, tx) =
            run_supervisor(test_cfg(rnsd, dir.path().join("reticulum")), state.clone());
        wait_for(&state, Duration::from_secs(5), |s| {
            matches!(s, SidecarState::Running { .. })
        })
        .await;
        tx.send(true).unwrap();
        // The supervisor must return promptly (well within the SIGTERM grace).
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor stopped after shutdown")
            .unwrap();
    }

    /// A fake child line reaches `tracing` at debug on target `rnsd`.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn child_output_is_captured_to_tracing() {
        use std::sync::{Arc as StdArc, Mutex};
        use tracing::Level;

        // A subscriber that appends formatted events into a shared buffer.
        #[derive(Clone)]
        struct BufWriter(StdArc<Mutex<Vec<u8>>>);
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
            type Writer = BufGuard;
            fn make_writer(&'a self) -> Self::Writer {
                BufGuard(self.0.clone())
            }
        }
        struct BufGuard(StdArc<Mutex<Vec<u8>>>);
        impl Write for BufGuard {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = StdArc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_writer(BufWriter(buf.clone()))
            .finish();
        // Single-threaded runtime: the drain task polls on this thread, so the
        // thread-local default subscriber applies to it.
        let _guard = tracing::subscriber::set_default(subscriber);

        // A pipe carrying one sentinel line, closed so the drain reaches EOF.
        let (mut w, r) = tokio::io::duplex(64);
        {
            use tokio::io::AsyncWriteExt;
            w.write_all(b"RNSD-SENTINEL up\n").await.unwrap();
            w.shutdown().await.unwrap();
        }
        drain(r, "stdout").await;

        let logged = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains("RNSD-SENTINEL up"),
            "sentinel not captured; log was: {logged}"
        );
    }

    /// Polls `state`'s sidecar snapshot until `pred` holds or the timeout elapses.
    #[cfg(unix)]
    async fn wait_for(
        state: &Arc<ConnectivityState>,
        timeout: Duration,
        pred: impl Fn(&SidecarState) -> bool,
    ) {
        let start = Instant::now();
        loop {
            if pred(&state.sidecar_snapshot()) {
                return;
            }
            if start.elapsed() > timeout {
                panic!(
                    "state did not satisfy predicate within {timeout:?}; last = {:?}",
                    state.sidecar_snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
