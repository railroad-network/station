//! `FrameTransport` over the supervised Reticulum LXMF adapter (T2.6.2, ADR-0026 §3).
//!
//! ADR-0026 ratified the sidecar and found the decisive constraint: **RNS exposes
//! no language-neutral send/receive RPC**. The supported way to move an LXMF
//! message is the in-process Python `RNS` + `LXMF` API attaching to a running
//! `rnsd` shared instance. So the station drives a small, supervised **Python
//! adapter co-process** (`scripts/reticulum/lxmf_adapter.py`) over a local
//! length-prefixed binary pipe: hand it `{destination, opaque frame bytes}`, it
//! does the `LXMF.LXMessage` / `handle_outbound` dance; it hands back
//! `{source, opaque frame bytes}` on delivery. The adapter is carrier plumbing and
//! holds no RRN key — integrity stays in the app-layer sealed/signed envelopes the
//! [`DtnSyncer`](crate::dtn_sync) moves (ADR-0013).
//!
//! This module is the Rust half: the [line protocol](`codec`) (unit-tested) and
//! [`ReticulumTransport`], a [`FrameTransport`] that spawns the adapter, writes
//! outbound frames to its stdin, and drains inbound frames a background reader
//! thread collects from its stdout. The real end-to-end path (adapter ↔ `rnsd` ↔
//! `rnsd` ↔ adapter) is exercised in the T2.6.1 spike lane, extended by T2.6.2.

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};

use rrn_protocol::transport::{Endpoint, FrameTransport, TransportError, TransportProfile};

/// The shared inbound queue a background reader thread fills and `poll_recv` drains.
type Inbox = Arc<Mutex<VecDeque<(Endpoint, Vec<u8>)>>>;

/// The length-prefixed binary framing the station and the Python adapter speak
/// over the pipe. Each message is `u32` big-endian total body length, then the
/// body: a `u16` endpoint-string length, the endpoint (UTF-8 Reticulum
/// destination hex), then the raw carrier frame. Deliberately tiny and explicit
/// so the two languages cannot disagree about it.
pub mod codec {
    /// Encodes one `(endpoint, frame)` message. Same shape both directions
    /// (outbound `endpoint` = destination, inbound `endpoint` = source).
    pub fn encode(endpoint: &str, frame: &[u8]) -> Vec<u8> {
        let ep = endpoint.as_bytes();
        let body_len = 2 + ep.len() + frame.len();
        let mut out = Vec::with_capacity(4 + body_len);
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.extend_from_slice(&(ep.len() as u16).to_be_bytes());
        out.extend_from_slice(ep);
        out.extend_from_slice(frame);
        out
    }

    /// Reads one message from `r`, or `None` at clean EOF. Returns the endpoint
    /// string and the frame bytes. Refuses a body larger than `max_body` **before
    /// allocating it**, so a peer (or a buggy adapter) cannot make us allocate an
    /// arbitrary `u32` of memory per message.
    pub fn read_message<R: std::io::Read>(
        r: &mut R,
        max_body: usize,
    ) -> std::io::Result<Option<(String, Vec<u8>)>> {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let body_len = u32::from_be_bytes(len_buf) as usize;
        if body_len > max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("adapter message body {body_len} exceeds the {max_body}-byte cap"),
            ));
        }
        let mut body = vec![0u8; body_len];
        r.read_exact(&mut body)?;
        if body.len() < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "adapter message shorter than its endpoint-length prefix",
            ));
        }
        let ep_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + ep_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "adapter message endpoint length exceeds the message body",
            ));
        }
        let endpoint = String::from_utf8_lossy(&body[2..2 + ep_len]).into_owned();
        let frame = body[2 + ep_len..].to_vec();
        Ok(Some((endpoint, frame)))
    }
}

/// How to launch the Reticulum LXMF adapter co-process.
#[derive(Clone, Debug)]
pub struct AdapterConfig {
    /// The Python interpreter that has `rns` + `lxmf` (the pinned venv).
    pub python: PathBuf,
    /// The adapter script (`scripts/reticulum/lxmf_adapter.py`).
    pub script: PathBuf,
    /// The `rnsd` config dir the adapter attaches its shared instance to.
    pub config_dir: PathBuf,
    /// Where the adapter persists its LXMF identity (the reachability key — its
    /// custody is T2.9.1's at-rest scope, ADR-0026 §7).
    pub identity_path: PathBuf,
    /// The largest carrier frame, in bytes — the [`TransportProfile::max_frame_bytes`].
    pub max_frame_bytes: usize,
    /// Advisory sustained throughput for the airtime budgeter, or `None`.
    pub sustained_bytes_per_sec: Option<u32>,
}

/// A [`FrameTransport`] backed by the supervised Reticulum LXMF adapter.
///
/// Owns the adapter child: outbound [`send`](FrameTransport::send) writes to its
/// stdin; a background thread drains its stdout into a queue that
/// [`poll_recv`](FrameTransport::poll_recv) empties. A dead adapter surfaces as
/// [`TransportError::Backend`] — a connectivity event the [`DtnSyncer`](crate::dtn_sync)
/// tolerates, never a panic.
pub struct ReticulumTransport {
    child: Mutex<Child>,
    /// The adapter's stdin. `None` after shutdown takes it (dropping it EOFs the
    /// adapter's input so it can exit gracefully before the kill fallback).
    stdin: Mutex<Option<ChildStdin>>,
    inbox: Inbox,
    profile: TransportProfile,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl ReticulumTransport {
    /// Spawns the adapter and starts draining its output.
    pub fn spawn(cfg: AdapterConfig) -> std::io::Result<Self> {
        let mut child = Command::new(&cfg.python)
            .arg(&cfg.script)
            .arg("--config")
            .arg(&cfg.config_dir)
            .arg("--identity")
            .arg(&cfg.identity_path)
            .arg("--max-frame")
            .arg(cfg.max_frame_bytes.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.take().expect("adapter stdin piped");
        let mut stdout = child.stdout.take().expect("adapter stdout piped");
        let inbox: Inbox = Arc::new(Mutex::new(VecDeque::new()));
        // Capture the adapter's stderr into tracing so its diagnostics are visible.
        if let Some(err) = child.stderr.take() {
            std::thread::spawn(move || {
                use std::io::BufRead;
                let reader = std::io::BufReader::new(err);
                for line in reader.lines().map_while(std::io::Result::ok) {
                    tracing::debug!(target: "lxmf_adapter", "{line}");
                }
            });
        }
        // Drain stdout messages into the inbox, capping each at the frame budget
        // plus a small endpoint/prefix allowance so a runaway adapter cannot make
        // us allocate unboundedly.
        let inbox_reader = inbox.clone();
        let max_body = cfg.max_frame_bytes.saturating_add(2 + 128);
        let reader = std::thread::spawn(move || {
            // Ends on clean EOF or a read error: the adapter is gone, and
            // send/poll then surface the failure as a Backend error.
            while let Ok(Some((ep, frame))) = codec::read_message(&mut stdout, max_body) {
                inbox_reader
                    .lock()
                    .expect("adapter inbox mutex")
                    .push_back((Endpoint::new(ep), frame));
            }
        });

        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(Some(stdin)),
            inbox,
            profile: TransportProfile {
                max_frame_bytes: cfg.max_frame_bytes,
                sustained_bytes_per_sec: cfg.sustained_bytes_per_sec,
                lossy: true,
            },
            reader: Some(reader),
        })
    }

    /// Whether the adapter child is still running (a cheap, non-blocking check the
    /// daemon loop polls to decide when to re-spawn).
    pub fn is_alive(&self) -> bool {
        self.child
            .lock()
            .map(|mut c| matches!(c.try_wait(), Ok(None)))
            .unwrap_or(false)
    }

    /// Stops the adapter: closes its stdin (EOF → it should exit), waits a bounded
    /// grace, then **kills** it if it has not exited — so a wedged adapter cannot
    /// hang station shutdown. Bounded, unlike a bare `wait()`.
    pub fn shutdown(mut self) {
        self.stop_child();
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }

    /// Closes stdin, polls for exit up to a grace period, then kills.
    fn stop_child(&mut self) {
        // Take (drop) stdin → the adapter reaches EOF on its input and should exit.
        if let Ok(mut guard) = self.stdin.lock() {
            guard.take();
        }
        // Bounded wait: up to ~2s in 50ms polls, then SIGKILL via kill().
        if let Ok(mut child) = self.child.lock() {
            for _ in 0..40 {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                    Err(_) => break,
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ReticulumTransport {
    fn drop(&mut self) {
        // Belt-and-braces: never orphan the Python process, even on a panic path.
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.try_wait();
        }
    }
}

impl FrameTransport for ReticulumTransport {
    fn profile(&self) -> TransportProfile {
        self.profile
    }

    fn send(&self, to: &Endpoint, frame: Vec<u8>) -> Result<(), TransportError> {
        if frame.len() > self.profile.max_frame_bytes {
            return Err(TransportError::FrameTooLarge {
                found: frame.len(),
                max: self.profile.max_frame_bytes,
            });
        }
        let msg = codec::encode(&to.0, &frame);
        let mut guard = self.stdin.lock().expect("adapter stdin mutex");
        let stdin = guard
            .as_mut()
            .ok_or_else(|| TransportError::Backend("adapter stopped".into()))?;
        stdin
            .write_all(&msg)
            .and_then(|()| stdin.flush())
            .map_err(|e| TransportError::Backend(format!("adapter write failed: {e}")))
    }

    fn poll_recv(&self) -> Result<Vec<(Endpoint, Vec<u8>)>, TransportError> {
        let mut inbox = self.inbox.lock().expect("adapter inbox mutex");
        Ok(inbox.drain(..).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::codec;

    const MAX: usize = 4096;

    #[test]
    fn codec_roundtrips_one_message() {
        let msg = codec::encode("a1b2c3d4", b"\x00\x01\xff frame bytes");
        let mut cursor = std::io::Cursor::new(msg);
        let (ep, frame) = codec::read_message(&mut cursor, MAX).unwrap().unwrap();
        assert_eq!(ep, "a1b2c3d4");
        assert_eq!(frame, b"\x00\x01\xff frame bytes");
        // A second read hits clean EOF.
        assert_eq!(codec::read_message(&mut cursor, MAX).unwrap(), None);
    }

    #[test]
    fn codec_streams_multiple_messages_back_to_back() {
        let mut buf = codec::encode("aa", b"one");
        buf.extend(codec::encode("bb", b"two"));
        buf.extend(codec::encode("cc", b""));
        let mut cursor = std::io::Cursor::new(buf);
        let mut got = Vec::new();
        while let Some(m) = codec::read_message(&mut cursor, MAX).unwrap() {
            got.push(m);
        }
        assert_eq!(
            got,
            vec![
                ("aa".to_string(), b"one".to_vec()),
                ("bb".to_string(), b"two".to_vec()),
                ("cc".to_string(), Vec::new()),
            ]
        );
    }

    #[test]
    fn codec_rejects_a_truncated_body() {
        // A length prefix promising 10 body bytes, but only 3 follow.
        let mut buf = 10u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0, 1, 2]);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(codec::read_message(&mut cursor, MAX).is_err());
    }

    #[test]
    fn codec_rejects_an_oversize_body_before_allocating() {
        // A 1 GiB length prefix must be refused against the cap, not allocated.
        let buf = (1u32 << 30).to_be_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(buf);
        assert!(codec::read_message(&mut cursor, MAX).is_err());
    }
}
