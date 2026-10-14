//! Client side of the line-delimited JSON protocol, plus the shared codec.
//!
//! The `rrn` CLI uses [`UnixClient`] to call a running daemon; the gossip layer
//! reuses [`request_response`] over TCP to talk to peers (same envelope, a
//! different transport and method set). Keeping the read/write of one
//! `\n`-terminated JSON line in one place means the two transports cannot drift.
//!
//! Every line is read through [`read_line_bounded`] with a per-surface cap
//! (the constants below): a peer that never sends `\n` cannot grow a buffer
//! without limit on either side of any line-JSON connection.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rrn_protocol::bundle::MAX_BUNDLE_BYTES;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::UnixStream;

use crate::rpc::{Request, Response};

/// Longest request line the peer port reads. Peer requests are three tiny
/// methods (`peer_handshake`, `log_tail`, `log_range`).
pub const PEER_REQUEST_LINE_LIMIT: usize = 4 * 1024;

/// Longest request line the owner-only Unix socket reads. The largest local
/// request is `bundle_submit` carrying a DTN bundle of up to
/// [`MAX_BUNDLE_BYTES`] hex-encoded (≈ 2×), plus headroom for the envelope —
/// the same worst case the mobile channel's body limit is sized to.
pub const LOCAL_REQUEST_LINE_LIMIT: usize = MAX_BUNDLE_BYTES * 2 + 256 * 1024;

/// Longest response line a replica reads from a peer. Any log entry entered
/// through a surface bounded by [`LOCAL_REQUEST_LINE_LIMIT`] fits, even though
/// a [`WireEntry`](crate::gossip::WireEntry) serializes bytes as JSON number
/// arrays (at most 4 bytes of JSON per byte), with headroom for the envelope.
pub const PEER_RESPONSE_LINE_LIMIT: usize = 4 * LOCAL_REQUEST_LINE_LIMIT + 1024 * 1024;

/// Longest response line the CLI reads from its own daemon — a sanity bound,
/// not a protocol limit.
pub const LOCAL_RESPONSE_LINE_LIMIT: usize = 64 * 1024 * 1024;

/// How long the peer port waits for each request line before closing the
/// connection without a reply.
pub const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Concurrent peer-port connections served at once; a connection accepted
/// while all are in use is dropped immediately.
pub const MAX_PEER_CONNECTIONS: usize = 8;

/// Most entries one `log_range` page serves; a caller's `limit` is clamped to
/// `1..=MAX_LOG_RANGE_ENTRIES`.
pub const MAX_LOG_RANGE_ENTRIES: u32 = 256;

/// Payload-byte budget of one `log_range` page (the sum of the entries' signed
/// bytes). A page always carries at least one entry, so an entry larger than
/// the budget is still served, alone.
pub const MAX_LOG_RANGE_PAGE_BYTES: usize = 1024 * 1024;

/// Most `log_range` pages a replica pulls from one peer in one gossip round.
pub const MAX_PAGES_PER_ROUND: usize = 64;

/// Why [`read_line_bounded`] could not produce a line.
#[derive(Debug, thiserror::Error)]
pub enum LineError {
    /// More than `max` bytes arrived without a newline.
    #[error("line exceeds {max} bytes")]
    TooLong {
        /// The cap that was exceeded.
        max: usize,
    },
    /// The line was not valid UTF-8.
    #[error("line is not valid UTF-8")]
    NotUtf8,
    /// The underlying read failed.
    #[error("read failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads one `\n`-terminated line of at most `max` bytes (excluding the
/// newline) into `buf`, which is cleared first. Returns the byte count read
/// (`0` = EOF before any byte). A line that reaches `max + 1` bytes without a
/// newline is [`LineError::TooLong`] — the caller cannot resynchronize and
/// should close; a final unterminated line at EOF is returned as read. The
/// bytes are checked as UTF-8 so a caller can `std::str::from_utf8` them
/// without a second failure mode.
pub async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> Result<usize, LineError> {
    buf.clear();
    // `max` content bytes plus the terminating newline.
    let n = (&mut *r)
        .take(max as u64 + 1)
        .read_until(b'\n', buf)
        .await?;
    // At most `max + 1` bytes were read: a full budget with no newline in it
    // means the line is longer than `max`.
    if n > max && !buf.ends_with(b"\n") {
        return Err(LineError::TooLong { max });
    }
    if std::str::from_utf8(buf).is_err() {
        return Err(LineError::NotUtf8);
    }
    Ok(n)
}

/// Writes `request` as one JSON line, then reads exactly one JSON line of at
/// most `max_line` bytes back and parses it as a [`Response`]. Works over any
/// byte stream (Unix or TCP).
pub async fn request_response<S>(
    stream: &mut S,
    request: &Request,
    max_line: usize,
) -> Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line = serde_json::to_string(request).context("encode request")?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .await
        .context("write request")?;
    stream.flush().await.context("flush request")?;

    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    let n = read_line_bounded(&mut reader, &mut buf, max_line)
        .await
        .context("read response line")?;
    if n == 0 {
        return Err(anyhow!("connection closed before a response was received"));
    }
    let text = std::str::from_utf8(&buf).context("decode response")?;
    serde_json::from_str(text.trim_end()).context("decode response")
}

/// A thin RPC client over a daemon's Unix socket. Each call opens a fresh
/// connection — Phase 0 favours simplicity over connection reuse.
pub struct UnixClient {
    socket: PathBuf,
}

impl UnixClient {
    /// Targets the daemon listening at `socket`.
    pub fn new(socket: impl AsRef<Path>) -> Self {
        UnixClient {
            socket: socket.as_ref().to_path_buf(),
        }
    }

    /// Calls `method` with `params`, returning the `result` value on success or
    /// an error carrying the daemon's `error.message` on failure.
    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let request = Request {
            id: uuid::Uuid::new_v4().to_string(),
            method: method.to_string(),
            params,
        };
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connect to station socket {}", self.socket.display()))?;
        let response = request_response(&mut stream, &request, LOCAL_RESPONSE_LINE_LIMIT).await?;

        if let Some(err) = response.error {
            return Err(anyhow!("{} (code {})", err.message, err.code));
        }
        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Feeds `input` through a duplex pipe (then closes it) and reads lines
    /// with cap `max` until EOF or an error.
    async fn read_all(input: &[u8], max: usize) -> Vec<Result<Vec<u8>, String>> {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        let owned = input.to_vec();
        let writer = tokio::spawn(async move {
            tx.write_all(&owned).await.unwrap();
            tx.shutdown().await.unwrap();
        });
        let mut reader = BufReader::new(rx);
        let mut out = Vec::new();
        let mut buf = Vec::new();
        loop {
            match read_line_bounded(&mut reader, &mut buf, max).await {
                Ok(0) => break,
                Ok(_) => out.push(Ok(buf.clone())),
                Err(e) => {
                    out.push(Err(format!("{e:?}")));
                    break;
                }
            }
        }
        writer.await.unwrap();
        out
    }

    #[tokio::test]
    async fn read_line_bounded_caps_and_eofs() {
        // A line of exactly `max` bytes plus its newline is accepted.
        let max = 16;
        let mut exact = vec![b'a'; max];
        exact.push(b'\n');
        let got = read_all(&exact, max).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref().unwrap(), &exact);

        // A final line of exactly `max` bytes with no newline is returned at EOF.
        let got = read_all(&vec![b'b'; max], max).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref().unwrap().len(), max);

        // Two lines in one stream are read one at a time.
        let got = read_all(b"one\ntwo\n", max).await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].as_ref().unwrap(), b"two\n");

        // `max + 1` bytes without a newline is too long — even with more to come.
        let over = vec![b'a'; max + 1];
        let got = read_all(&over, max).await;
        assert_eq!(got.len(), 1);
        assert!(got[0].as_ref().unwrap_err().contains("TooLong"), "{got:?}");
        let mut far_over = vec![b'a'; max * 8];
        far_over.push(b'\n');
        let got = read_all(&far_over, max).await;
        assert!(got[0].as_ref().unwrap_err().contains("TooLong"), "{got:?}");

        // Non-UTF-8 is refused as such.
        let got = read_all(b"\xff\xfe\n", max).await;
        assert!(got[0].as_ref().unwrap_err().contains("NotUtf8"), "{got:?}");

        // EOF before any byte reads as 0 (no lines).
        assert!(read_all(b"", max).await.is_empty());
    }

    #[test]
    fn peer_response_cap_fits_the_largest_entry() {
        // The largest entry any bounded surface can admit carries fewer payload
        // bytes than one local request line; 0xff is the widest byte as a JSON
        // number (`255,`).
        let entry = crate::gossip::WireEntry {
            signer: vec![0xff; 32],
            signature: vec![0xff; 64],
            bytes: vec![0xff; LOCAL_REQUEST_LINE_LIMIT],
        };
        let result = crate::gossip::LogRangeResult {
            entries: vec![entry],
            next_from_seq: u64::MAX,
        };
        let response = Response::ok(
            uuid::Uuid::new_v4().to_string(),
            serde_json::to_value(&result).unwrap(),
        );
        let line = serde_json::to_string(&response).unwrap();
        assert!(
            line.len() <= PEER_RESPONSE_LINE_LIMIT,
            "response line {} exceeds the cap {PEER_RESPONSE_LINE_LIMIT}",
            line.len()
        );
    }
}
