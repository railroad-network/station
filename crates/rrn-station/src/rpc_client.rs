//! Client side of the line-delimited JSON protocol, plus the shared codec.
//!
//! The `rrn` CLI uses [`UnixClient`] to call a running daemon; the gossip layer
//! reuses [`request_response`] over TCP to talk to peers (same envelope, a
//! different transport and method set). Keeping the read/write of one
//! `\n`-terminated JSON line in one place means the two transports cannot drift.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::rpc::{Request, Response};

/// Writes `request` as one JSON line, then reads exactly one JSON line back and
/// parses it as a [`Response`]. Works over any byte stream (Unix or TCP).
pub async fn request_response<S>(stream: &mut S, request: &Request) -> Result<Response>
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
    let mut buf = String::new();
    let n = reader
        .read_line(&mut buf)
        .await
        .context("read response line")?;
    if n == 0 {
        return Err(anyhow!("connection closed before a response was received"));
    }
    serde_json::from_str(buf.trim_end()).context("decode response")
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
        let response = request_response(&mut stream, &request).await?;

        if let Some(err) = response.error {
            return Err(anyhow!("{} (code {})", err.message, err.code));
        }
        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }
}
