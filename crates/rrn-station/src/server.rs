//! The Unix-socket RPC server the `rrn` CLI talks to.
//!
//! One line-delimited JSON request per line in, one response per line out (see
//! [`crate::rpc`]). Each accepted connection is handled concurrently, but every
//! request is forwarded to the single-threaded [`core`](crate::core), so there
//! is no shared-state race. A malformed line is answered with an
//! [`INVALID_REQUEST`](crate::rpc::INVALID_REQUEST) error and the connection
//! kept open — one bad line never takes down the daemon.
//!
//! The socket file is the authorization boundary: it is created with owner-only
//! permissions, so only the user who started the station can call it (there is
//! no in-band auth, by design — see the threat model).

use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::core::CoreHandle;
use crate::rpc::{self, Request, Response};

/// Binds a Unix listener at `path`, replacing any stale socket file, and sets
/// owner-only (`0o600`) permissions on it.
pub fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    // A leftover socket from a previous run would make bind fail with EADDRINUSE.
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    set_owner_only(path)?;
    Ok(listener)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Accepts CLI connections on `listener` until `shutdown` flips to `true`,
/// dispatching every request to `core`.
pub async fn serve(
    listener: UnixListener,
    core: CoreHandle,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let core = core.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, core).await {
                                tracing::debug!(error = %e, "CLI connection ended");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "CLI accept failed"),
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Handles one CLI connection: a stream of request lines, a response per line.
async fn handle_conn(stream: UnixStream, core: CoreHandle) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(()); // client closed
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(trimmed) {
            Ok(req) => {
                let id = req.id.clone();
                match core.call(req).await {
                    Ok(result) => Response::ok(id, result),
                    Err(err) => Response {
                        id,
                        result: None,
                        error: Some(err),
                    },
                }
            }
            Err(e) => Response::err("", rpc::INVALID_REQUEST, format!("malformed request: {e}")),
        };

        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        write_half.write_all(out.as_bytes()).await?;
        write_half.flush().await?;
    }
}
