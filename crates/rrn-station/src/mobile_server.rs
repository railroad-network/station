//! The mobile-facing HTTP surface (ADR-0008).
//!
//! A plain-HTTP listener a mobile on the local network reaches, bound to the
//! `[mobile] listen` port that mDNS advertises (T1.3.2). Plain HTTP is
//! deliberate: the security boundary is the application-layer sealed-and-signed
//! envelope, not the transport, so TLS would buy a property we already produce
//! ourselves — see ADR-0008. Every handler forwards to the single-threaded
//! [`Core`](crate::core), so there is no shared-state race here either.
//!
//! Today it exposes `POST /pair` (T1.3.3) and `POST /rpc`, the authenticated
//! request channel (T1.3.4). Long-poll updates (T1.3.5) add their route here.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::core::CoreHandle;
use crate::pairing::{PairError, PairRequest, PairResponse};
use crate::rpc_envelope::ChannelError;

/// Builds the router over a core handle.
fn app(core: CoreHandle) -> Router {
    Router::new()
        .route("/pair", post(pair))
        .route("/rpc", post(rpc))
        .with_state(core)
}

/// Serves the mobile HTTP surface on `listener` until `shutdown` flips to true.
pub async fn serve(listener: TcpListener, core: CoreHandle, mut shutdown: watch::Receiver<bool>) {
    let result = axum::serve(listener, app(core))
        .with_graceful_shutdown(async move {
            // Resolves when the station begins shutting down; ignore a dropped
            // sender (the station is going away regardless).
            let _ = shutdown.wait_for(|stopping| *stopping).await;
        })
        .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "mobile HTTP server stopped with an error");
    }
}

/// `POST /pair` — a mobile's one-time pairing request (T1.3.3).
///
/// A rejected request maps to `400 Bad Request` with a short reason (the mobile
/// shows it to the user); a core that is shutting down maps to `503`.
async fn pair(
    State(core): State<CoreHandle>,
    Json(request): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    match core.pair_request(request).await {
        Ok(response) => Ok(Json(response)),
        Err(PairError::Unavailable) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            PairError::Unavailable.as_str().to_string(),
        )),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.as_str().to_string())),
    }
}

/// `POST /rpc` — a paired mobile's authenticated request (T1.3.4).
///
/// The body is the opaque sealed envelope; the response body is the opaque
/// sealed reply. The transport is bytes in, bytes out — everything meaningful is
/// inside the seal (ADR-0008). An authentication failure maps to `401` (the
/// mobile is not, or not provably, a paired member); a malformed or
/// wrong-recipient envelope to `400`; a shutting-down core to `503`.
async fn rpc(State(core): State<CoreHandle>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
    match core.rpc_request(body.to_vec()).await {
        Ok(sealed_reply) => Ok(sealed_reply),
        Err(e) => Err((channel_status(e), e.as_str().to_string())),
    }
}

/// Maps a [`ChannelError`] to the HTTP status the mobile sees. Authentication
/// failures are `401`-equivalent; framing/addressing errors are `400`.
fn channel_status(e: ChannelError) -> StatusCode {
    match e {
        ChannelError::Sealed
        | ChannelError::BadSignature
        | ChannelError::NotPaired
        | ChannelError::StaleTimestamp
        | ChannelError::Replay => StatusCode::UNAUTHORIZED,
        ChannelError::Malformed
        | ChannelError::UnsupportedVersion
        | ChannelError::WrongRecipient => StatusCode::BAD_REQUEST,
        ChannelError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}
