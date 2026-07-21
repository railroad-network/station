//! The mobile-facing HTTP surface (ADR-0008).
//!
//! A plain-HTTP listener a mobile on the local network reaches, bound to the
//! `[mobile] listen` port that mDNS advertises (T1.3.2). Plain HTTP is
//! deliberate: the security boundary is the application-layer sealed-and-signed
//! envelope, not the transport, so TLS would buy a property we already produce
//! ourselves — see ADR-0008. Every handler forwards to the single-threaded
//! [`Core`](crate::core), so there is no shared-state race here either.
//!
//! Routes: `POST /pair` (T1.3.3), `POST /rpc` — the authenticated request channel
//! (T1.3.4) — and `POST /subscribe`, the long-poll for push-style updates
//! (T1.3.5). The subscribe handler is the one place a request is *held open*: it
//! authenticates through the core, then either returns pending events immediately
//! or parks on the core's log-tail signal (up to `subscribe_hold`) and returns
//! the moment a relevant event is appended. The wait lives here, never in the
//! core loop.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::core::{CoreHandle, SubscribeOutcome};
use crate::pairing::{PairError, PairRequest, PairResponse};
use crate::rpc_envelope::ChannelError;

/// Router state: the core handle plus how long a `/subscribe` is held open.
#[derive(Clone)]
struct AppState {
    core: CoreHandle,
    subscribe_hold: Duration,
}

/// Builds the router over a core handle and the subscribe hold duration.
fn app(core: CoreHandle, subscribe_hold: Duration) -> Router {
    Router::new()
        .route("/pair", post(pair))
        .route("/rpc", post(rpc))
        .route("/subscribe", post(subscribe))
        .with_state(AppState {
            core,
            subscribe_hold,
        })
}

/// Serves the mobile HTTP surface on `listener` until `shutdown` flips to true.
/// `subscribe_hold` is how long a long-poll waits before an empty heartbeat.
pub async fn serve(
    listener: TcpListener,
    core: CoreHandle,
    subscribe_hold: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let result = axum::serve(listener, app(core, subscribe_hold))
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
    State(state): State<AppState>,
    Json(request): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    match state.core.pair_request(request).await {
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
async fn rpc(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
    match state.core.rpc_request(body.to_vec()).await {
        Ok(sealed_reply) => Ok(sealed_reply),
        Err(e) => Err((channel_status(e), e.as_str().to_string())),
    }
}

/// `POST /subscribe` — a paired mobile's long-poll for push updates (T1.3.5).
///
/// Same sealed envelope as `/rpc` (method `subscribe`, params carry the
/// `last_seen_event_id` cursor). The handler authenticates through the core, then
/// either returns pending events immediately or parks on the log-tail signal
/// until an event is appended or `subscribe_hold` elapses (an empty heartbeat).
/// The response is the same sealed reply shape, carrying `{last_seen_event_id,
/// events}` as its result.
async fn subscribe(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let core = &state.core;
    match core.subscribe(body.to_vec()).await {
        Err(e) => Err((channel_status(e), e.as_str().to_string())),
        Ok(SubscribeOutcome::Ready(sealed)) => Ok(sealed),
        Ok(SubscribeOutcome::Waiting {
            member,
            member_pk,
            last_seen,
            nonce,
        }) => {
            let mut tail = core.log_tail_watch();
            let hold = tokio::time::sleep(state.subscribe_hold);
            tokio::pin!(hold);
            loop {
                tokio::select! {
                    _ = &mut hold => {
                        // Timeout: return a sealed empty heartbeat advancing the
                        // cursor. `None` here would only be a seal failure.
                        return match core
                            .poll_events(member, member_pk, last_seen, nonce, true)
                            .await
                        {
                            Some(sealed) => Ok(sealed),
                            None => Err((
                                StatusCode::SERVICE_UNAVAILABLE,
                                "could not seal subscribe reply".to_string(),
                            )),
                        };
                    }
                    changed = tail.changed() => {
                        if changed.is_err() {
                            // The core dropped the tail sender — shutting down.
                            return Err((
                                StatusCode::SERVICE_UNAVAILABLE,
                                "station unavailable".to_string(),
                            ));
                        }
                        if let Some(sealed) = core
                            .poll_events(member, member_pk, last_seen, nonce, false)
                            .await
                        {
                            return Ok(sealed);
                        }
                        // Tail advanced but nothing for this member — keep waiting.
                    }
                }
            }
        }
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
