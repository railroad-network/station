//! Seating the drawn jury, redrawing around jurors who go silent, and tallying.
//!
//! The panel is *derived*, deterministically, from three inputs: the sortition
//! order (who was drawn, in what sequence), the verdicts on the log, and the
//! clock. [`resolve_panel`] replays the seating forward from the dispute's open
//! time — the first [`panel_size`](crate::DisputeParams::panel_size) candidates
//! take their seats, and any who pass their response deadline without a valid
//! verdict are redrawn around, their seat handed to the next candidate in the
//! sequence (ADR-0014 §4). [`tally`] then reads the seated verdicts for a
//! majority.

use std::collections::HashMap;

use rrn_identity::address::Address;

use crate::DisputeParams;

/// One occupant of a panel seat.
#[derive(Clone, Debug)]
pub struct SeatedJuror {
    /// The juror in this seat.
    pub juror: Address,
    /// When they took the seat: the dispute's open time for the initial panel, or
    /// the moment the juror they replaced timed out.
    pub seated_at: i64,
    /// Their verdict, if they cast one within their window: `Some(true)` upholds,
    /// `Some(false)` rejects, `None` means still awaiting (or past deadline).
    pub verdict: Option<bool>,
}

/// The seated jury as of a moment in time — the occupied seats only (a seat the
/// sortition could not fill is simply absent).
#[derive(Clone, Debug, Default)]
pub struct Panel {
    /// The occupied seats.
    pub seats: Vec<SeatedJuror>,
}

impl Panel {
    /// The seat `juror` currently occupies, if any.
    pub fn seat_of(&self, juror: &Address) -> Option<&SeatedJuror> {
        self.seats.iter().find(|s| &s.juror == juror)
    }
}

/// A terminal ruling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisputeOutcome {
    /// A majority upheld the dispute: the confirmation was false, the transfer is
    /// voided.
    Upheld,
    /// A majority rejected the dispute: the confirmation stands, the transaction
    /// settles as proposed.
    Rejected,
}

/// Derives the seated jury as of `now` from the sortition `sequence`, the cast
/// `verdicts`, and the timing.
///
/// A candidate takes a seat at a known instant; their verdict counts only if cast
/// within `[seated_at, seated_at + juror_response_seconds]`. A seat whose occupant
/// lets that window close without a valid verdict is handed to the next unused
/// candidate, seated at the missed deadline — cascading deterministically until
/// the pool is exhausted or no more deadlines have passed as of `now`. Iterating
/// seats in index order gives the shared redraw queue a stable priority, so the
/// whole derivation is a pure function of its inputs.
pub fn resolve_panel(
    sequence: &[Address],
    verdicts: &HashMap<Address, (bool, i64)>,
    opened_at: i64,
    params: &DisputeParams,
    now: i64,
) -> Panel {
    let rw = params.juror_response_seconds;
    let mut seats: Vec<Option<SeatedJuror>> = Vec::with_capacity(params.panel_size);
    let mut cursor = 0usize; // next unused candidate in `sequence`

    // Seat the initial panel at the dispute's open time.
    for _ in 0..params.panel_size {
        if cursor < sequence.len() {
            seats.push(Some(SeatedJuror {
                juror: sequence[cursor],
                seated_at: opened_at,
                verdict: None,
            }));
            cursor += 1;
        } else {
            seats.push(None);
        }
    }

    // Resolve verdicts and redraw around no-shows until the panel is stable.
    loop {
        let mut changed = false;
        // Index access is deliberate: each pass may reassign a whole seat slot
        // (`seats[s] = ...`) and advance the shared redraw cursor, which an
        // iterator over the elements cannot express.
        #[allow(clippy::needless_range_loop)]
        for s in 0..seats.len() {
            let Some(occ) = seats[s].as_ref() else {
                continue;
            };
            if occ.verdict.is_some() {
                continue; // a responder is locked in
            }
            let (juror, seated_at) = (occ.juror, occ.seated_at);

            // Count a verdict only if cast inside this occupant's window and not in
            // the future relative to `now`.
            if let Some((uphold, cast_at)) = verdicts.get(&juror) {
                if *cast_at >= seated_at && *cast_at <= seated_at + rw && *cast_at <= now {
                    seats[s].as_mut().expect("seat occupied").verdict = Some(*uphold);
                    changed = true;
                    continue;
                }
            }

            // No valid verdict. Once the window has strictly closed, the seat is a
            // no-show and is redrawn from the queue (or left empty if exhausted).
            let deadline = seated_at + rw;
            if now > deadline {
                seats[s] = if cursor < sequence.len() {
                    let replacement = SeatedJuror {
                        juror: sequence[cursor],
                        seated_at: deadline,
                        verdict: None,
                    };
                    cursor += 1;
                    Some(replacement)
                } else {
                    None
                };
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    Panel {
        seats: seats.into_iter().flatten().collect(),
    }
}

/// The panel's ruling, if a majority of the full panel size has been reached.
/// `None` while the jury is still short of a majority — waiting on verdicts, or
/// hung.
///
/// The threshold is a majority of `panel_size` (2 of 3), so it can never be met
/// on both sides at once.
pub fn tally(panel: &Panel, params: &DisputeParams) -> Option<DisputeOutcome> {
    let uphold = panel
        .seats
        .iter()
        .filter(|s| s.verdict == Some(true))
        .count();
    let reject = panel
        .seats
        .iter()
        .filter(|s| s.verdict == Some(false))
        .count();
    let majority = params.panel_size / 2 + 1;
    if uphold >= majority {
        Some(DisputeOutcome::Upheld)
    } else if reject >= majority {
        Some(DisputeOutcome::Rejected)
    } else {
        None
    }
}
