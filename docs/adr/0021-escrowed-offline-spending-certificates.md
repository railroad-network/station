# 0021 — Escrowed offline spending certificates bound the debt floor under partition

## Status

Accepted

Date: 2026-08-26

## Context

ADR-0018's debt floor is enforced at the engine front door against a member's
*committed position* — settled balance minus every pending debit they have
signed. That check is sound because there is one front door and every
commitment passes through it promptly.

ADR-0020 keeps the single front door but makes submission delay-tolerant, which
opens a gap on the *receiver's* side: during a partition, a receiver who
accepts a signed proposal (and hands over the goods) is trusting that the
sender's debit will still clear the floor when it finally reaches the station.
It might not — the sender may have spent the same headroom with three other
receivers during the same outage, and whichever records arrive last are
refused. The refusal is correct from the ledger's point of view and ruinous
from the receiver's: they delivered value against a promise the system then
declined. The design overview names this the hard half of the exit criterion
("no limits violated on merge") and sketches the answer: an escrowed-headroom
design where capacity to commit while partitioned is *reserved ahead of time*
(§12, entrance criterion 1).

The forces:

- **Offline verification must be possible with nothing but the payload.** A
  receiver in a field with no connectivity can verify an Ed25519 signature and
  read a cap and an expiry; they cannot query anyone's balance.
- **Reservation must use machinery that already exists.** ADR-0018 already
  counts pending signed debits against headroom; a reservation that behaves
  exactly like a pending debit inherits every property of that arithmetic,
  including release-on-expiry.
- **A dishonest spender must be *provably* dishonest.** Refusing the fourth
  overspent record punishes the honest receiver holding it. The system cannot
  prevent offline double-spending (no connectivity, no coordination) — it can
  only make it bounded, attributable, and expensive. ADR-0020's outbox chains
  exist partly for this.
- **Bounded exposure, not zero exposure.** The community's worst case must be
  a known number, as the debt floor itself made walk-away loss a known number.

## Decision

**The station issues member-requested, station-signed, expiring, amount-capped
offline spending certificates. Issuing a certificate reserves its full cap
against the member's debt-floor headroom, exactly as a pending signed debit.
Spends that reference a certificate, within its cap and validity, are admitted
unconditionally on arrival — the headroom was paid for at issuance. Overspend
of a certificate is provable equivocation: the excess spend is refused, an
equivocation record is appended, a dispute opens automatically, and the
equivocation is a reputation event.**

Concretely:

1. **Issuance is a front-door operation while connected.** A member submits a
   signed `CertificateRequest { cap_centi, requested_at }`; the engine checks
   the cap against the member's current headroom (settled balance minus
   committed debits minus every *outstanding* certificate cap) and, if it
   fits, appends a station-signed `HeadroomCertificate { cert_id, member,
   cap_centi, issued_at, expires_at }` to the log. `cert_id` is the Blake3
   content address of the certificate. Validity defaults to 7 days
   (`[credit] cert_validity_seconds`), cap ≤ the Tier-2 single-transaction
   ceiling by default (`[credit] cert_max_cap_centi`) — offline trade is
   Tier-1/2 commerce, not exceptional transfers.
2. **Reservation is committed-position arithmetic.** An outstanding (unexpired,
   unreturned, not fully spent) certificate counts its *remaining* cap in
   `committed_debits_centi` for its member. Expiry releases the unspent
   remainder using the same boundary discipline as proposal expiry (ADR-0018
   point 2): past `expires_at` plus the DTN grace (point 4), the engine will
   never admit another spend against it, so the headroom frees. A member may
   also return a certificate early with a signed `CertificateReturn`, which
   releases the remainder once admitted.
3. **A certificate-backed spend names its certificate.** `TransactionProposal`
   gains an optional `cert_id` field — additive, omitted-when-`None` from the
   canonical CBOR, per the ADR-0010 discipline, so every existing proposal's
   content id is unchanged. A receiver verifying offline checks: the
   certificate's station signature, `member == proposal.sender`, spend amount
   ≤ cap, certificate unexpired at signing, and (against the certificate
   holder's presented spend history — see point 5) remaining allowance. The
   receiver's confirmation is their acceptance of that evidence.
4. **Admission honors the escrow.** A cert-backed proposal (and its
   confirmation) arriving within the certificate's validity plus a DTN
   delivery grace (`[credit] cert_delivery_grace_seconds`, default 14 days,
   judged by the admission clock per ADR-0022) is admitted **without a fresh
   floor check**, provided the certificate's cumulative admitted spend stays
   ≤ cap. The floor cannot be violated: the cap was subtracted from headroom at
   issuance. Note the proposal's own `expires_at` must also accommodate DTN
   delivery — wallets set it to at least the certificate validity when signing
   a cert-backed spend.
5. **Overspend is equivocation, and it is provable.** The station admits
   cert-referenced spends in arrival order until the cap is exhausted; a spend
   that would exceed the cap is refused
   (`Error::CertificateOverspent`) and, because both the admitted spends and
   the refused spend are member-signed against the same `cert_id`, their
   conjunction is a self-contained proof of deliberate double-commitment. The
   station appends a station-signed `EquivocationRecord { member, cert_id,
   evidence: [content hashes], recorded_at }`, which (a) automatically opens
   an ADR-0014 dispute on behalf of the stranded receiver, flowing to a jury
   like any other, and (b) is a scoring input under ADR-0009's locked formula
   revision accompanying this ADR. The same applies to an outbox-chain fork
   (two entries at one position — ADR-0020 point 2).
6. **Exposure is bounded and computable.** The honest-receiver worst case per
   incident is one refused spend ≤ `cert_max_cap_centi`; the community-level
   worst case is the sum of outstanding certificate caps, which is exactly the
   headroom already reserved — i.e. within the debt floor everyone already
   accepted. There is no new unbounded liability anywhere.
7. **Non-certificated records still flow.** Anything else signed offline
   (plain proposals, confirmations, votes, vouches) travels the same bundles
   and takes its chances at the ordinary front door in arrival order. The
   certificate is the opt-in instrument for *spending against delivery of
   value* while partitioned; a refused uncertificated spend is a nuisance, not
   a crisis, because the receiver knew it carried no escrow.

## Consequences

- **The exit criterion's hard half closes by construction.** No admission
  sequence — in any arrival order, after any partition — can land a member
  below the floor: uncertificated debits are floor-checked at admission, and
  certificated debits were floor-debited at issuance.
- **Going offline becomes a deliberate, visible act** — members top up
  certificates before a market day or a storm, which doubles as a legible
  operational ritual for the community ("check your paper credit before the
  outage drill").
- **Reserved headroom is idle headroom.** A member holding a 10-Common
  certificate has 10 Commons less to spend online. This is the escrow doing
  its job; wallets should surface remaining allowance and make return easy.
- **New locked surfaces.** Three new signed record kinds (request,
  certificate, return), one station record (equivocation), one additive
  proposal field, and an ADR-0009 scoring input — each needs kind
  discriminators, cross-platform CBOR fixtures, and threat-model sections.
- **The receiver's offline check is only as good as presented history.** A
  spender can hide earlier cert spends from a new receiver; the cap still
  bounds the damage and the proof still convicts. Receivers who care can
  demand the spender's outbox chain segment since issuance (gaps are visible).
  Stated plainly in the threat model.
- **Deliberate, bounded fraud is possible once per member.** A member can burn
  their standing to overspend one certificate by its cap. The equivocation
  proof, automatic dispute, and reputation consequence make it a
  once-per-community-lifetime trade nobody rational makes for ≤ 10 Commons.

## Alternatives Considered

- **Optimistic offline spending, merge policy only.** Refuse over-floor
  arrivals, let receivers dispute. Rejected as the default: it prices the
  partition risk onto exactly the party least able to assess it (the receiver),
  and turns every reconnect into a refusal lottery — corrosive to the trust a
  young community runs on. It survives as the fallback for uncertificated
  records (point 7).
- **Node-level headroom slices (bounded counter across writers).** The
  literal bounded-counter design. Moot under ADR-0020's single writer, and
  member-level escrow answers the actual failure mode (member equivocation),
  which node slices do not.
- **Receiver-side insurance pool instead of escrow.** A commons pool absorbs
  refused spends. Rejected: socializes fraud instead of preventing it, needs
  governance machinery that doesn't exist, and leaves exposure unbounded in
  incident count.
- **Bearer notes (blind-signed fixed denominations).** Cash-like, elegant,
  but a much larger cryptographic surface (blind signatures, double-spend DB),
  anonymity properties the vouch-based identity model deliberately does not
  want, and unnecessary when every spend is party-attributed anyway.
- **Hard-fail the whole bundle on any overspend.** Punishes every innocent
  record travelling with a guilty one; per-record outcomes in the delivery
  receipt (ADR-0020) are strictly better.

## References

- ADR-0018 — the debt floor; committed-position arithmetic and
  release-on-expiry, both reused here
- ADR-0020 — outbox chains (the equivocation evidence base), bundles,
  arrival-order admission
- ADR-0022 — the admission clock that judges certificate validity and grace
- ADR-0009 — the locked scoring formula this ADR extends with the
  equivocation input (revision recorded alongside)
- ADR-0014 — the dispute path an equivocation record auto-opens
- ADR-0010 — the additive-field / omit-when-`None` discipline `cert_id`
  follows
- Design overview §12 entrance criterion 1 (escrowed headroom), §3.1
- `crates/rrn-ledger/src/credit.rs`, `crates/rrn-ledger/src/engine.rs`
