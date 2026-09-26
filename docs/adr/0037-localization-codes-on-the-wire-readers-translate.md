# 0037 — Localization: the wire carries codes, readers translate

## Status

Accepted — ratified 2026-09-25 (the maintainer delegated the ratification
review; it returned accept-with-changes and the changes are folded in — see
the ratification note below)

Date: 2026-09-25

> **Ratification note (2026-09-25).** Drafted from a survey of the three
> repos on 2026-09-25, then reviewed for ratification at the maintainer's
> delegation. The review's findings folded into this ADR: the slug rule is
> `<crate>.<enum>.<variant>` (variant names collide across the enums of one
> crate), wrapping and internal variants have no slug of their own, the trait
> lives in a new leaf crate `rrn-reason`, `params` carry only the requester's
> own data, the member device sends no locale in transport metadata
> (`Accept-Language`), catalogs are bundled and reviewed as code with a
> reviewer who reads the language for safety-critical strings,
> member-authored text is bidi-isolated and never shares a text node with an
> amount, fingerprints and addresses are rendered verbatim, the i18next
> catalog format is stated correctly (JSON v4, not ICU), and the CLI wallet
> is named as a documented pilot limitation rather than a localized reader.
> Implementation tickets are written against this ratified text.

## Context

Every human-facing surface of the platform is English-only today, and none of
them has a mechanism for being anything else:

- **The mobile app** (`../mobile`) carries roughly a thousand hand-written
  English strings, about four fifths of them in the main screens. Amounts,
  dates, relative times and plurals are formatted by hand in English; `Intl`
  is avoided on a stale premise (a comment in `src/ledger/format.ts` says
  Hermes "does not fully implement" it — Hermes has shipped
  `Intl.NumberFormat` and `Intl.DateTimeFormat` on both platforms for several
  major versions; the gaps are in the newer `Intl` APIs such as
  `PluralRules` and `RelativeTimeFormat`, which have small polyfills). Station
  error text is shown to members verbatim in about seventeen places, and
  twenty-two regular expressions match English words in those messages to
  choose friendlier copy.
- **The station's RPC surfaces** (operator socket and the sealed mobile
  channel) report failures as a JSON-RPC `{code, message}` with only five
  numeric codes; every business refusal — debt floor, tier, certificate
  limits, marketplace rules — is `INVALID_PARAMS` plus the `Display` text of a
  data-bearing domain error enum. The message is documented as "not meant to
  be machine-matched", and the app machine-matches it anyway because it has
  nothing else.
- **The `rrn` CLI** builds its text-mode output inline in `format!` closures
  (eighty-seven of them), documents that output as greppable, and has a stable
  `--format json` mode beside it.
- **Paper artifacts** (`rrn paper render`) emit QR sheets with almost no
  prose, through a hand-rolled PDF writer that uses unembedded Helvetica and
  replaces every non-ASCII character with `?` — so even an accented Latin name
  on a credential card breaks today.
- **The docs site** is a single-language mdBook.

The platform is meant for self-organizing communities anywhere, and the
90-day pilot may well be run by one whose members do not read English. Two
facts about the existing design make this tractable and shape the decision:

1. **Nothing signed carries station-written prose.** A refused delivery
   receipt carries a `RefusalReason` from a closed set of twenty slugs
   (ADR-0020, `docs/spec/dtn-bundles.md` §"Refusal reasons"), explicitly
   "never free text, so a receipt reader on any platform can branch". The
   mobile FFI's six error enums (thirty-six variants) and its
   `OfflineSpendVerdict` (fourteen variants) are typed. The ceremony and VMK
   fingerprints (ADR-0016, ADR-0024) are language-neutral codes. The one
   exception is the sealed-channel `ResponseEnvelope`, which is station-signed
   over its exact JSON bytes and carries the free-text `error.message`.
2. **The station does not know the member's language, and must not need
   to.** A member's locale is a property of their device (ADR-0006, ADR-0028:
   the member device is the only key holder and the only thing the member
   interacts with). A station serves a whole community, is often a read-only
   replica of another community's log (ADR-0020 §7), and forwards receipts
   through couriers, radio and paper that never see a locale. Localizing at
   the station would push every member's language preference into the
   channel, into the log, or into the courier path.

## Decision

**Localization is a reader-side concern. Every machine-generated message that
can reach a member is identified on the wire by a stable code, and each
localized reader (the mobile app and the docs site now; the CLI wallet when
a follow-up ADR adopts Fluent) renders that code in the reader's own language
from a catalog it ships.** No signed payload, log
record, receipt, bundle, or RPC error ever carries localized text, and no
component ever selects a language on another party's behalf. Nine
sub-decisions follow.

### 1. RPC errors gain a stable `reason` slug and structured `params`

`RpcError` (operator socket, `rrn-station::rpc`) and `ResponseError` (the
sealed mobile channel, `rrn-station::rpc_envelope`) each gain two optional,
additive fields:

```jsonc
{ "code": -32602,
  "message": "debt floor exceeded: this debit would take the projected balance to -2350 centicommons, below the floor of -2000",
  "reason": "ledger.debt_floor_exceeded",
  "params": { "floor_centi": -2000, "projected_centi": -2350 } }
```

- `reason` is `<crate>.<enum>.<variant>` in snake_case, where `<enum>` is
  the error enum's name minus its `Error` suffix and a crate with a single
  `Error` enum omits the middle segment: `rrn_ledger::Error::DebtFloorExceeded`
  → `ledger.debt_floor_exceeded`;
  `rrn_marketplace::LifecycleError::CloseNotPermitted` →
  `marketplace.lifecycle.close_not_permitted`. The middle segment is required
  because variant names repeat across the enums of one crate with different
  meanings (`CloseNotPermitted` on an inquiry vs. a listing, `UnknownProposal`
  in three governance enums). A workspace test asserts every emitted slug is
  unique. Slugs use dots and snake_case; the receipt refusal slugs are kebab
  (`bad-signature`) and the two registries differ deliberately — they are
  different code sets with different signers.
- **A variant that merely wraps another error type** (`#[from]`,
  `#[error(transparent)]`) has no slug of its own: its `reason` and `params`
  are the inner error's, so `rrn_dispute::Error::Ledger(DebtFloorExceeded)`
  reports `ledger.debt_floor_exceeded`. **Variants that wrap storage, I/O,
  SQLite, CBOR or a free `String`** are internal failures: `reason =
  "station.internal"`, no `params`, whatever crate they came from — an
  internal boundary is never a translation key. A refusal that is not a
  domain error (a literal `invalid_params("…")` in the station) gets a slug
  from a station-owned `station.*` list. Slugs are **append-only and never
  renamed**: they are the translation keys every reader depends on.
- The slug trait lives in a **new leaf crate `rrn-reason`** (depends only on
  `serde_json`; no `rrn-*` dependency; no `unsafe`), beside `rrn-crypto` at
  the bottom of the graph, so every domain crate including `rrn-protocol`
  can implement it without adding a JSON dependency to the storage layer or
  touching the audit boundary.
- `params` carries the enum variant's data fields, by their Rust names, as
  JSON — integers as integers, amounts as centicommons, times as Unix seconds
  — so a reader can format them in its own locale. `params` never carries
  prose, and carries **only fields the refused record itself named or that
  concern the requester**: never another member's data, a filesystem path, a
  key, or SQL text. Today every data-bearing variant already interpolates its
  fields into `message`, so this adds no exposure; the rule binds future
  variants.
- `message` stays exactly what it is: English diagnostic text for logs and
  the operator console, still not for machine matching. Readers that have a
  translation for `reason` must not display `message`; readers that do not
  (an unknown slug from a newer station) fall back to a generic localized
  sentence *and* may show `message` as diagnostic detail.
- Both fields are `#[serde(default, skip_serializing_if = "Option::is_none")]`
  so an older client reads a newer station and vice versa. The
  `ResponseEnvelope` is signed at generation time over the bytes that include
  them, which is fine: the mobile and the CLI wallet's channel client both
  verify the bytes they received and never re-serialize (`rpc_envelope.rs`,
  the type's doc-comment; `rrn-cli`'s `channel_client.rs`). The envelope
  version does not change. The channel error plumbing on both sides —
  the station's `(code, message)` tuples and the wallet's
  `ChannelClientError::Method` — is widened to carry the two fields, which
  is a source change, not a wire change.
- The slug registry is published in `docs/spec/rpc-error-reasons.md`,
  generated from the code, and is the third machine-stable code set beside
  the receipt refusal slugs and the FFI error variants.

### 2. Nothing else on the wire changes

`RefusalReason` slugs, FFI error variants, `OfflineSpendVerdict`, the
`ReceiptOutcome` strings, and the reputation band names are already codes;
they stay byte-identical, and the readers translate them. No signed record
gains a language field. Server-built English summaries inside RPC *results*
(`history` row text, `receipt_summary`) are operator-console conveniences;
the app must not display them to members and must build its own from the
structured fields beside them. Byte limits on member-authored signed text
(memo 2048 bytes, titles 200, descriptions 8 KiB) stay as they are; the app
shows the remaining budget in bytes of UTF-8 — a non-Latin script spends two
to four bytes per character — never a Latin-only character count.

Member-authored text is rendered in an **isolating bidirectional run**
(Unicode FSI…PDI or the platform equivalent) and **never shares a text node
with an amount**, so a memo carrying right-to-left override characters
cannot visually reorder a sign or digits once right-to-left layout is
enabled; bidi control characters are stripped at entry on the member
device. The station keeps accepting any UTF-8 (the log is not a display
surface). **Fingerprints, ceremony codes and `rrn1…` addresses are rendered
verbatim**, never through `Intl` or a catalog string, and the ceremony
instructions in every language say to read Latin letters and digits
(ADR-0016, ADR-0024).

### 3. The mobile app is the first localized reader

The app adopts a message catalog (i18next with react-i18next; JSON v4
catalogs per screen group — named `{{placeholders}}`, plural forms as
`_zero/_one/_two/_few/_many/_other` key suffixes selected by
`Intl.PluralRules`, `context` suffixes for gender and case; keys extracted
by tooling and checked complete in CI). Language follows the device
locale by default, with an override in Settings that is stored on-device
only. Sentences are whole messages with named placeholders, never assembled
from fragments, and never case-transformed after translation. A lint rule
forbids new raw text in JSX. The existing English becomes the `en` catalog
and the test suite keeps rendering it, so the roughly six hundred English-literal
assertions stay meaningful.

### 4. Numbers, money, dates and plurals go through `Intl`

Amounts remain signed integer centicommons everywhere (repository
conventions); the *display* of a centicommon value is `Intl.NumberFormat`
over `centi / 100` with two fixed fraction digits, and "Commons" / `₡` is a
catalog string, not a literal. Amount *entry* accepts the locale's decimal
separator and grouping and is parsed back to integer centi without ever
touching a float in a signed payload. Dates use `Intl.DateTimeFormat`;
relative times and plurals use `Intl.RelativeTimeFormat` and
`Intl.PluralRules`, polyfilled from `@formatjs` where the bundled Hermes
lacks them. The mobile foundation ticket verifies each of these on an
Android and an iOS device build before the catalog work starts, and records
which polyfills were needed, since the comment in `format.ts` was written
for a reason.

### 5. Paper artifacts stay language-neutral; the PDF stays ASCII

QR sheets carry codes, chunk indices and a member-visible summary line; they
carry no instructions (the instructions live in the app and the docs, which
are localized). The credential card's printed `name` is documented as
ASCII-only until a separate decision embeds a Unicode-capable font in the
PDF writer — that writer is a deliberately small audit surface (ADR-0021's
paper path) and font embedding is not worth its audit cost on the current
evidence. `rrn paper credential` warns when a `--name` would be degraded.

### 6. The docs site is translated per language with gettext

The mdBook adopts `mdbook-i18n-helpers` (a release compatible with the
site's pinned mdBook 0.5, pinned in the workflow): English Markdown stays the
source,
each language is a `po/<lang>.po`, and the site builds one book per
language under `/<lang>/`. Untranslated paragraphs fall back to English
rather than vanishing. The generated command and ADR reference pages are
excluded from translation.

### 7. The CLI stays English for now; JSON is the stable interface

`rrn` help text, text-mode output, the `station` console, the boot and
recovery ceremonies, and every `bail!` stay English in this decision.
`--format json` is the interface scripts and other readers depend on;
text mode is a rendering of it. If the `rrn wallet` member device needs a
second language for a laptop-member community, a follow-up ADR adopts
Fluent (`fluent-bundle`) for the `wallet` subcommand family only, selected by
an `RRN_LANG` override over the process locale. Until then, a member on a
CLI wallet in a non-English community is a documented limitation of the
pilot. The operator surfaces are not planned for translation.

### 8. Language is never a protocol input, and never transport metadata

No record, receipt, envelope, treaty (ADR-0030) or federation profile
(ADR-0029) carries a language tag, and nothing derives ordering, windows,
electorates or matching (ADR-0036) from one. A community may *state* its
working languages in its charter text or listing descriptions for people to
read; that text is content, not a field. Display formatting of admission-clock
timestamps (§4) computes nothing: every window and deadline stays the
station's (ADR-0022).

The member device sends no locale in transport metadata either. The sealed
channel runs over plain local HTTP (ADR-0008), and some platform HTTP stacks
add an `Accept-Language` header from the device's preferred languages by
default; the channel client sets that header explicitly to a fixed value (or
omits it where the platform allows), and the station never reads or logs it.
Locale is a fingerprinting signal to a LAN observer (an ADR-0008 residual)
and must not become one because of this decision.

### 9. Catalogs are code

Catalogs are bundled with the app build and the site build and are never
fetched at runtime (no i18next backend plugin, no remote `.po`). They sit
inside the same trust boundary as the code they ship with. A translation
change is reviewed like code, and strings tagged **safety-critical** —
fingerprint and ceremony-code comparison, backup and recovery, debt-floor
and equivocation warnings, amount signs and the "you are paying / you are
receiving" copy — require a reviewer who reads the target language before
merge. The threat model gains a Localization section covering catalog
tampering, locale as a fingerprinting signal, and bidi control characters in
member-authored text.

## Consequences

**Easier**

- The app can be translated by editing catalogs, with no station change per
  language and no protocol change ever.
- Station refusals become machine-readable for every reader at once: the
  CLI wallet, the app, and any future client branch on `reason` and format
  `params`, and the twenty-two English regular expressions in the app go
  away. This is a correctness improvement even for English.
- The "codes not prose" rule already stated for receipts becomes a
  workspace-wide invariant a reviewer can grep for: a new refusal without a
  slug is a review finding.

**Harder / costs**

- The slug registry is a compatibility surface. Renaming a domain error
  variant now changes a public key; the generated spec page and a test that
  pins the registry make that visible.
- The app carries a catalog, an i18n runtime, and `Intl` polyfills plus
  per-locale data on both platforms until the foundation ticket's device
  check proves otherwise; the runtime cost is measured there and expected to
  be tens of kilobytes plus locale data.
- Text-length assumptions in the app (forty-seven `numberOfLines`
  truncations, a few fixed widths) become visible as soon as a longer
  language ships; the RTL work (`marginStart`, mirrored chevrons) is small
  but real, and `I18nManager` is enabled only when the first RTL locale is
  actually shipped.
- Two known limitations become documented rather than fixed: the ASCII-only
  credential-card name, and the English-only CLI including the CLI wallet
  (ADR-0028's member device for a member who owns only a laptop).
- Translation review needs a human who reads each shipped language; a
  language without such a reviewer cannot ship (§9).

**Follow-up work** (ticketed): the station slug fields, the `rrn-reason`
crate and the registry; the threat-model Localization section; the app
catalog foundation, formatting, extraction, error mapping, native shells and
RTL readiness; the docs-site gettext pipeline; and the first non-English
locale end to end, in a language the maintainer chooses.

## Alternatives Considered

- **Localize at the station** (a `lang` field on the channel handshake, the
  station rendering `message` in the member's language). Rejected: it puts
  the member's language on a signed envelope and into station logs, it
  cannot reach paper, radio or courier-carried receipts, a read replica has
  no idea who its readers are, and every language ships as a station
  release instead of an app release.
- **Keep matching `message` text, but stabilize the English.** Rejected: it
  makes the English message a protocol, which is what the doc-comment on
  `RpcError` already tells us not to do, and it still leaves `params`
  unavailable for locale-aware formatting.
- **Encode the slug in the numeric `code`** (one JSON-RPC server-error code
  per refusal). Rejected: the `-32000..-32099` range is a hundred values,
  the domain enums already have three hundred variants between them, and a
  number is a worse translation key than a name.
- **Lingui or react-intl instead of i18next.** Either would do; i18next is
  chosen for its React Native maturity, its namespace loading, and the size
  of its tooling ecosystem. Lingui and react-intl use ICU MessageFormat;
  i18next uses its own JSON v4 form. The trade is a slightly less expressive
  plural syntax for a smaller runtime and no message-format parser at
  runtime. The catalog format is the decision that matters for translators,
  and it is stated in §3.
- **A hand-rolled formatting layer with per-locale tables instead of
  `Intl`.** Rejected: it is what the app has now, in one language, and it
  cannot be made correct for the plural and number rules of languages the
  project has not chosen yet.
- **Embedding a font in the PDF writer now.** Deferred, not rejected: a
  CID-keyed TrueType subset with a ToUnicode map is several hundred lines in
  an audit surface, for a field (the printed name) that is a convenience on
  a card whose QR payload is the real credential.
- **Translating the CLI in this decision.** Deferred: the CLI's readers are
  operators and couriers; the greppable text mode is an interface for
  scripts; and a Fluent adoption is a separate, contained decision.

## References

- ADR-0006 (member device and FFI surface), ADR-0008 (the sealed channel
  over plain local HTTP and its LAN-observer residual), ADR-0028 (the CLI
  member wallet)
- ADR-0020 §7 and `docs/spec/dtn-bundles.md` (receipt refusal slugs)
- ADR-0016, ADR-0024 (language-neutral ceremony fingerprints)
- ADR-0021 (offline spending certificates and the paper path)
- `crates/rrn-station/src/rpc.rs`, `crates/rrn-station/src/rpc_envelope.rs`
  (the error types this ADR extends)
- `crates/rrn-mobile-ffi/src/rrn_mobile_ffi.udl` (the typed error enums)
- mdBook `mdbook-i18n-helpers` (the docs-site pipeline)
