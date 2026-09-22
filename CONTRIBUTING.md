# Contributing

Railroad Network is built by a single maintainer, with AI-assisted review, and
is **pre-audit**: Phases 0 through 2 (foundation, one community, single-community
resilience) are implemented, but the 90-day community pilot and the independent
professional security audit have not happened. Until that audit lands,
**unsolicited code contributions are not being merged.** Accepting outside
changes to a cryptographic and ledger codebase before it is audited would
expand the audit surface, and every merged line has to be defensible to the
auditors.

What is genuinely useful right now, in order:

1. **Run a pilot.** Twenty people, one station, play stakes, ninety days, and
   honest notes about what confused people. The guides at
   <https://railroad-network.github.io> are the runbook. Open an issue with
   what you learned.
2. **Report bugs and confusing behaviour**: open an issue with the commit, the
   command or screen, and what you expected.
3. **Fix the documentation.** The docs site
   ([`railroad-network.github.io`](https://github.com/railroad-network/railroad-network.github.io))
   takes pull requests; every page has an edit link. Corrections to the
   runbooks, specs, and threat model in this repo are welcome as pull requests
   too.
4. **Security issues**: never a public issue. See [SECURITY.md](SECURITY.md).

If you want to propose a code change anyway, open an issue describing it first
so the design can be settled (and an ADR written if it touches a locked
decision) before anyone writes code.

## Development workflow

For anyone building the workspace, including the maintainer:

```sh
cargo build --workspace
cargo nextest run --workspace                     # the test suite (install: cargo install cargo-nextest --locked)
cargo test --workspace --doc                      # doc-tests, which nextest skips
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo deny check && cargo audit                   # licenses, advisories, bans, CVEs
./scripts/install-hooks.sh                        # once: the pre-commit formatting hook
```

Conventions the code and docs follow:

- **No `unsafe` outside `rrn-crypto`.** A workspace-wide lint enforces it.
- **The log is the source of truth.** Balances, standing, tallies, and indexes
  are derived by replay and must be re-derivable. Caches are caches.
- **Anything signed goes through `SignedPayload<T>`**, signing the canonical
  CBOR bytes of the payload, never the wire envelope. A new signed record kind
  needs a distinct `kind` discriminator, a cross-platform CBOR fixture (the
  mobile repo verifies byte-identical encodings), and a threat-model section.
- **Amounts are integer centicommons.** Never a float in a signed payload.
- **Time is Unix seconds as `i64`**, injected as a parameter into ledger and
  settlement code so tests fast-forward without sleeping. Windows and
  electorates are anchored on the station's admission clock (ADR-0022).
- **Tests in layers:** unit tests per crate, `proptest` for anything with
  algebraic structure, cross-crate integration tests under `tests/`, each
  crate's integration tests compiled into one `it` binary, and fuzz targets
  under `fuzz/`.
- **Commits are lightweight conventional commits.** No ticket or milestone
  identifiers in source, comments, commit messages, or pull requests; cite the
  ADR or describe the behaviour. No AI session links in anything committed.

## Architecture Decision Records

Every locked design decision is an ADR in [`docs/adr/`](docs/adr/README.md),
in MADR format, append-only: a changed decision gets a new ADR that supersedes
the old one. A contribution that would change or introduce a locked decision
comes with an ADR, drafted from [`docs/adr/template.md`](docs/adr/template.md),
and the ADR is reviewed before the code. The threat model
([`docs/threat-model.md`](docs/threat-model.md)) grows alongside: each new
surface adds its STRIDE section and states plainly what it does not mitigate.

## DCO sign-off

All commits must carry a `Signed-off-by` line (the
[Developer Certificate of Origin](https://developercertificate.org/)), added
with `git commit -s`. It certifies that you have the right to submit the
contribution under the project's license.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the
project's dual [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT) license.
