# Security Policy

## Supported Versions

**None.** Railroad Network is pre-audit, research-stage software. Phases 0
through 2 are implemented and have had an internal AI-assisted security review
(see [Audit status](README.md#audit-status)), but no independent professional
audit. There are no supported releases and no release binaries; nothing here
should be used to hold, transfer, or represent anything of real value.

## Reporting a Vulnerability

If you believe you've found a security vulnerability in this project, in the
[`mobile`](https://github.com/railroad-network/mobile) app, or in the
documentation site, please **do not open a public GitHub issue, pull request,
or discussion**. Instead, email:

**security@railroad-network.org**

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof of concept if available
- The commit hash or version you tested against

### What to expect

- We aim to acknowledge reports within **5 business days**.
- We will work with you to understand and confirm the issue, and will let you
  know our intended timeline for a fix.
- Please give us a reasonable amount of time to address the issue before any
  public disclosure.

### What is already public

Per the project's open-source posture, every audit report is published, and
the threat model states plainly what is *not* mitigated:

- [`docs/security/audit-2026-08.md`](docs/security/audit-2026-08.md): the
  August 2026 internal review, with each finding's failure scenario.
- [`docs/security/phase-2-redteam.md`](docs/security/phase-2-redteam.md): the
  resilience-surface checklist, attacker by attacker.
- [`docs/threat-model.md`](docs/threat-model.md): the living STRIDE threat
  model, including the **Known limitations** section.

A report that a documented limitation is exploitable is still welcome; a
report that rediscovers one is best filed as an issue against the
documentation.

Thank you for helping keep Railroad Network and its users safe.
