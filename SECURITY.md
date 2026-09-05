# Security & responsible use

`mad-tools` is a battery for testing the reliability and security of AI agents. It is built to
**reproduce and measure**, not to weaponize.

## Rules of use

- Test **only** systems you own or are **explicitly authorized** to test (a bug-bounty program's
  defined scope, a signed engagement, or your own infrastructure).
- Before touching any external target, read that program's rules in full: scope, out-of-scope,
  **prohibited activities**, rate limits, and disclosure policy. Absence of an explicit rule is
  not permission.
- The synthetic subjects in this repo (`подопытный_*`, local doubles) are the intended default
  targets for learning and CI. They contain no real data and reach no external host.

## Reporting

Findings produced with this battery are meant for **responsible disclosure** to the affected
party, with reproduction steps and before/after numbers, and an explicit statement of what the
check does **not** prove.

## What this battery does not do

It does not exfiltrate data, establish persistence, evade detection, or maintain access. Probes
that touch a target send bounded, benign markers (canaries) and read the response; the verdict is
computed locally by code.
