# Security policy

ReD-Pot is a security tool: it is *meant* to be attacked. Bugs that matter are the ones that let an attacker
**escape the decoy**, **reach the manager**, **tamper with alerts**, or **use ReD-Pot against your own network**.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security problems.
E-mail **info@redsidesecurity.com** with:

- what you found and which version / commit,
- steps to reproduce (a proof of concept helps),
- the impact you believe it has.

We answer within 5 working days and credit researchers in the release notes, unless you prefer to stay anonymous.

## In scope

- code execution inside or outside a decoy container,
- reaching the manager UI / sensor API from a decoy, or bypassing authentication,
- spoofing events for another sensor, forging or suppressing alerts,
- crashing a decoy or the manager with crafted traffic,
- leaking bait plaintext, keys or admin secrets from a sensor.

## Out of scope

- "the decoy can be identified as a honeypot" (please do tell us how, but as a normal issue),
- attacks that need root on the manager host,
- findings in the lab bridge mode that the README already lists as residual.
