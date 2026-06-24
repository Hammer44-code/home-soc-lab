# Home SOC Lab

A Tier 1 SOC Analyst portfolio project: a self-contained detection lab that
ingests Windows endpoint telemetry into Splunk, runs Atomic Red Team attack
simulations against it, and turns the resulting alerts into MITRE-mapped
detections and end-to-end incident reports.

> **Status: complete.** 13 validated MITRE-mapped detections (SPL + Sigma), 3
> full incident investigations, an automation toolkit, and a signature write-up —
> all built on real telemetry from a reproducible 3-VM lab.

---

## Why this project exists

Most entry-level SOC portfolios stop at "I installed Splunk." This one is built
to show the full Tier 1 workflow — detection writing, alert triage, incident
investigation, MITRE ATT&CK mapping, and clear written communication — using a
small, reproducible lab that anyone can stand up on a single 16 GB laptop.

## Stack

- **SIEM:** Splunk Free (Ubuntu Server)
- **Endpoint telemetry:** Sysmon with a SwiftOnSecurity-based config + Splunk Universal Forwarder
- **Victim:** Windows 10 Enterprise Evaluation
- **Attacker:** Kali Linux + Atomic Red Team / Invoke-AtomicRedTeam
- **Detection format:** Splunk SPL + Sigma YAML

## Repository layout

```
home-soc-lab/
├── README.md                 # You are here
├── LICENSE                   # MIT
├── setup/                    # Lab build guide, Sysmon config, UF inputs, diagram
├── detections/               # Per-technique detection write-ups (SPL + Sigma)
│   └── sigma/                # Vendor-neutral Sigma YAML rules
├── investigations/           # Full incident reports (INC-2026-00X)
├── scripts/                  # Python automation: detection runner + coverage generator
├── notes/                    # SPL cheatsheet and working notes
└── blog/                     # Signature long-form write-up
```

## Table of contents

- [Lab setup](./setup/README.md) — build guide, network design, Sysmon + UF config
- [Detection library](./detections/README.md) — 13 validated, MITRE-mapped detections (SPL + Sigma)
- [Coverage matrix](./detections/README.md#coverage) — techniques × tactics × severity × status
- [Incident reports](./investigations/README.md) — full Tier 1 investigations (1 flagship multi-stage intrusion + 2 focused)
- [Automation scripts](./scripts/README.md) — Splunk detection runner + coverage-matrix generator
- [Signature blog post](./blog/clearing-the-logs-told-me-when-you-panicked.md) — why log clearing is futile against a forwarding SIEM
- [SPL patterns cheatsheet](./notes/splunk-spl-cheatsheet.md) — the reusable SPL idioms behind the detections
- [What I learned](#what-i-learned)

## Skills demonstrated

- **SIEM querying & alert triage** — 13 Splunk SPL detections, each tuned through a
  validate-against-live-telemetry loop; triage judgment shown in
  [INC-2026-003](./investigations/INC-2026-003-discovery-burst.md) (escalating a
  noisy signal, and documenting what would have made it benign).
- **Detection engineering** — [13 detections](./detections/README.md) across 7
  ATT&CK tactics using a deliberate vocabulary of models (single signature, effect
  tripwire, burst correlation, weighted score, two-stage plant→trigger), plus
  portable [Sigma](./detections/sigma/) rules.
- **Incident investigation & reporting** — a flagship
  [end-to-end intrusion report](./investigations/INC-2026-001-multistage-intrusion.md)
  (10 techniques, unified timeline, cross-source correlation, containment) and two
  focused case reports.
- **Threat hunting & MITRE ATT&CK mapping** — every detection and incident mapped
  to ATT&CK tactics/techniques; validated with Atomic Red Team and live
  network-side attacks (NetExec password spray, smbexec).
- **Automation & scripting** — a Python [toolkit](./scripts/README.md): a Splunk
  REST detection-runner and a coverage-matrix generator that keeps docs honest.
- **Written communication** — detection write-ups, incident reports, and a
  [signature blog post](./blog/clearing-the-logs-told-me-when-you-panicked.md)
  pitched at both technical and non-technical readers.

## What I learned

A few lessons that this lab drove home harder than any course did:

- **Detection is downstream of architecture.** The single highest-leverage decision
  was forwarding logs off the host in real time — it's what made the attacker's
  log-clearing futile and preserved the full timeline. The blog post is the long
  version of this.
- **Detection writing is the last 20%.** I had a complete, tuned SPL before
  discovering Sysmon wasn't even logging the event class it needed. *Verify the data
  is in the index before iterating on the query* became rule zero.
- **Anchor on the effect, not the tool.** The OS writes an event when an action
  completes (EID 1102/104 for a log clear, EID 13 for a registry write, EID 7045
  for a service install) regardless of which tool an attacker used — keying on those
  is tool-agnostic and nearly evasion-proof.
- **Field *shape* is where detections quietly break.** Multivalued `User` fields,
  binaries logged by bare name (`net1` with no `.exe`), the `net.exe`→`net1.exe`
  wrapper, surgical access masks (`0x1410`, not `0x1FFFFF`) — most of my iteration
  loops were calibration against the real data's shape, not logic errors.
- **The boring control beats the clever query.** A Critical, SYSTEM-level,
  multi-stage intrusion began with one weak admin password. The best preventive
  control wasn't a detection — it was password policy and account lockout.

## Credits

- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — baseline Sysmon configuration.
- [Red Canary / Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — attack simulation library.
- [MITRE ATT&CK](https://attack.mitre.org/) — technique taxonomy used throughout.

## License

[MIT](./LICENSE).
