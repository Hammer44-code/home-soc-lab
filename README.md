# Home SOC Lab

A Tier 1 SOC Analyst portfolio project: a self-contained detection lab that
ingests Windows endpoint telemetry into Splunk, runs Atomic Red Team attack
simulations against it, and turns the resulting alerts into MITRE-mapped
detections and end-to-end incident reports.

> **Status:** Sprint 1 — foundation and scaffolding. Detections, investigations,
> scripts, and the signature blog post land in later sprints.

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
├── investigations/           # Full incident reports (INC-2025-00X)
├── scripts/                  # Python / PowerShell automation helpers
├── notes/                    # SPL cheatsheet and working notes
└── blog/                     # Signature long-form write-up
```

## Table of contents

- [Lab setup](./setup/README.md) — build guide, network design, Sysmon + UF config
- Detection library — *TBD sprint 2-3*
- Coverage matrix — *TBD sprint 3*
- Incident reports — *TBD sprint 4*
- Automation scripts — *TBD sprint 5*
- Signature blog post — *TBD sprint 5*
- What I learned — *TBD sprint 5*

## Skills demonstrated

*Filled in progressively as each sprint lands artifacts. Final mapping in Sprint 5.*

- SIEM querying & alert triage — *TBD sprint 2*
- Detection engineering — *TBD sprint 2-3*
- Incident investigation & reporting — *TBD sprint 4*
- Threat hunting & MITRE ATT&CK mapping — *TBD sprint 3*
- Malware / network traffic analysis — *TBD sprint 4*
- Automation & scripting — *TBD sprint 5*

## Credits

- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — baseline Sysmon configuration.
- [Red Canary / Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — attack simulation library.
- [MITRE ATT&CK](https://attack.mitre.org/) — technique taxonomy used throughout.

## License

[MIT](./LICENSE).
