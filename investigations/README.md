# Incident Investigations

Full incident reports written to the standard of a Tier 1 SOC analyst's
investigation — alert triage, cross-source correlation, scoping, MITRE ATT&CK
mapping, impact assessment, and containment/recovery guidance. Each report is
built on **real telemetry** captured in `index=endpoint` during the lab's
detection validations (see [`../detections/`](../detections/README.md)); the
provenance of every report is disclosed inside it.

## Reports

| Incident | Type | Severity | Tactics / Techniques | Summary |
|---|---|---|---|---|
| [INC-2026-001](INC-2026-001-multistage-intrusion.md) | **Flagship — multi-stage intrusion** | Critical | 7 tactics / 10 techniques | Password spray → SMB lateral movement to SYSTEM → discovery → impair defenses → UAC bypass → credential theft (SAM + LSASS) → persistence → event-log clearing. The full kill chain on one host, reconstructed end to end. |
| [INC-2026-002](INC-2026-002-lsass-credential-dump.md) | Focused — single-alert triage | Critical | T1003.001 | LSASS memory dump via `comsvcs.dll` MiniDump. Fast, high-confidence triage of a Critical credential-theft alert (Phase 6b of INC-2026-001). |
| [INC-2026-003](INC-2026-003-discovery-burst.md) | Focused — triage judgment | Medium | T1087.001, T1082 | A clustered account/system reconnaissance burst — the alert where the value is the *judgment call* (recon vs. admin vs. inventory agent), including what would have made it benign (Phase 3 of INC-2026-001). |

## How these relate

INC-2026-001 is the anchor: a single end-to-end intrusion that chains most of the
lab's [13 validated detections](../detections/README.md). The two focused reports
zoom in on individual phases of that same intrusion to demonstrate the two ends of
the Tier 1 workload:

- **INC-2026-002** — the *slam-dunk Critical*: an alert that is malicious on sight,
  triaged and contained quickly.
- **INC-2026-003** — the *judgment call*: a lower-confidence, noisier signal that
  has to be reasoned about and either escalated or closed with justification.

## Method & honesty note

The lab is a single Windows endpoint, and the attack stages were validated as
separate exercises over several weeks. Where a report presents a unified incident
timeline (INC-2026-001), it says so explicitly and lists the true per-stage capture
dates in an appendix. No telemetry is fabricated — every IP, account, command,
event ID, access mask, and registry path is a real value from `index=endpoint`.

See the repository [root README](../README.md) for lab topology and build notes.
