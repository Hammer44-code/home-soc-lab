# Home SOC Lab — Sprint Execution Plan

## Context

The source doc `/home/nolan/cybersec-showcase/soc_detection_lab/IMPLEMENTATION_PLAN.md` lays out a 5-week Home SOC Lab project (Splunk + Sysmon + Atomic Red Team) targeting a Tier 1 SOC Analyst portfolio. This document translates that plan into discrete sprints Claude Code can execute across multiple sessions.

**Split of responsibility** (clarified with user):
- **Claude Code ("CC")** scaffolds the repo: directory structure, config files, detection write-ups with sample events, investigation report drafts, Sigma rules, automation scripts, blog post, README.
- **User** executes the physical lab: installs VMs, runs Atomic Red Team, captures real screenshots, validates SPL against live data, then pastes real log samples back for CC to integrate.
- **Sample-data policy**: CC fabricates realistic Sysmon/Windows event samples so every deliverable is complete-looking on first pass. User swaps in real data in later sprints as the lab comes online.

**Repo layout**: scaffold at `/home/nolan/cybersec-showcase/soc_detection_lab/home-soc-lab/` (nested subfolder, keeps IMPLEMENTATION_PLAN.md at parent level). Git init inside the subfolder during Sprint 1.

**Sprint cadence**: 5 sprints, one per week in the source plan. Each sprint is resumable — CC can pick up mid-sprint across sessions by reading the sprint's checklist.

---

## Sprint Format (how to read each sprint)

Every sprint below has:
- **Goal** — one-sentence outcome.
- **CC tasks** — what Claude Code does this sprint.
- **User tasks** — what the user does in parallel (lab work CC can't do).
- **Handoff** — explicit points where CC needs real data from the user, or the user needs CC's artifacts to proceed.
- **Deliverables** — concrete files/paths produced.
- **Exit criteria** — how CC and user agree the sprint is done.

---

## Sprint 1 — Foundation & Scaffolding

**Goal:** Lay down the repo skeleton, author all setup/config artifacts, and give the user a clear build guide for the VM lab.

### CC tasks
1. Create repo at `home-soc-lab/` with directory tree per IMPLEMENTATION_PLAN.md §"Final Repo Structure" (setup/, detections/sigma/, investigations/, scripts/, notes/, blog/).
2. `git init` inside `home-soc-lab/`, add `.gitignore` (ignore screenshots subfolder staging, OS junk, local creds).
3. Write `/setup/README.md` — full lab build instructions derived from §"Week 1 — Lab Foundation" (hardware budget table, network design, IP scheme, step-by-step for Ubuntu/Splunk, Windows/Sysmon/UF, Kali).
4. Write `/setup/sysmon-config.xml` — a commented wrapper that pulls SwiftOnSecurity's config (with clear provenance/credit and a note on licensing).
5. Write `/setup/splunk-inputs.conf` — UF stanza shipping the four log channels listed in the plan.
6. Write `/setup/architecture-diagram.md` — mermaid/ASCII diagram (user will export to PNG later with draw.io).
7. Stub `/README.md` at repo root — title, one-paragraph purpose, TOC matching final structure, placeholder sections marked `TBD sprint N`.
8. Add `LICENSE` (MIT).
9. Commit in logical chunks (scaffold, setup docs, license) so git history shows steady progress.

### User tasks (parallel track)
- Install VirtualBox/VMware.
- Build Ubuntu Server VM, install Splunk Free, create `endpoint` index.
- Build Windows 10 Eval VM, install Sysmon + UF using CC's `splunk-inputs.conf` and `sysmon-config.xml`.
- Build Kali VM.
- Verify ingestion: `index=endpoint | stats count by sourcetype` returns WinEventLog entries.
- Capture 3-4 screenshots into `/setup/screenshots/` proving logs flow.

### Handoff
- **User → CC** at end of sprint: paste one raw Sysmon EID 1 event and one Security EID 4624 event from the real lab into chat. CC uses these to calibrate field names (some Splunk versions rename fields e.g. `CommandLine` vs `process.command_line`) before Sprint 2 SPL authoring.

### Deliverables
- `home-soc-lab/` repo initialized with git history.
- `/setup/README.md`, `sysmon-config.xml`, `splunk-inputs.conf`, `architecture-diagram.md`.
- `/README.md` stub + `LICENSE`.

### Exit criteria
- `git log` shows 3+ commits.
- User confirms lab ingestion is working (or flags blockers).
- CC has a real sample event to calibrate against.

---

## Sprint 2 — Detection Engineering Foundations (3 detections + cheatsheet)

**Goal:** Ship the first 3 detection write-ups with real (or sample) events, plus an SPL cheatsheet.

### CC tasks
1. Write `/notes/splunk-spl-cheatsheet.md` — commands from §"Week 2" task 2, grouped by purpose (search/filter, aggregation, time, extraction). Include 5-8 working example queries.
2. Author 3 detection write-ups using the §"Detection Write-Up Template":
   - `/detections/T1059.001-powershell-encoded.md`
   - `/detections/T1003.001-lsass-access.md`
   - `/detections/T1053.005-scheduled-task.md`
3. For each detection: MITRE mapping, severity, full SPL (starter SPL from the plan, refined with field names from Sprint 1 handoff), "why it works", false-positive profile, Atomic Red Team test command, fabricated sample event block (marked clearly as representative until user swaps in real log).
4. Stub `/detections/README.md` with coverage-matrix table header — will be expanded in Sprint 3.
5. Commit each detection individually so git history reflects iterative work.

### User tasks (parallel track)
- Install Atomic Red Team + Invoke-AtomicRedTeam on Windows victim.
- Execute `T1059.001`, `T1003.001`, `T1053.005` one at a time, noting wall-clock timestamps.
- Validate each of CC's SPL queries returns hits in Splunk. Tune field names if needed.
- Capture screenshots of each detection firing → `/detections/screenshots/`.
- Paste 1 real log sample per technique back to CC.

### Handoff
- **User → CC**: real log sample per technique.
- **CC → User** (on receipt): replaces fabricated sample-event blocks in the 3 detection files with real ones; adjusts SPL if field names differ.

### Deliverables
- 3 detection markdowns following the template exactly.
- `/notes/splunk-spl-cheatsheet.md`.
- Coverage-matrix stub in `/detections/README.md`.

### Exit criteria
- Each of the 3 detections has been validated to fire in real Splunk.
- Real log samples embedded in write-ups.
- 3+ commits in the sprint.

---

## Sprint 3 — Detection Library & Sigma (expand to 10-12 + 2 Sigma rules)

**Goal:** Round out the detection library across all MITRE tactics listed in §"Week 3", add 2 Sigma rules, finalize the coverage matrix.

### CC tasks
1. Author remaining detection write-ups (same template) to cover the tactics table in §"Week 3":
   - `/detections/T1547.001-registry-run-keys.md` (Persistence)
   - `/detections/T1548.002-uac-bypass.md` (Priv Esc)
   - `/detections/T1070.001-clear-event-logs.md` (Defense Evasion)
   - `/detections/T1562.001-disable-defender.md` (Defense Evasion)
   - `/detections/T1003.002-sam-registry-dump.md` (Cred Access)
   - `/detections/T1087-account-discovery.md` (Discovery)
   - `/detections/T1082-system-info-discovery.md` (Discovery)
   - `/detections/T1021.002-smb-admin-shares.md` (Lateral Movement)
   - `/detections/T1059.003-cmd-execution.md` (Execution — second per tactic)
2. Write 2 Sigma rules in `/detections/sigma/`:
   - `clear-event-logs.yml` (T1070.001)
   - `lsass-unusual-parent.yml` (T1003.001)
   - Include both YAML source and a comment block showing the `sigma convert` output for Splunk.
3. Build the coverage matrix in `/detections/README.md` — table with columns: Detection File | Technique | Tactic | Severity | Status. Row per detection. Reference it from main `/README.md`.
4. Each detection uses fabricated-but-plausible sample events; user swaps in real ones as they test.
5. Commit per detection (10+ commits this sprint).

### User tasks (parallel track)
- Execute each corresponding Atomic Red Team test on victim VM, staggered so Splunk correlation stays clean.
- Validate SPL fires.
- Capture screenshots per detection.
- Tune any FP cases — report findings back so CC can add notes to each write-up.

### Handoff
- **User → CC**: any SPL that fails to fire, FP examples encountered, real log samples.
- **CC → User**: updated write-ups with real samples + FP notes.

### Deliverables
- 10-12 total detection write-ups.
- 2 Sigma YAML rules + converted SPL.
- Finalized `/detections/README.md` coverage matrix.
- `/detections/screenshots/` with evidence per technique.

### Exit criteria
- Coverage matrix covers every MITRE tactic in the §"Week 3" table.
- Every detection has been fired end-to-end at least once in the real lab.

---

## Sprint 4 — Incident Investigation Write-Ups (3 scenarios)

**Goal:** Produce three full-length incident reports using the §"Investigation Report Template", picking one as the "showcase."

### CC tasks
1. Author all three reports under `/investigations/`:
   - `INC-2025-001-phishing-to-persistence.md` (Scenario 1)
   - `INC-2025-002-credential-theft-chain.md` (Scenario 2 — **showcase**, most polish)
   - `INC-2025-003-lotl-reconnaissance.md` (Scenario 3)
2. Each report follows the template exactly: executive summary, initial alert, timeline, technical analysis (process tree, network, file artifacts), IOC table, MITRE mapping, impact assessment, containment/remediation, detection gaps.
3. Use fabricated-but-realistic artifacts (process trees, IPs from the 192.168.56.0/24 range per the plan, SHA256 placeholders tagged clearly as lab-synthetic).
4. For the showcase (INC-002), include extra depth: more detailed timeline, more IOCs, a short sidebar "what I'd have missed without the Defender-disable detection", a stronger lessons-learned section.
5. Cross-link each report from the main `/README.md` with a one-sentence summary.
6. Commit per report.

### User tasks (parallel track)
- Execute each full attack chain end-to-end on the lab VMs (chain the individual atomic tests so telemetry is contiguous).
- Follow CC's report as a map: pivot the alerts in Splunk, capture screenshots for (a) initial alert, (b) process tree, (c) timeline — at minimum 3 per report.
- Note any deviation between CC's fabricated artifacts and real observations; report deltas back.

### Handoff
- **User → CC** per scenario: real timestamps, process tree screenshots, actual IOCs (hashes, file paths, command lines).
- **CC → User**: reports updated in-place with real data replacing synthetic artifacts.

### Deliverables
- 3 investigation reports (showcase polished further than the other two).
- `/investigations/screenshots/` with 3+ images per scenario.

### Exit criteria
- All three reports pass a readability test: a non-technical reader can follow the executive summary, and a technical reader can reproduce the investigation from the timeline + SPL.
- Showcase report cross-linked from main README as the primary narrative.

---

## Sprint 5 — Polish, Automation & Signature Blog Post

**Goal:** Ship scripts, blog post, polished README, tag `v1.0`.

### CC tasks
1. Write automation scripts in `/scripts/`:
   - `parse-sysmon-iocs.py` (Python) — reads Sysmon JSON/XML, extracts hashes/IPs/filenames to CSV. 30-80 lines with header comment.
   - `splunk-alert-triage.ps1` (PowerShell) — given a hostname, pulls recent process events and outputs a timeline.
   - `atomic-test-runner.ps1` (optional) — wrapper that paces ART tests with sleeps so Splunk correlation is clean.
2. Write the signature blog post `/blog/lsass-detection-deep-dive.md` (~1500-2500 words) following the 6-section structure in §"Week 5": threat → artifacts → detection (line-by-line SPL) → FP profile → evasion discussion → further reading.
3. Polish `/README.md` main: purpose, architecture diagram embed, skills-demonstrated list mapped to repo sections, coverage matrix pulled in, investigation-report links, blog link, honest "What I Learned" section (leave as a checklist of prompts for the user to fill — CC can draft placeholder bullets but user should personalize).
4. Final pass: every detection/investigation screenshot readable, no secrets/API keys/personal data in repo, LICENSE present.
5. Tag `v1.0` on the final commit. Draft release notes.

### User tasks (parallel track)
- Test both scripts against real Sysmon data from the lab; report bugs.
- Publish the blog post to Medium/dev.to/personal site; send back the live URL so CC can swap it into README.
- Personalize "What I Learned" section with real reflections from weeks 1-4.
- Do a final "interview readiness" pass: can you narrate one investigation as a story?

### Handoff
- **User → CC**: blog post live URL; any script bugs.
- **CC → User**: README link updated; scripts fixed.

### Deliverables
- `/scripts/parse-sysmon-iocs.py`, `/scripts/splunk-alert-triage.ps1` (+ optional runner).
- `/blog/lsass-detection-deep-dive.md` + live URL linked from main README.
- Polished main `/README.md`.
- `v1.0` tag.

### Exit criteria
- `v1.0` tag pushed.
- Main README passes the "storefront test": a hiring manager reading only the README understands what the project is and can find the strongest evidence within 30 seconds.
- No secrets committed (CC grep-checks for common patterns before tag).

---

## Critical Files Produced (cross-sprint map)

| Path | Sprint | Notes |
|---|---|---|
| `home-soc-lab/README.md` | 1 stub → 5 polish | Grows each sprint |
| `home-soc-lab/LICENSE` | 1 | MIT |
| `home-soc-lab/.gitignore` | 1 | OS + IDE noise |
| `/setup/README.md` | 1 | Build guide |
| `/setup/sysmon-config.xml` | 1 | SwiftOnSecurity-based |
| `/setup/splunk-inputs.conf` | 1 | UF channels |
| `/setup/architecture-diagram.md` | 1 | User exports to PNG |
| `/notes/splunk-spl-cheatsheet.md` | 2 | |
| `/detections/*.md` (10-12) | 2-3 | Per template |
| `/detections/README.md` | 2 stub → 3 final | Coverage matrix |
| `/detections/sigma/*.yml` (2) | 3 | |
| `/investigations/INC-2025-00[1-3]-*.md` | 4 | Showcase = INC-002 |
| `/scripts/parse-sysmon-iocs.py` | 5 | |
| `/scripts/splunk-alert-triage.ps1` | 5 | |
| `/blog/lsass-detection-deep-dive.md` | 5 | ~1500-2500 words |

## Templates to Reuse (verbatim from IMPLEMENTATION_PLAN.md §"Templates")

- **Detection Write-Up Template** — MITRE / Severity / SPL / Why / FP / Test / Sample / Refs. Reuse for every file in `/detections/`.
- **Investigation Report Template** — Exec summary / Initial alert / Timeline / Technical analysis / IOCs / MITRE / Impact / Remediation / Gaps. Reuse for every file in `/investigations/`.

No need to re-author these — the source plan's templates are already well-formed.

## Verification (end-to-end)

Run at the end of each sprint:

1. **Structural**: `tree home-soc-lab/` matches the target tree for that sprint.
2. **Git**: `git log --oneline` shows 3+ commits that sprint (plan principle #1: "Commit as you go").
3. **Deliverables checklist**: every checkbox from the corresponding Week's "Deliverables" section in IMPLEMENTATION_PLAN.md is checked.
4. **Handoff closed**: any `TODO(user)` or `TODO(lab-sample)` markers CC left in files have been replaced with real data (or explicitly deferred to a later sprint with a linked issue).
5. **Sprint 5 only — pre-tag sanity**:
   - `grep -rE '(password|secret|api[_-]?key|BEGIN .* PRIVATE KEY)' home-soc-lab/` returns nothing.
   - `git tag` lists `v1.0`.

## Out of Scope / Explicit Non-Goals

- Claude Code does **not** install software, provision VMs, or execute Atomic Red Team tests — those are user-side.
- Claude Code does **not** take real screenshots — user provides them; CC embeds references.
- No domain controller / AD setup — the plan deliberately stays single-endpoint.
- No cloud / SaaS logs — all on-prem lab.
