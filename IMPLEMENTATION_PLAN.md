# Home SOC Lab — Implementation Plan

**Project:** `home-soc-lab`
**Target Role:** Tier 1 SOC Analyst (entry-level)
**Timeline:** 5 weeks (~8-12 hrs/week)
**Stack:** Splunk Free · Sysmon · Atomic Red Team · Windows 10 (victim) · Kali Linux (attacker) · Ubuntu Server (SIEM host)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Skills Showcased](#skills-showcased)
3. [Guiding Principles](#guiding-principles)
4. [Lab Architecture](#lab-architecture)
5. [Week 1 — Lab Foundation](#week-1--lab-foundation)
6. [Week 2 — Detection Engineering Foundations](#week-2--detection-engineering-foundations)
7. [Week 3 — Attack Simulation & Detection Library](#week-3--attack-simulation--detection-library)
8. [Week 4 — Incident Investigation Write-Ups](#week-4--incident-investigation-write-ups)
9. [Week 5 — Polish, Automation, and Signature Blog Post](#week-5--polish-automation-and-signature-blog-post)
10. [Final Repo Structure](#final-repo-structure)
11. [Templates](#templates)
12. [Interview Preparation](#interview-preparation)
13. [Resources & References](#resources--references)

---

## Project Overview

Build a functional home SOC that ingests Windows endpoint telemetry into Splunk, simulate realistic adversary behavior using Atomic Red Team, write detections mapped to MITRE ATT&CK, investigate the resulting alerts end-to-end, and document everything as professional deliverables.

The goal is not to build the most elaborate lab — it is to produce **evidence of Tier 1 SOC competence**: SIEM querying, alert triage, detection writing, incident investigation, MITRE mapping, and clear written communication.

---

## Skills Showcased

This project is explicitly designed to demonstrate the six skill areas you identified:

| Skill | Where It's Demonstrated |
|---|---|
| SIEM querying & alert triage | `/detections/` — SPL queries, saved alerts, triage notes |
| Detection engineering | `/detections/` — custom Splunk rules + Sigma rules |
| Incident investigation & reporting | `/investigations/` — full incident reports |
| Threat hunting & MITRE ATT&CK mapping | Coverage matrix + technique-level write-ups |
| Malware/network traffic analysis | Scenario 2 & 3 in `/investigations/`, plus PCAP analysis notes |
| Automation & scripting | `/scripts/` — Python/PowerShell for log parsing, IOC extraction, triage helpers |

---

## Guiding Principles

Three rules that separate a project that gets interviews from a project that gets ignored.

**1. Commit as you go.** Your GitHub history should show 5 weeks of steady progress. A repo dumped in one commit looks fabricated. Push small commits frequently — setup notes, draft queries, screenshots, failed attempts with lessons learned.

**2. Screenshot relentlessly.** Every detection that fires, every Splunk query result, every process tree, every attack execution. Capture now or re-stage later — and re-staging always takes 3x longer.

**3. Write the README last, but outline it first.** Sketch the README structure in Week 1 so you know what you're building toward. Polish the final narrative in Week 5 when you know what you actually accomplished.

---

## Lab Architecture

### Hardware Budget (Single Laptop, 16GB RAM)

| VM | RAM | vCPU | Disk | Purpose |
|---|---|---|---|---|
| Ubuntu Server (Splunk) | 4 GB | 2 | 60 GB | SIEM indexer + search head |
| Windows 10 Eval (victim) | 4 GB | 2 | 60 GB | Endpoint telemetry source |
| Kali Linux (attacker) | 2-3 GB | 2 | 30 GB | Offensive tooling |
| Host OS reserve | 4-5 GB | — | — | Keep laptop responsive |

**Total VM footprint:** ~14 GB RAM, ~150 GB disk. Run only the VMs you actively need — shut down Kali when analyzing logs, shut down the victim when you're just writing SPL.

### Network Design

Use a **host-only network** in VirtualBox or VMware Workstation Player. This keeps all attack traffic contained to the virtualized environment — no risk to your home network, no accidental internet exposure of the victim VM.

Suggested IP scheme:
- Ubuntu Splunk: `192.168.56.10`
- Windows victim: `192.168.56.20`
- Kali attacker: `192.168.56.30`

Give each VM a static IP. Disable internet on the victim after initial patching to prevent Defender cloud lookups from interfering with attack simulations. If you need to pull down Atomic Red Team payloads, toggle internet on briefly, then turn it off.

### Diagram (to recreate in draw.io or excalidraw)

```
          ┌─────────────────────────────────────┐
          │       Host Laptop (Windows/macOS)    │
          │                                      │
          │   VirtualBox Host-Only Network       │
          │   192.168.56.0/24                    │
          │                                      │
          │  ┌──────────────┐  ┌──────────────┐ │
          │  │  Windows 10  │  │ Kali Linux   │ │
          │  │   (Victim)   │  │  (Attacker)  │ │
          │  │ 192.168.56.20│  │192.168.56.30 │ │
          │  │              │  │              │ │
          │  │ Sysmon       │  │ Atomic Red   │ │
          │  │ Splunk UF────┼──┤ Team         │ │
          │  └──────┬───────┘  └──────┬───────┘ │
          │         │                 │         │
          │         └──────┬──────────┘         │
          │                ▼                    │
          │  ┌──────────────────────────┐       │
          │  │   Ubuntu Server          │       │
          │  │   (Splunk Free)          │       │
          │  │   192.168.56.10          │       │
          │  └──────────────────────────┘       │
          └─────────────────────────────────────┘
```

---

## Week 1 — Lab Foundation

**Goal:** Get logs flowing from a Windows victim into Splunk, with Kali ready to attack.

### Setup Tasks

1. **Install virtualization platform**
   - VirtualBox (free) or VMware Workstation Player (free for personal use)
   - Verify VT-x/AMD-V is enabled in your laptop BIOS

2. **Build Ubuntu Server (Splunk host)**
   - Ubuntu Server 22.04 LTS, minimal install
   - 4 GB RAM, 2 vCPU, 60 GB disk
   - Install Splunk Free from splunk.com (requires free account)
   - Configure Splunk to listen on port 9997 for forwarders
   - Create an index called `endpoint`

3. **Build Windows 10 victim**
   - Microsoft Windows 10 Enterprise Evaluation (90-day free ISO)
   - 4 GB RAM, 2 vCPU, 60 GB disk
   - Install Sysmon with [SwiftOnSecurity's config](https://github.com/SwiftOnSecurity/sysmon-config) (industry-standard starting baseline)
   - Install Splunk Universal Forwarder, point it at your Ubuntu box
   - Configure `inputs.conf` to ship:
     - `WinEventLog:Security`
     - `WinEventLog:Microsoft-Windows-Sysmon/Operational`
     - `WinEventLog:Microsoft-Windows-PowerShell/Operational`
     - `WinEventLog:System`
   - Enable PowerShell Script Block Logging via Group Policy

4. **Build Kali Linux**
   - Kali 2024.x minimal install
   - 2-3 GB RAM, 2 vCPU, 30 GB disk
   - No Splunk forwarder — this is pure attack tooling

5. **Verify ingestion**
   - Run on Splunk: `index=endpoint | stats count by sourcetype`
   - You should see `WinEventLog:*` entries populating
   - Generate some activity on the victim (open notepad, run a PowerShell cmdlet) and confirm it lands in Splunk within ~30 seconds

### Week 1 Deliverables

- [ ] `/setup/README.md` with full build instructions and architecture diagram (PNG export)
- [ ] `/setup/sysmon-config.xml` with credit to SwiftOnSecurity
- [ ] `/setup/splunk-inputs.conf` showing UF configuration
- [ ] `/setup/screenshots/` with 3-4 screenshots proving logs are flowing
- [ ] First GitHub commit with README stub

### Common Pitfalls

- **Sysmon installs but events don't appear in Splunk:** Check UF `inputs.conf` — the channel name must be exact, including the `Microsoft-Windows-Sysmon/Operational` format.
- **VMs can't talk to each other:** Ensure all three are on the same host-only adapter, not NAT. Give each a static IP.
- **Splunk won't start on Ubuntu:** Usually a permissions issue — run `sudo /opt/splunk/bin/splunk start --accept-license` as the initial startup.
- **Windows victim is unbearably slow:** Disable unnecessary services, give it an SSD-backed virtual disk, and don't run Kali at the same time unless actively attacking.

---

## Week 2 — Detection Engineering Foundations

**Goal:** Understand your log data, learn SPL, and write your first three detections.

### Tasks

1. **Baseline your environment (3 hours)**
   - Browse Splunk without a goal. What does a normal login look like (Event ID 4624)? What does process creation (Sysmon Event ID 1) contain? What network connections does the victim make idle (Sysmon EID 3)?
   - This "I know what normal looks like" muscle is exactly what separates a functional Tier 1 from someone still reading from a runbook.

2. **Learn SPL fundamentals**
   - Core commands: `search`, `where`, `stats`, `table`, `eval`, `rex`, `rename`, `sort`, `dedup`
   - Time modifiers: `earliest=-24h`, `latest=now`
   - Statistical: `count`, `dc` (distinct count), `values`
   - Write down patterns you find useful — they become your `notes/splunk-spl-cheatsheet.md`

3. **Run your first three Atomic Red Team tests**
   - Install Atomic Red Team on the Windows victim (use Invoke-AtomicRedTeam PowerShell module)
   - Execute these three, one at a time, noting timestamps:
     - **T1059.001** — PowerShell Execution (encoded command variant)
     - **T1003.001** — LSASS Memory Dump (use the `comsvcs.dll` variant, less noisy than Mimikatz)
     - **T1053.005** — Scheduled Task Creation

4. **Write detections for each**
   - Use the detection write-up template (see [Templates](#templates))
   - For each, include: MITRE mapping, SPL query, why it works, false positive profile, test case, sample event
   - Save each as a Splunk alert (even if it never fires in production — the configuration demonstrates you understand alerting)

### Example Starter SPL Queries

**T1059.001 — Encoded PowerShell:**
```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*")
| table _time host User ParentImage Image CommandLine
```

**T1003.001 — LSASS Access:**
```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*lsass.exe"
| where NOT SourceImage IN ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\wininit.exe")
| table _time host SourceImage TargetImage GrantedAccess
```

**T1053.005 — Scheduled Task Creation:**
```spl
index=endpoint sourcetype="WinEventLog:Security" EventCode=4698
| table _time host Subject_User_Name Task_Name Task_Content
```

These are starting points — tune them with your own data before finalizing.

### Week 2 Deliverables

- [ ] `/detections/T1059.001-powershell-encoded.md`
- [ ] `/detections/T1003.001-lsass-access.md`
- [ ] `/detections/T1053.005-scheduled-task.md`
- [ ] `/notes/splunk-spl-cheatsheet.md`
- [ ] Screenshots of each detection firing in Splunk
- [ ] Commits spread across the week (not a single end-of-week dump)

---

## Week 3 — Attack Simulation & Detection Library

**Goal:** Expand to 10-12 detections covering diverse MITRE tactics, plus introduce Sigma rules.

### Coverage Plan

Write **at least one detection per tactic** below. Pick two per tactic if you have time.

| MITRE Tactic | Suggested Techniques |
|---|---|
| Execution | T1059.001 (PowerShell), T1059.003 (cmd) |
| Persistence | T1547.001 (Registry Run Keys), T1053.005 (Scheduled Tasks — done Week 2) |
| Privilege Escalation | T1548.002 (UAC Bypass via fodhelper or similar) |
| Defense Evasion | T1070.001 (Clear Windows Event Logs), T1562.001 (Disable Defender) |
| Credential Access | T1003.001 (LSASS — done Week 2), T1003.002 (Security Account Manager via reg save) |
| Discovery | T1087 (Account Discovery via net user/net group), T1082 (System Info Discovery) |
| Lateral Movement | T1021.002 (SMB/Admin Shares) |

### Sigma Rules

Write **at least two rules in Sigma YAML format**. Sigma is vendor-neutral and shows you think beyond one SIEM. Convert them to Splunk using `sigma convert` from the [pysigma](https://github.com/SigmaHQ/pySigma) toolkit and include both the YAML and the converted SPL in the repo.

Good candidates for Sigma:
- Clearing of Windows event logs (T1070.001)
- LSASS access from unusual parent process

### Coverage Matrix

In `/detections/README.md`, build this table. It's often the first thing a reviewer skims:

```markdown
| Detection File | Technique | Tactic | Severity | Status |
|---|---|---|---|---|
| T1059.001-powershell-encoded.md | T1059.001 | Execution | High | ✅ Tested |
| T1003.001-lsass-access.md | T1003.001 | Credential Access | Critical | ✅ Tested |
| ... | ... | ... | ... | ... |
```

### Week 3 Deliverables

- [ ] 10-12 detection write-ups in `/detections/`, each following the template
- [ ] 2 Sigma rules in `/detections/sigma/`
- [ ] `/detections/README.md` with coverage matrix
- [ ] Screenshots of attack execution and detection firing for each

---

## Week 4 — Incident Investigation Write-Ups

**Goal:** This is where you separate yourself. Produce three realistic, end-to-end incident reports.

Most entry-level candidates stop at detections. Full investigation reports — written in the format an actual SOC would produce — are disproportionately valuable for interviews.

### Three Scenarios to Execute and Investigate

Each scenario is a **multi-step attack chain**, not a single technique. You'll execute the chain, then investigate it from the resulting alerts outward.

#### Scenario 1: Phishing → PowerShell → Persistence

- Simulate a malicious document (macro-style) that executes encoded PowerShell
- The PowerShell downloads a second-stage payload (simulated)
- The payload creates a scheduled task for persistence
- **Your investigation:** start from the encoded PowerShell alert, pivot to parent process (Office), follow the chain to the scheduled task

#### Scenario 2: Credential Theft Chain

- Attacker disables Windows Defender (T1562.001)
- Dumps LSASS memory (T1003.001)
- Exports SAM via `reg save` (T1003.002)
- Exfiltrates to Kali via SMB or HTTP
- **Your investigation:** start from Defender disablement alert, identify the broader credential theft pattern, extract IOCs

#### Scenario 3: Living-off-the-Land Reconnaissance

- Attacker uses built-in Windows tools for discovery: `whoami /priv`, `net user /domain`, `systeminfo`, `tasklist`
- Follows with attempted lateral movement via WMI or SMB
- **Your investigation:** start from discovery command clustering, build a timeline, assess intent

### Investigation Report Standard

Each report uses the [investigation report template](#investigation-report-template). Minimum contents:

- Executive summary (3-4 sentences)
- Initial alert that fired
- Timeline with timestamps
- Technical analysis (process trees, network connections, file artifacts)
- Indicators of Compromise (IOCs) in a table
- MITRE ATT&CK mapping for every technique observed
- Impact assessment
- Containment and remediation recommendations
- Detection gaps / lessons learned

### Pick Your Showcase Report

One of these three will be your "showcase" — the one you reference in interviews. Polish it most. My recommendation: **Scenario 2 (Credential Theft Chain)**, because it's the most dramatic narrative and demonstrates the widest skill range (detection, investigation, IOC extraction, MITRE mapping, remediation thinking).

### Week 4 Deliverables

- [ ] `/investigations/INC-2025-001-phishing-to-persistence.md`
- [ ] `/investigations/INC-2025-002-credential-theft-chain.md`
- [ ] `/investigations/INC-2025-003-lotl-reconnaissance.md`
- [ ] Each report includes at least 3 screenshots (alert, process tree, timeline)
- [ ] One "showcase" report polished to publication quality

---

## Week 5 — Polish, Automation, and Signature Blog Post

**Goal:** Add automation scripts, polish all deliverables, and produce the single piece of writing that will carry the most weight in interviews.

### The Signature Blog Post (~1500-2500 words)

Pick your strongest detection and write a deep-dive piece. My recommendation: **LSASS memory access (T1003.001)** — classic technique, rich material, well-documented so you can ground your claims.

Structure:

1. **The threat** — why attackers dump LSASS, what they get from it
2. **The artifacts** — what the log evidence looks like (Sysmon EID 10, Windows Security EID 4656/4663)
3. **The detection** — your SPL, line by line, explaining each filter
4. **False positive profile** — what legitimate processes access LSASS (svchost, wininit, etc.) and how to tune
5. **What the detection misses** — honest discussion of evasion (PPL bypass, direct syscalls, comsvcs.dll minidump, etc.)
6. **Further reading** — links to Red Canary's Threat Detection Report, MITRE ATT&CK, original research

Publish on Medium, dev.to, or your own site. Link prominently from your README. **This single piece of writing will do more for interviews than the rest of the repo combined** because it proves detection-engineering mindset, not just button-pushing.

### Automation Scripts (to demonstrate scripting skill)

Add 2-3 small, useful scripts to `/scripts/`:

1. **`parse-sysmon-iocs.py`** — Python script that ingests a Sysmon event (XML or JSON) and extracts IOCs (hashes, IPs, filenames) into a CSV
2. **`splunk-alert-triage.ps1`** — PowerShell script that, given a hostname, pulls recent process creation events and outputs a timeline
3. **`atomic-test-runner.ps1`** (optional) — wrapper that runs a batch of Atomic Red Team tests with spacing so you can correlate to Splunk cleanly

Each script should have a clear header comment explaining purpose, inputs, outputs. Keep them short — 30-80 lines is ideal. Hiring managers want to see you *can* script, not that you've written a framework.

### Final README Polish

Your main README is the storefront. Minimum sections:

- Project purpose (2 sentences)
- Architecture diagram
- Skills demonstrated (bulleted, mapped to repo sections)
- Detection coverage matrix (pulled in from `/detections/README.md`)
- Links to investigation reports with one-sentence summaries
- Link to blog post
- "What I Learned" section — honest reflection, not marketing fluff. Include things that went wrong and what you'd do differently.
- LICENSE (MIT is fine)
- Credits — SwiftOnSecurity for Sysmon config, Red Canary for Atomic Red Team, etc.

### Week 5 Deliverables

- [ ] Blog post published and linked
- [ ] 2-3 automation scripts in `/scripts/`
- [ ] Polished main README
- [ ] LICENSE file
- [ ] Repo tagged `v1.0`
- [ ] All screenshots reviewed for readability
- [ ] No secrets, API keys, or personal data committed

---

## Final Repo Structure

```
home-soc-lab/
├── README.md                         # Main showcase
├── LICENSE
├── /setup/
│   ├── README.md                     # Lab build instructions
│   ├── architecture-diagram.png
│   ├── sysmon-config.xml
│   ├── splunk-inputs.conf
│   └── screenshots/
├── /detections/
│   ├── README.md                     # Coverage matrix
│   ├── T1059.001-powershell-encoded.md
│   ├── T1003.001-lsass-access.md
│   ├── T1003.002-sam-registry-dump.md
│   ├── T1053.005-scheduled-task.md
│   ├── T1070.001-clear-event-logs.md
│   ├── T1087-account-discovery.md
│   ├── T1547.001-registry-run-keys.md
│   ├── T1562.001-disable-defender.md
│   ├── T1548.002-uac-bypass.md
│   ├── T1021.002-smb-admin-shares.md
│   └── sigma/
│       ├── clear-event-logs.yml
│       └── lsass-unusual-parent.yml
├── /investigations/
│   ├── INC-2025-001-phishing-to-persistence.md
│   ├── INC-2025-002-credential-theft-chain.md
│   └── INC-2025-003-lotl-reconnaissance.md
├── /scripts/
│   ├── parse-sysmon-iocs.py
│   └── splunk-alert-triage.ps1
├── /notes/
│   └── splunk-spl-cheatsheet.md
└── /blog/
    └── lsass-detection-deep-dive.md  # Or link to hosted version
```

---

## Templates

### Detection Write-Up Template

```markdown
# Detection: [Descriptive Name]

## MITRE ATT&CK
- **Tactic:** [e.g., Credential Access]
- **Technique:** [e.g., T1003.001 — OS Credential Dumping: LSASS Memory]
- **Sub-technique:** [if applicable]

## Severity
[Critical / High / Medium / Low]

## Detection Logic

```spl
[Your full SPL query here]
```

## Why This Works
[1-2 paragraphs explaining the behavioral indicator this detects. What does the attacker
need to do that produces this log signal? Why is it hard for them to avoid?]

## False Positive Considerations
[What legitimate processes or users might trigger this. Suggested tuning (whitelisting
specific parent processes, specific service accounts, etc.).]

## Test Case
[Exact Atomic Red Team test or manual command used to validate]

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

## Sample Event
[Screenshot or redacted log sample showing the detection firing]

## References
- [Link to MITRE ATT&CK page]
- [Link to Red Canary or other research]
```

### Investigation Report Template

```markdown
# Incident Report: [Scenario Name]

**Report ID:** INC-2025-XXX
**Analyst:** [Your Name]
**Date:** [Date]
**Severity:** [Critical / High / Medium / Low]
**Status:** [Contained / Investigating / Closed]

## Executive Summary
[3-4 sentences a non-technical manager can read. What happened, what was affected,
what was done.]

## Initial Alert
- **Detection:** [Which rule fired]
- **Time:** [Timestamp]
- **Host:** [Affected endpoint]
- **Triggering query:**
  ```spl
  [SPL]
  ```
- **Screenshot:** [Embedded]

## Investigation Timeline
| Time | Event |
|---|---|
| T+0:00 | Alert fired for encoded PowerShell on WIN-VICTIM-01 |
| T+0:03 | Pivoted to parent process — WINWORD.EXE identified |
| T+0:08 | Confirmed macro execution via Office logs |
| T+0:15 | Identified scheduled task creation for persistence |
| T+0:22 | Extracted IOCs, escalated to Tier 2 |

## Technical Analysis

### Process Tree
```
WINWORD.EXE (PID 4321)
  └── powershell.exe -enc [base64] (PID 5678)
        └── schtasks.exe /create /tn "Updater" ... (PID 6789)
```

### Network Activity
[Relevant connections with IPs, ports, timestamps]

### File Artifacts
[Files created, modified, or accessed]

## Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| SHA256 | abc123... | Malicious macro document |
| IP | 192.168.56.30 | C2 simulation |
| Filename | Updater.ps1 | Persistence payload |
| Reg Key | HKLM\...\Run\Updater | Persistence mechanism |

## MITRE ATT&CK Mapping
- T1566.001 — Phishing: Spearphishing Attachment
- T1059.001 — PowerShell
- T1053.005 — Scheduled Task

## Impact Assessment
- **Confirmed compromised:** WIN-VICTIM-01
- **Data accessed:** [None confirmed / specific files]
- **Lateral movement:** [None observed / details]
- **Credentials at risk:** [Local admin / domain creds / none]

## Containment & Remediation Recommendations
1. Isolate WIN-VICTIM-01 from the network
2. Kill scheduled task "Updater"
3. Remove registry persistence key
4. Reset local admin credentials on host
5. Hunt for same IOCs across other endpoints

## Detection Gaps / Lessons Learned
- Macro execution was not alerted on directly — only caught via downstream PowerShell
- Recommendation: Add detection for Office spawning child processes (Sysmon EID 1 with
  parent WINWORD.EXE/EXCEL.EXE and child powershell.exe/cmd.exe/wscript.exe)
```

---

## Interview Preparation

### How to Talk About This Project

When asked "tell me about a project," **do not describe the whole lab**. Pick one incident investigation and walk through it as a narrative:

> "I caught an alert for encoded PowerShell execution on one of my endpoints. First thing I did was pivot to the parent process — turned out to be Word, which immediately told me this was likely a malicious macro. From there I built out the timeline..."

This narrative proves you can do the job. The rest of the repo is supporting evidence.

### Anticipated Questions

- **"Why Splunk over Sentinel/Elastic?"** — Acknowledge you chose Splunk because it's most common in Tier 1 job postings but that your Sigma rules demonstrate vendor-neutral thinking and you're interested in learning whichever SIEM the employer uses.
- **"What would you do differently?"** — Have a real answer. Mine would be: "I'd introduce a second endpoint earlier to get lateral movement detection in, and I'd add packet capture to the Kali-to-victim path for network-layer analysis."
- **"What's a false positive you encountered?"** — You should have a real one from Week 3 or 4. Legitimate svchost LSASS access is a classic example.
- **"Walk me through your LSASS detection."** — Explain the SPL line by line. If you wrote the blog post, this is easy.

### What Not to Oversell

Be honest that this is a lab, not production experience. Hiring managers respect candidates who can distinguish between "I did this in a controlled environment" and "I ran a real SOC." Overclaiming kills credibility fast.

---

## Resources & References

### Official Documentation
- [MITRE ATT&CK](https://attack.mitre.org/) — the canonical reference
- [Splunk SPL Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Sigma Rule Format](https://github.com/SigmaHQ/sigma)

### Tools
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) (PowerShell runner)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular) (more advanced alternative)

### Reading (genuinely worth your time)
- Red Canary's annual **Threat Detection Report** — the single best free resource on real-world adversary behavior
- **The DFIR Report** — case studies of real intrusions, written in exactly the format you should emulate
- **SANS Reading Room** — free whitepapers on detection engineering

### Communities
- r/cybersecurity, r/blueteamsec on Reddit
- BloodHoundGang, MSSP Slack/Discord communities
- Twitter/X — follow @SwiftOnSecurity, @cyb3rops (Florian Roth), @likethecoins (Katie Nickels)

---

**Last updated:** Start of project
**Target completion:** Week 5
**Tag when done:** `v1.0`
