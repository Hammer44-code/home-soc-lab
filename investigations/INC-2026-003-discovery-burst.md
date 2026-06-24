# INC-2026-003 — Host Reconnaissance Burst (Account & System Discovery)

| | |
|---|---|
| **Incident ID** | INC-2026-003 |
| **Title** | Clustered account- and system-discovery commands consistent with post-access host reconnaissance |
| **Severity** | **Medium** (escalated from a Low-confidence signal after triage) |
| **Status** | Closed — True Positive (lab exercise) |
| **Classification** | True Positive — adversary/automated reconnaissance |
| **Affected host** | `DESKTOP-0DU4BT6` — soc-victim, `192.168.56.20` (Windows 10 22H2) |
| **Actor account** | `DESKTOP-0DU4BT6\analyst` |
| **Date of activity** | 2026-06-03 20:54 & 21:16 (Central) |
| **Report date** | 2026-06-24 |
| **Analyst** | Nolan — Tier 1 SOC (home-soc-lab) |
| **ATT&CK** | TA0007 Discovery — T1087.001 (Account Discovery: Local) · T1082 (System Information Discovery) |

---

## 1. Executive Summary

A burst of distinct **account-** and **system-discovery** commands ran on
`DESKTOP-0DU4BT6` within two short windows — `whoami`, `net user`,
`net localgroup`, `query user`, `systeminfo`, `hostname`, `wmic os/bios/...`, and a
registry version query. Individually each command is benign and runs every day on
healthy hosts; the alert exists because **several distinct discovery commands
clustered together from one account in minutes**, which is the signature of an
operator (or an automated recon module) orienting on a freshly accessed host.

This is the kind of alert where **the value is the triage judgment**, not the raw
signal: a single `whoami` would be closed without a second look, but a clustered
sweep has to be examined and a call made. After reviewing the parent processes,
working directory, and command clustering, this was assessed a **True Positive**
reconnaissance event and escalated from Low to **Medium**. In the broader picture
this is **Phase 3 of [INC-2026-001](INC-2026-001-multistage-intrusion.md)** — the
discovery step that follows initial access and precedes credential theft.

> **Lab note:** real telemetry captured during validation of detections
> [T1087](../detections/T1087-account-discovery.md) and
> [T1082](../detections/T1082-system-info-discovery.md) (ART `T1087.001-8/9/10` and
> `T1082-1/7/27/39`, 2026-06-03). All field values are verbatim from Splunk.

---

## 2. Detection Trigger

The burst-correlation searches counted **distinct discovery command *types*** per
account in 5-minute windows and alerted at `>= 3`:

```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\whoami.exe" OR Image="*\\query.exe"
 OR Image="*\\quser.exe" OR Image="*\\wmic.exe" OR Image="*\\powershell.exe" ...)
| eval discovery_cmd=case( ... classify off Image, args off CommandLine ... )
| where isnotnull(discovery_cmd)
| eval acct=coalesce(mvindex(mvfilter(User!="NOT_TRANSLATED"),0), User)
| bin _time span=5m
| stats dc(discovery_cmd) as distinct_cmds values(discovery_cmd) as commands values(ParentImage) as parents count by _time host acct
| where distinct_cmds >= 3
```

**Two burst rows fired** for `acct=DESKTOP-0DU4BT6\analyst`:

| Window | Search | `distinct_cmds` | `commands` | `parents` |
|---|---|---|---|---|
| 20:54 | Account Discovery (T1087.001) | **3** | `net-account`, `query-user`, `whoami` | `net.exe`, `query.exe`, `powershell.exe`, `cmd.exe` |
| 21:16 | System Info Discovery (T1082) | **4** | `systeminfo`, `hostname`, `wmic-system`, `reg-version` | `cmd.exe`, `powershell.exe` |

---

## 3. Investigation & Analysis — the triage decision

The discriminator for this technique is **not** any single command (all are
common) — it is the *shape* of the activity. Triage walked the standard questions:

**Q1 — Is the clustering real, or an artifact?** Yes, real: 3 and 4 *distinct*
command types in single 5-minute windows from one account. A human troubleshooting
one thing runs one command; this is a sweep across the account/group/OS/hardware
surface. (One nuance handled by the detection: `net user`/`net localgroup` spawn a
`net.exe` → `net1.exe` wrapper pair, so the raw event count is inflated — but the
alert counts *distinct command types*, not raw events, so the wrapper does not
fabricate the burst. Confirmed in the data: the `20:54` window's `net.exe` and
`net1.exe` are the same logical `net-account` command.)

**Q2 — What is the parent process?** The `parents` were `cmd.exe` / `powershell.exe`
/ `net.exe` / `query.exe`. This is the field that separates "admin at a console"
from "recon after initial access." Here the parent chain is a scripted shell
sweep, not an interactive `explorer.exe`→`cmd.exe` a human typed into. The parent
command lines confirm chaining of multiple discovery actions per line, e.g.:

```
ParentCommandLine: "cmd.exe" /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
```

— two discovery actions in one shell invocation, which is automation, not a human.

**Q3 — Where is it running from?** Every event's `CurrentDirectory` was
**`C:\Users\analyst\AppData\Local\Temp\`**. A discovery sweep whose working
directory is `\Temp\` (rather than a normal shell CWD like the user profile root)
is itself a triage signal — it suggests the commands were dropped/launched by
tooling staged in Temp, not typed by an admin.

**Q4 — Is the binary genuine?** Spot-checked: the `systeminfo.exe` and `net1.exe`
events carried the real Microsoft-signed hashes and ran from `System32` — so this
is not a renamed-LOLBin masquerade. (Genuine binaries; the *behaviour* is the
issue, not a trojaned tool.)

**Q5 — What is the surrounding context?** The same account (`analyst`) is the one
compromised in [INC-2026-001](INC-2026-001-multistage-intrusion.md), and this
discovery burst sits between the lateral-movement-to-SYSTEM step and the
credential-theft step. A discovery sweep that *precedes* credential access on the
same host is the textbook recon-then-loot sequence.

**Verdict:** **True Positive — reconnaissance.** Escalated Low → **Medium**.
Discovery on its own is not destructive, but in this context it is the orientation
phase of an active intrusion and warranted escalation rather than closure.

### What would have made this benign (the other side of the call)

To document the judgment honestly — this same alert is a routine **false positive**
when:
- the `parents` field is an **inventory/asset agent** (SCCM, Intune, Lansweeper,
  PDQ) — these run `systeminfo`/`wmic` sweeps on a schedule and are bursty by
  nature. The right response there is to allowlist the agent's parent binary, not
  lower the threshold.
- the parent is an interactive `explorer.exe`→`cmd.exe`/`powershell.exe` and the
  CWD is a normal profile path — a human admin troubleshooting.

Neither held here (scripted shell parents, Temp CWD, compromised account, recon
position in a kill chain), which is what tipped the call to True Positive.

---

## 4. Scope & Impact

- **Direct impact:** none destructive — discovery is read-only. No data was
  altered or exfiltrated *by these commands*.
- **Indirect significance:** the attacker now knows the local accounts, group
  memberships, privilege of their session, OS build/patch level, and hardware/VM
  status of the host — the inputs to privilege-escalation and lateral-movement
  planning. Treat as the **early-warning** phase: the same actor's next moves
  (credential access, persistence) are the destructive ones.
- **VM-evasion note:** the `wmic bios`/`csproduct`-style queries in the T1082
  window would, on this VirtualBox host, return tell-tale virtualisation strings. A
  real adversary seeing those might recognise an analysis VM and abort — making
  BIOS/csproduct queries a useful canary in production.

---

## 5. Indicators / Hunt Pivots

| Type | Indicator |
|---|---|
| Behaviour | ≥3 distinct discovery command *types* from one account in 5 min (EID 1) |
| Account discovery | `whoami`, `net user`, `net localgroup`, `query user` / `quser` |
| System discovery | `systeminfo`, `hostname`, `wmic os\|bios\|cpu\|baseboard\|...`, `reg query …CurrentVersion` |
| Context flag | discovery `CurrentDirectory` in `\Temp\` / `\AppData\` / `\Downloads\` |
| Context flag | discovery `parents` include `wscript.exe`, `mshta.exe`, an Office app, or a Temp-path binary |
| Wrapper | `net.exe`→`net1.exe` parent/child pair on `net` discovery |

---

## 6. Response & Recommendations

1. **Do not auto-close discovery bursts — triage them.** Pull the `parents` and
   `CurrentDirectory`, and check whether the same account shows credential-access
   or persistence activity nearby. That correlation is what turns a Medium signal
   into an incident.
2. **Correlate forward.** Pivot the account/host forward in time for T1003
   (credential access) and T1547/T1053 (persistence). In this case that pivot lands
   directly on the rest of INC-2026-001.
3. **Allowlist inventory agents by parent, not by threshold.** The one benign
   source that reliably trips this alert is asset-management tooling — exclude its
   parent binary in a baseline rather than weakening the rule.
4. **Add a complementary control for the blind spot.** `cmd.exe` built-ins (`ver`,
   `set`, `echo %VAR%`) spawn no process and produce no EID 1, so pure-built-in
   fingerprinting is invisible here. PowerShell script-block / process-command-line
   auditing covers that gap.

## 7. Analyst Notes & Lessons

- **This is the "judgment" alert.** Unlike a LSASS dump (INC-2026-002), which is
  malicious on sight, a discovery burst requires an analyst to weigh parent
  process, working directory, and surrounding activity and *decide*. Showing the
  decision — including what would have made it benign — is the point.
- **Count distinct types, not raw events.** The `net.exe`→`net1.exe` wrapper and
  repeated commands would inflate a naive event count; counting distinct *command
  types* (`dc(discovery_cmd)`) is what makes the threshold meaningful.
- **Clustering beats signatures for common LOLBins.** There is no "bad string" to
  match — `whoami` is `whoami`. The detectable difference between an admin and an
  adversary is sparse-and-purposeful vs. bursty-and-broad. The detection encodes
  that behavioural difference.

## References

- Detection write-ups (full SPL, raw events, tuning): [T1087 — Account Discovery](../detections/T1087-account-discovery.md) · [T1082 — System Information Discovery](../detections/T1082-system-info-discovery.md)
- Parent incident: [INC-2026-001 — Multi-Stage Intrusion](INC-2026-001-multistage-intrusion.md) (this is Phase 3)
- MITRE ATT&CK: <https://attack.mitre.org/techniques/T1087/001/> · <https://attack.mitre.org/techniques/T1082/>
