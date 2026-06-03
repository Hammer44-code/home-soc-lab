# Detection: Account Discovery

> **Status: validated 2026-06-03.** The burst-correlation SPL fired end-to-end against Atomic Red Team `T1087.001-8/9/10` on the soc-victim VM (`distinct_cmds=3`: `net-account`, `query-user`, `whoami`). Validation exposed two real calibration bugs — a CommandLine-vs-Image classifier failure and a multivalued `User` field — both fixed and documented in Tuning Notes. The Sample Event below is a real captured EID 1.

## MITRE ATT&CK

- **Tactic:** Discovery (TA0007)
- **Technique:** T1087 — Account Discovery
- **Sub-technique:** T1087.001 — Local Account (the focus in this single-endpoint lab; T1087.002 Domain Account is noted as a future extension once a DC exists)

## Severity

**Low-to-Medium** — Account-discovery commands are individually low-signal: `whoami`, `net user`, and `net localgroup` are run constantly by administrators, scripts, and legitimate software. A single invocation is almost never worth an alert. The signal lives in **context and clustering** — an unusual parent process running a discovery command, or a *burst* of several distinct discovery commands in a short window, which is the hallmark of an attacker (or a post-exploitation framework's auto-recon module) orienting on a freshly accessed host. This detection therefore ships two SPLs: a per-command classifier (low severity, mostly for hunting/pivoting) and a **burst-correlation** search (medium severity, the real alert).

## Detection Logic

Both searches key off Sysmon **EID 1** (process creation) for the standard account-enumeration LOLBins. The per-command search classifies each invocation; the burst search counts *distinct* discovery commands per host/user in a time window and fires when several land close together.

### Primary — per-command classifier (hunting / pivot)

```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\whoami.exe" OR Image="*\\query.exe" OR Image="*\\quser.exe" OR Image="*\\wmic.exe" OR Image="*\\powershell.exe")
| eval discovery_cmd=case(
    match(Image, "(?i)\\\\net1?\.exe$") AND match(CommandLine, "(?i)\s(user|localgroup|group|accounts)\b"), "net account",
    match(Image, "(?i)\\\\whoami\.exe$"), "whoami",
    match(Image, "(?i)\\\\quser\.exe$") OR (match(Image, "(?i)\\\\query\.exe$") AND match(CommandLine, "(?i)\suser\b")), "query user",
    match(Image, "(?i)\\\\wmic\.exe$") AND match(CommandLine, "(?i)\s(useraccount|group)\b"), "wmic account",
    match(CommandLine, "(?i)Get-Local(User|Group|GroupMember)"), "ps Get-Local*",
    match(CommandLine, "(?i)(Get-AdUser|Get-AdGroup|Get-AdGroupMember)"), "ps Get-Ad* (domain)",
    1=1, null())
| where isnotnull(discovery_cmd)
| table _time host User ParentImage Image discovery_cmd CommandLine
| sort - _time
```

### Secondary — burst correlation (the real alert)

```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\whoami.exe" OR Image="*\\query.exe" OR Image="*\\quser.exe" OR Image="*\\wmic.exe" OR Image="*\\powershell.exe")
| eval discovery_cmd=case(
    match(Image, "(?i)\\\\net1?\.exe$") AND match(CommandLine, "(?i)\s(user|localgroup|group|accounts)\b"), "net-account",
    match(Image, "(?i)\\\\whoami\.exe$"), "whoami",
    match(Image, "(?i)\\\\quser\.exe$") OR (match(Image, "(?i)\\\\query\.exe$") AND match(CommandLine, "(?i)\suser\b")), "query-user",
    match(Image, "(?i)\\\\wmic\.exe$") AND match(CommandLine, "(?i)\s(useraccount|group)\b"), "wmic-account",
    match(CommandLine, "(?i)Get-Local(User|Group|GroupMember)"), "ps-getlocal",
    1=1, null())
| where isnotnull(discovery_cmd)
| eval acct=coalesce(mvindex(mvfilter(User!="NOT_TRANSLATED"),0), User)
| bin _time span=5m
| stats dc(discovery_cmd) as distinct_cmds values(discovery_cmd) as commands values(ParentImage) as parents count by _time host acct
| where distinct_cmds >= 3
| sort - _time
```

### What each piece does

**Primary (classifier):**

- Scopes to the account-enumeration LOLBins. `net.exe` and `net1.exe` are both listed because **`net.exe` is a thin wrapper that re-launches itself as `net1.exe`** to do the actual work — so `net user` produces *two* EID 1 events (`net.exe` then `net1.exe`), and a detection that only watches `net.exe` would still fire, but watching both makes the wrapper relationship visible.
- `net` invocations are scoped by the `match()` to the account-relevant subcommands (`user`, `localgroup`, `group`, `accounts`) so that unrelated `net` usage (`net use`, `net start`, `net view`) doesn't pollute the results.
- `whoami` is included with no argument filter — even bare `whoami` is a discovery signal, and `whoami /all`/`/groups`/`/priv` are stronger ones.
- `discovery_cmd` is `null()` for anything that doesn't match, and `where isnotnull(discovery_cmd)` drops it — so the `powershell.exe`/`wmic.exe` in the base filter only survive if their command line actually contains a discovery cmdlet/alias.

**Secondary (burst):**

- Same base + classification, but it `bin`s events into 5-minute buckets and uses `stats dc(discovery_cmd)` to count **distinct** discovery command *types* per host/user/bucket.
- `where distinct_cmds >= 3` is the alert threshold: three or more *different* account-discovery commands from the same user inside five minutes is the recon-burst pattern. A human admin checking one thing runs one command; an attacker (or an automated recon module like those in Cobalt Strike, Sliver, or a `SharpHound`-style collector) sweeps several in seconds.
- `values(ParentImage)` surfaces what spawned the burst — a burst whose parent is `cmd.exe`/`powershell.exe` spawned in turn by `winword.exe`, `mshta.exe`, or an unexpected process is the high-confidence incident shape.

## Why This Works

Discovery is a required phase of essentially every intrusion: after gaining access, the attacker has to learn *where they are and what they can reach* before moving. Account discovery specifically answers "what users and groups exist, and am I privileged?" — the input to privilege escalation and lateral-movement planning.

The technique is unavoidable in the sense that the information only lives in places you have to *query* — the SAM, the local groups, the domain (if joined). The built-in tools that read those (`net`, `whoami`, `wmic`, the PowerShell `Get-Local*` cmdlets) are the natural way to do it, and they all spawn observable processes (EID 1) or, for the API-only path, still leave PowerShell script-block evidence.

The defender's leverage is **not** the individual command — it's too common — but the *clustering*. Legitimate use is sparse and purposeful; adversary use is bursty and broad ("enumerate everything"). The burst-correlation SPL turns that behavioral difference into a detectable signal, which is why it, not the per-command classifier, is the real alert.

## Tuning Notes

Validated end-to-end on 2026-06-03 against Atomic Red Team `T1087.001-8/9/10`. The burst SPL fired with `distinct_cmds=3` (`net-account`, `query-user`, `whoami`) in a single 5-minute bucket. Two real bugs surfaced during validation — both are the kind of calibration miss you only catch against live data.

**Iteration loop #1 — classify the binary off `Image`, never `CommandLine`.** The first-draft classifier matched the binary inside `CommandLine`, e.g. `match(CommandLine, "(?i)\\(query|quser)\.exe.*\suser\b")`. Against real telemetry this silently failed for most commands, because **Windows logs many of these by bare command name in the command line** while the full path only lives in the `Image` field. The captured command lines were `query  user` (no `query.exe`), `net1 localgroup` (bare `net1`, no `.exe`), `wmic  OS get ...` (bare `wmic`). So `query-user` and others never classified, the bucket only reached 2 distinct types, and the burst SPL returned **nothing**. **Fix:** match the *binary* against `Image` (`match(Image, "(?i)\\quser\.exe$")`) and use `CommandLine` only for the *arguments* (`match(CommandLine, "(?i)\suser\b")`). Same family as the T1547.001 RunOnceEx parse — assumptions about field *shape* are where detections quietly break. This Image-vs-CommandLine split is now the standard idiom for the discovery detections (applied identically in [T1082](T1082-system-info-discovery.md)).

**Iteration loop #2 — the `User` field is multivalued (`NOT_TRANSLATED` + real account).** Grouping `... by _time host User` produced **two identical burst rows** — one keyed on `NOT_TRANSLATED`, one on `DESKTOP-0DU4BT6\analyst` — because each Sysmon-via-WinEventLog event carries *both* values: `NOT_TRANSLATED` from the Windows Event Log envelope (the `Sid=S-1-5-18` couldn't be translated at the envelope layer) and the real `DESKTOP-0DU4BT6\analyst` from the Sysmon message body. The raw Sample Event below shows both under `User`. **Fix:** collapse to the real account before grouping — `| eval acct=coalesce(mvindex(mvfilter(User!="NOT_TRANSLATED"),0), User)`, then `... by _time host acct`. This multivalue-`User` quirk affects any `stats ... by User` on this index and is worth remembering for every future process-based detection.

**`net.exe` → `net1.exe` wrapper confirmed.** A single `net localgroup` produced two EID 1 events: `net.exe` (parent) immediately re-launching `net1.exe` (child) with the same arguments — `ParentImage=...\net.exe`, `ParentCommandLine="...\net.exe" localgroup`, child `CommandLine=...\net1 localgroup`. Both are in the SPL's base filter so the detection fires on either; the pair just makes the wrapper relationship visible in the process tree.

**Bin-boundary fragility (accepted).** The burst uses `bin _time span=5m`, so a discovery sweep that straddles a 5-minute boundary can split its distinct-command count across two buckets and miss the `>= 3` threshold. In the lab the sweep landed inside the 20:50 bucket and fired cleanly. For production, a sliding-window approach (e.g. `streamstats` over a time window) is more robust than fixed bins — noted as a future hardening, not changed here to keep the SPL readable.

## False Positive Considerations

The per-command search is intentionally noisy — it's a hunting/pivot tool, not an alert. Expected benign sources:

- **Interactive administrators** running `whoami`, `net localgroup administrators`, or `net user` during legitimate troubleshooting.
- **Login scripts and GPO** that call `net` to map drives or check group membership at logon.
- **Software installers and management agents** that query accounts/groups to set permissions.
- **Monitoring/inventory tools** that periodically enumerate local accounts.

**Tuning recommendations:**

1. **Alert only on the burst SPL, hunt on the classifier.** A single discovery command should not page anyone. Three+ distinct types in five minutes should.
2. **Tune the `distinct_cmds` threshold to your baseline.** Start at 3; if a legitimate logon script trips it, either raise the threshold or exclude that specific `ParentImage`.
3. **Weight by parent.** A burst under `explorer.exe` (a human typing) is lower-confidence than the same burst under `cmd.exe`←`wscript.exe` or a process running from `\AppData\`/`\Temp\`. Add `ParentImage` to the triage view (already in `values(parents)`).
4. **Correlate with other tactics.** A discovery burst that immediately precedes a credential-access (T1003) or persistence (T1547/T1053) event on the same host is a near-certain intrusion — chain them in a correlation search later in the project.

## Test Case

Use [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) on the soc-victim VM. The T1087.001 atomics run a series of local account-enumeration commands — benign, read-only, no Defender wrestling, nothing to clean up.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

Invoke-AtomicTest T1087.001 -ShowDetailsBrief

# Test numbers vary by ART version — always run -ShowDetailsBrief first.
# In the version validated here the local-Windows tests were 8/9/10 (NOT 1/2):
#   T1087.001-8  Enumerate all accounts (Local)        -> net.exe / net1.exe
#   T1087.001-9  Enumerate via PowerShell (Local)      -> wraps net user / Get-Local*
#   T1087.001-10 Enumerate logged-on users via CMD     -> query.exe / quser.exe
# (Test 11 is ESXi — skip on Windows.) Run them close together so they land in
# one 5-minute bucket for the burst SPL:
Invoke-AtomicTest T1087.001 -TestNumbers 8,9,10
```

These produce a cluster of EID 1 events: `net.exe`+`net1.exe` for `net user`/`net localgroup`, `query.exe`/`quser.exe` for logged-on-user enumeration, plus the PowerShell wrapper — exactly the multi-command burst the secondary SPL is built to catch.

**To validate end-to-end:**

1. Confirm the VM clock reads Central, note the wall-clock time.
2. Run the atomics above (run them close together so they fall in one 5-minute bucket).
3. Run the **primary** SPL ("Last 15 minutes") — confirm one row per discovery command with `discovery_cmd` classified.
4. Run the **secondary** SPL — confirm a single burst row for your host/user with `distinct_cmds >= 3` and `commands` listing the types.
5. Paste me back one full raw EID 1 event (ideally the `net1.exe` one, to confirm the wrapper relationship) so I can replace the representative sample and flip this to validated.
6. No cleanup needed — these are read-only discovery commands.

**First-pass calibration check:** before trusting the SPL, run `index=endpoint EventCode=1 Image="*\\net1.exe" | stats count` for the test window to confirm `net1.exe` events land as expected (the wrapper behavior is a common surprise).

## Sample Event

> **Real EID 1 captured during 2026-06-03 lab validation of ART `T1087.001-8`** — the `net1.exe` child of a `net localgroup` invocation. Verbatim from Splunk.

```
06/03/2026 08:54:01.170 PM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=1
EventType=4
ComputerName=DESKTOP-0DU4BT6
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=16297
TaskCategory=Process Create (rule: ProcessCreate)
OpCode=Info
Sid=S-1-5-18
SidType=0
Message=Process Create:
RuleName: -
UtcTime: 2026-06-03 20:54:01.167
ProcessGuid: {22860150-9469-6a20-d202-000000000a00}
ProcessId: 7476
Image: C:\Windows\System32\net1.exe
FileVersion: 10.0.19041.3636 (WinBuild.160101.0800)
Description: Net Command
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: net1.exe
CommandLine: C:\Windows\system32\net1 localgroup
CurrentDirectory: C:\Users\analyst\AppData\Local\Temp\
User: DESKTOP-0DU4BT6\analyst
LogonGuid: {22860150-8b77-6a20-82a1-080000000000}
LogonId: 0x8A182
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=78E53D5AE8839C58FA40BEA32B775999,SHA256=E62071AA18768DD88ACAF97FA7B1F2FEC9FCCE89736C1EE9A800699328D196EA,IMPHASH=537AEF5B177E3302247DAB07A052B2D8
ParentProcessGuid: {22860150-9469-6a20-d102-000000000a00}
ParentProcessId: 3080
ParentImage: C:\Windows\System32\net.exe
ParentCommandLine: "C:\Windows\system32\net.exe" localgroup
ParentUser: DESKTOP-0DU4BT6\analyst
```

(The auto-extracted `User` field on this event is multivalued — both `NOT_TRANSLATED` and `DESKTOP-0DU4BT6\analyst` — which is the quirk the burst SPL's `acct` dedup handles; see Tuning Notes.)

### Analyst notes on this real captured event

- **`Image: ...\net1.exe` with `ParentImage: ...\net.exe`** — the wrapper relationship, captured live. The atomic ran `net localgroup`; `net.exe` parsed it and re-launched `net1.exe` with the same argument to do the work. Both binaries are in the SPL filter, and the single `net` command produced this parent/child pair in the process tree. `ParentCommandLine` shows the original `net` form, the child `CommandLine` shows the `net1` form.
- **`CommandLine: C:\Windows\system32\net1 localgroup`** — note the binary appears as bare **`net1`** with no `.exe` and no quoting. This is the exact reason the classifier keys on the `Image` field (`C:\Windows\System32\net1.exe`) for the binary and uses `CommandLine` only for the `localgroup` argument — matching the binary inside `CommandLine` would have missed this entirely (see Tuning Notes, iteration #1).
- **`CurrentDirectory: C:\Users\analyst\AppData\Local\Temp\`** — ART's staging directory. In a real intrusion, account-discovery commands whose working directory is `\Temp\`/`\AppData\`/`\Downloads\` are themselves a triage signal; legitimate admin discovery usually runs from a normal shell CWD.
- **`Hashes: ...SHA256=E62071AA...`** — the real Microsoft-signed `net1.exe` hash. A process *claiming* to be `net1.exe` with a mismatched hash, or running from a non-`System32` path, would itself be the lead.
- **`ParentUser` / one-level-up triage** — here the parent is benign (`net.exe` from the ART shell). In a real intrusion the meaningful question is what spawned the shell: the burst SPL's `parents` field captured `powershell.exe`, `cmd.exe`, `net.exe`, `query.exe` for this run. A burst whose `parents` instead include `wscript.exe`, `mshta.exe`, or a binary out of `\Temp\` is adversary recon, not admin troubleshooting.
- **`IntegrityLevel: High`** — the `analyst` session is elevated; account discovery works fine at Medium integrity too, so this is context, not a requirement.

## References

- MITRE ATT&CK: [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) / [T1087.001 — Local Account](https://attack.mitre.org/techniques/T1087/001/)
- Atomic Red Team test catalog: [T1087.001 atomics](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md)
- Microsoft docs: [net localgroup / net user](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-localgroup)
- LOLBAS: [net.exe](https://lolbas-project.github.io/lolbas/OSBinaries/Net/) / [wmic.exe](https://lolbas-project.github.io/lolbas/OSBinaries/Wmic/)
- Red Canary Threat Detection Report — discovery via `net` and `whoami` is consistently among the most-observed adversary behaviors, almost always in clusters.
