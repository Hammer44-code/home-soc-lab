# Detection: System Information Discovery

> **Status: validated 2026-06-03.** The burst-correlation SPL fired end-to-end against Atomic Red Team `T1082-1/7/27/39` on the soc-victim VM (`distinct_cmds=4`: `systeminfo`, `hostname`, `wmic-system`, `reg-version`). Inherited the Image-based classifier and multivalued-`User` dedup proven in [T1087](T1087-account-discovery.md); see Tuning Notes for the WMIC/registry argument calibration this run required. The Sample Event below is a real captured EID 1.

## MITRE ATT&CK

- **Tactic:** Discovery (TA0007)
- **Technique:** T1082 — System Information Discovery

## Severity

**Low-to-Medium** — Like account discovery (see [T1087](T1087-account-discovery.md)), individual system-info commands (`systeminfo`, `hostname`, `wmic os get`) are run routinely by admins, scripts, and software, so a lone invocation is not alert-worthy. The detectable signal is the **burst**: malware and post-exploitation frameworks fingerprint a freshly accessed host by running several system-info queries back-to-back (OS version, patch level, hardware, domain membership) to decide what exploits and tooling will work. This write-up reuses the same two-SPL structure as T1087 — a per-command classifier for hunting and a burst-correlation search for the real alert — and the two detections share a tuning philosophy.

## Detection Logic

Both searches key off Sysmon **EID 1** (process creation) for the standard system-fingerprinting LOLBins.

### Primary — per-command classifier (hunting / pivot)

```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\systeminfo.exe" OR Image="*\\hostname.exe" OR Image="*\\fsutil.exe" OR Image="*\\wmic.exe" OR Image="*\\reg.exe" OR Image="*\\powershell.exe")
| eval discovery_cmd=case(
    match(Image, "(?i)\\\\systeminfo\.exe$"), "systeminfo",
    match(Image, "(?i)\\\\hostname\.exe$"), "hostname",
    match(Image, "(?i)\\\\fsutil\.exe$") AND match(CommandLine, "(?i)fsinfo"), "fsutil fsinfo",
    match(Image, "(?i)\\\\wmic\.exe$") AND match(CommandLine, "(?i)\s(os|computersystem|bios|qfe|csproduct|cpu|baseboard|diskdrive|memphysical|win32_)"), "wmic system",
    match(Image, "(?i)\\\\reg\.exe$") AND match(CommandLine, "(?i)query.*(CurrentVersion|BIOS|SystemBios|HardwareConfig)"), "reg query version/bios",
    match(CommandLine, "(?i)Get-(WmiObject|CimInstance).*Win32_(OperatingSystem|ComputerSystem|BIOS|Processor)"), "ps Get-Wmi system",
    1=1, null())
| where isnotnull(discovery_cmd)
| table _time host User ParentImage Image discovery_cmd CommandLine
| sort - _time
```

### Secondary — burst correlation (the real alert)

```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\systeminfo.exe" OR Image="*\\hostname.exe" OR Image="*\\fsutil.exe" OR Image="*\\wmic.exe" OR Image="*\\reg.exe" OR Image="*\\powershell.exe")
| eval discovery_cmd=case(
    match(Image, "(?i)\\\\systeminfo\.exe$"), "systeminfo",
    match(Image, "(?i)\\\\hostname\.exe$"), "hostname",
    match(Image, "(?i)\\\\fsutil\.exe$") AND match(CommandLine, "(?i)fsinfo"), "fsutil",
    match(Image, "(?i)\\\\wmic\.exe$") AND match(CommandLine, "(?i)\s(os|computersystem|bios|qfe|csproduct|cpu|baseboard|diskdrive|memphysical|win32_)"), "wmic-system",
    match(Image, "(?i)\\\\reg\.exe$") AND match(CommandLine, "(?i)query.*(CurrentVersion|BIOS|SystemBios|HardwareConfig)"), "reg-version",
    match(CommandLine, "(?i)Get-(WmiObject|CimInstance).*Win32_(OperatingSystem|ComputerSystem|BIOS|Processor)"), "ps-getwmi",
    1=1, null())
| where isnotnull(discovery_cmd)
| eval acct=coalesce(mvindex(mvfilter(User!="NOT_TRANSLATED"),0), User)
| bin _time span=5m
| stats dc(discovery_cmd) as distinct_cmds values(discovery_cmd) as commands values(ParentImage) as parents count by _time host acct
| where distinct_cmds >= 3
| sort - _time
```

### What each piece does

- **Binary scope.** `systeminfo.exe` and `hostname.exe` are near-exclusively used for discovery, so they're high-signal on their own. `wmic.exe`, `reg.exe`, and `powershell.exe` are general-purpose, so the `match()` only counts them when the command line targets a system-info class (`os`/`computersystem`/`bios`/`qfe`/`csproduct` for WMIC, a `CurrentVersion` query for `reg`, a `Win32_OperatingSystem`-family object for PowerShell).
- **`fsutil fsinfo`** is included because it's a common LOLBin way to enumerate drives/volumes during host fingerprinting.
- The classifier/burst split mirrors T1087 exactly: `discovery_cmd` is `null()` for non-matches and dropped by `where isnotnull(...)`; the burst SPL bins into 5-minute windows, counts `dc(discovery_cmd)`, and alerts at `>= 3` distinct types.

**Known false-negative class — cmd.exe built-ins.** `ver` and `set` are *internal* `cmd.exe` commands — they do **not** spawn their own process, so they produce **no EID 1 event**. An attacker fingerprinting purely via `ver`/`set`/`echo %...%` inside a single `cmd.exe` is invisible to this process-based detection. Catching those requires PowerShell/cmd command-line logging (script-block or process-command-line auditing), noted as a complementary control. `systeminfo.exe`, `hostname.exe`, etc. *are* real binaries and do fire EID 1.

## Why This Works

System fingerprinting is the orientation step of an intrusion: the attacker needs the OS build and patch level (to pick exploits), the hostname and domain status (to plan movement), and the hardware/VM indicators (sandbox evasion checks frequently query BIOS/`csproduct` to detect analysis VMs). The information lives in places that must be *queried*, and the built-in query tools spawn observable processes.

As with account discovery, the leverage is clustering, not the single command. One `systeminfo` from an admin is noise; `systeminfo` + `wmic os get` + `hostname` + `reg query ...CurrentVersion` within seconds, especially under a script-host parent, is a fingerprinting sweep. The burst SPL encodes that.

A bonus high-signal variant worth hunting separately: **VM/sandbox-evasion checks**. Malware often runs `wmic bios get serialnumber`, `wmic csproduct get`, or queries `HKLM\...\CurrentVersion\SystemBiosVersion` specifically to detect VirtualBox/VMware. In *this* lab — which **is** VirtualBox — those queries will return tell-tale strings; a real adversary seeing them would likely abort. That makes BIOS/csproduct queries a useful canary in a production environment (legit software rarely needs the BIOS serial).

## Tuning Notes

Validated end-to-end on 2026-06-03 against Atomic Red Team `T1082-1/7/27/39`. The burst SPL fired on the first clean run with `distinct_cmds=4` (`systeminfo`, `hostname`, `wmic-system`, `reg-version`) and a single deduplicated row. Because this detection is the sibling of [T1087](T1087-account-discovery.md), it inherited that detection's two hard-won fixes from the start — and they held:

**Inherited fix #1 — binary classified off `Image`, not `CommandLine`.** The captured `systeminfo` event has `CommandLine: systeminfo` — bare, no `.exe`, no path — so a CommandLine-anchored binary match would have missed it exactly as it did for T1087's `query user`. Keying on `Image` (`C:\Windows\System32\systeminfo.exe`) was correct. Same for the WMIC events, logged as bare `wmic  OS get ...`.

**Inherited fix #2 — multivalued `User` dedup.** The `User` field again carried both `NOT_TRANSLATED` and `DESKTOP-0DU4BT6\analyst`; the `acct` coalesce produced one clean row. (See the real Sample Event below — both values appear under `User`.)

**Calibration this run required — broaden the WMIC argument list.** ART `T1082-27` doesn't just run `wmic os get`; it sweeps `cpu`, `baseboard`, `diskdrive`, `MEMPHYSICAL`, `bios`, and `path win32_VideoController`. The first-draft `wmic-system` classifier only matched `os|computersystem|bios|qfe|csproduct`, so most of that sweep wouldn't have classified. Broadened the argument alternation to include `cpu|baseboard|diskdrive|memphysical|win32_`. The `win32_` token (no trailing `\b`, since `_` is a word char) catches the `path win32_*` form WMIC uses for device classes.

**Calibration — broaden the registry classifier, with a known gap.** The `reg` classifier was widened to `query.*(CurrentVersion|BIOS|SystemBios|HardwareConfig)` so BIOS/version registry discovery (e.g. ART `T1082-30`/`-39`/`-40`) classifies. **Known FN:** the parent of the captured `systeminfo` event chained `reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` — a disk-device enumeration that this classifier deliberately does *not* tag (it scopes to OS-version/BIOS keys, not every `reg query`). That's an intentional precision/recall tradeoff: tagging *all* `reg query` would flood the classifier with benign registry reads. `reg-version` in this run came from `T1082-39`'s `CurrentVersion` query, not the parent's `Disk\Enum` query.

**Confirmed false-negative class — cmd.exe built-ins.** `ver` and `set` (and `echo %VAR%`) are internal `cmd.exe` commands and spawn no process, so they produce no EID 1. ART `T1082-35` ("Check OS version via `ver`") therefore leaves no process-creation trace — expected, not a detection failure. Catching pure-built-in fingerprinting needs command-line/script-block logging, noted as a complementary control.

## False Positive Considerations

The per-command search is intentionally noisy (hunting tool). Expected benign sources:

- **Inventory and asset-management agents** (SCCM, Intune, Lansweeper, PDQ) that periodically run `systeminfo`/`wmic` to collect hardware and OS data — these are the dominant FP source and are *bursty by nature*, so they can trip the burst SPL.
- **Help-desk / admin troubleshooting** — `systeminfo`, `hostname`, `wmic qfe list` (installed patches) during support.
- **Software installers** checking OS version/architecture for compatibility.
- **Monitoring tools** polling system state.

**Tuning recommendations:**

1. **Alert on the burst SPL, hunt on the classifier** — same philosophy as T1087.
2. **Allowlist the inventory agents by `ParentImage`.** Asset agents are the one benign source that *will* trip the burst threshold; identify them in a baseline (their parent is the agent's own service binary) and exclude that parent rather than lowering the threshold.
3. **Weight VM/sandbox-evasion queries higher.** A `wmic bios`/`csproduct` query, or a `reg query` of the BIOS keys, from a non-inventory parent is higher-signal than generic `systeminfo` — legitimate software rarely reads the BIOS serial.
4. **Correlate cross-tactic.** A system-info burst that immediately follows initial access (a freshly spawned Office/`mshta` child) and precedes account discovery (T1087) is the textbook recon sequence — chain them in a later correlation search.

## Test Case

Use [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) on the soc-victim VM. The T1082 atomics run read-only system-info queries — benign, nothing to clean up.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

Invoke-AtomicTest T1082 -ShowDetailsBrief

# The T1082 catalog is large and version-dependent — always run -ShowDetailsBrief.
# The clean process-spawning set validated here was 1/7/27/39:
#   T1082-1  System Information Discovery   -> cmd /c systeminfo & reg query ...
#   T1082-7  Hostname Discovery             -> hostname.exe
#   T1082-27 System Information with WMIC   -> wmic os/bios/cpu/baseboard/...
#   T1082-39 OS Product Name via Registry   -> reg query ...\CurrentVersion
# Run close together so they share a 5-minute bucket:
Invoke-AtomicTest T1082 -TestNumbers 1,7,27,39

# AVOID the WinPwn set (14-23) and Griffon/SkyArk (10,24): they download
# external offensive tooling and trigger Defender. ESXi tests (31,32) and the
# Azure scan (24) don't apply to the Windows victim.
```

**To validate end-to-end:**

1. Confirm the VM clock reads Central, note the wall-clock time.
2. Run several atomics close together.
3. Run the **primary** SPL ("Last 15 minutes") — confirm one row per discovery command, classified.
4. Run the **secondary** SPL — confirm a burst row with `distinct_cmds >= 3`.
5. Paste me back one full raw EID 1 event (the `systeminfo.exe` one is ideal) so I can replace the representative sample and flip to validated.
6. No cleanup needed.

**First-pass calibration check:** run `index=endpoint EventCode=1 Image="*\\systeminfo.exe" | stats count` for the test window to confirm `systeminfo.exe` events land. Watch for any atomic that uses a `cmd.exe` built-in (`ver`/`set`) — those will *not* appear (see the false-negative note), which is expected, not a failure.

## Sample Event

> **Real EID 1 captured during 2026-06-03 lab validation of ART `T1082-1`.** Verbatim from Splunk.

```
06/03/2026 09:16:38.130 PM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=1
EventType=4
ComputerName=DESKTOP-0DU4BT6
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=16587
TaskCategory=Process Create (rule: ProcessCreate)
OpCode=Info
Sid=S-1-5-18
SidType=0
Message=Process Create:
RuleName: -
UtcTime: 2026-06-03 21:16:38.125
ProcessGuid: {22860150-99b6-6a20-9b03-000000000a00}
ProcessId: 7128
Image: C:\Windows\System32\systeminfo.exe
FileVersion: 10.0.19041.1 (WinBuild.160101.0800)
Description: Displays system information
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: sysinfo.exe
CommandLine: systeminfo
CurrentDirectory: C:\Users\analyst\AppData\Local\Temp\
User: DESKTOP-0DU4BT6\analyst
LogonGuid: {22860150-8b77-6a20-82a1-080000000000}
LogonId: 0x8A182
TerminalSessionId: 1
IntegrityLevel: High
Hashes: MD5=EE309A9C61511E907D87B10EF226FDCD,SHA256=6F87CAA51BDEA802045BB281FC2686A3C76364C26A3FFE6C2CCAC4AF5F9DB37B,IMPHASH=C7C3DF13F22D7A13802E6509367A5830
ParentProcessGuid: {22860150-99b6-6a20-9903-000000000a00}
ParentProcessId: 1140
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "cmd.exe" /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
ParentUser: DESKTOP-0DU4BT6\analyst
```

(As with the T1087 sample, the auto-extracted `User` field is multivalued — `NOT_TRANSLATED` and `DESKTOP-0DU4BT6\analyst` — handled by the burst SPL's `acct` dedup.)

### Analyst notes on this real captured event

- **`Image: ...\systeminfo.exe`** with **`CommandLine: systeminfo`** — `systeminfo` has essentially no use other than discovery; it pulls OS build, patch level, domain role, and hardware in one shot. Note the command line is the bare word `systeminfo` with no path or `.exe` — exactly why the classifier keys the binary on `Image`, not `CommandLine`.
- **`ParentCommandLine: "cmd.exe" /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`** — the real high-signal view. The atomic chained *two* discovery actions in one shell line: `systeminfo` (this event) and a `reg query` for disk devices. The parent command line reveals the multi-step recon before the child events are even fully correlated. Note the `reg query` here targets `CurrentControlSet\Services\Disk\Enum`, which the `reg-version` classifier intentionally does *not* tag (it scopes to OS-version/BIOS keys) — the `reg-version` in this run's burst came from the separate `T1082-39` `CurrentVersion` query.
- **`OriginalFileName: sysinfo.exe`** — note the on-disk file `systeminfo.exe` carries the internal original name `sysinfo.exe`. Detections that pivot on `OriginalFileName` (a useful rename-evasion check) need to know the internal name differs from the file name here.
- **`CurrentDirectory: C:\Users\analyst\AppData\Local\Temp\`** — ART staging. A system-info sweep whose working directory is `\Temp\`/`\AppData\` is itself a triage signal in production.
- **`ParentImage: ...\cmd.exe`** — benign in the lab (shell from the ART session). The triage question is always one level up: a `cmd.exe` under `explorer.exe` is a human; a `cmd.exe` under `mshta.exe`/`wscript.exe`/an Office app running this sweep is recon-after-initial-access. The burst SPL's `parents` field (`powershell.exe`, `cmd.exe` this run) is where that shows up.
- **`Hashes: ...SHA256=6F87CAA5...`** — the real Microsoft-signed `systeminfo.exe` hash; a mismatch or a non-`System32` path would itself be the lead.

## References

- MITRE ATT&CK: [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- Atomic Red Team test catalog: [T1082 atomics](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md)
- Microsoft docs: [systeminfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)
- LOLBAS: [wmic.exe](https://lolbas-project.github.io/lolbas/OSBinaries/Wmic/) / [reg.exe](https://lolbas-project.github.io/lolbas/OSBinaries/Reg/)
- Related lab detection: [T1087 — Account Discovery](T1087-account-discovery.md) (shares the burst-correlation pattern)
