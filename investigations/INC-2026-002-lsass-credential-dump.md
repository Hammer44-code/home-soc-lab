# INC-2026-002 — LSASS Memory Dump (comsvcs.dll MiniDump)

| | |
|---|---|
| **Incident ID** | INC-2026-002 |
| **Title** | Credential theft via LSASS process-memory dump using the `comsvcs.dll` MiniDump LOLBin |
| **Severity** | **Critical** |
| **Status** | Closed — contained (lab exercise) |
| **Classification** | Confirmed True Positive |
| **Affected host** | `DESKTOP-0DU4BT6` — soc-victim, `192.168.56.20` (Windows 10 22H2) |
| **Actor account** | `DESKTOP-0DU4BT6\analyst` (local Administrator) |
| **Date of activity** | 2026-05-20 10:07 (Central) |
| **Report date** | 2026-06-24 |
| **Analyst** | Nolan — Tier 1 SOC (home-soc-lab) |
| **ATT&CK** | TA0006 Credential Access — T1003.001 (OS Credential Dumping: LSASS Memory) |

---

## 1. Executive Summary

A process on `DESKTOP-0DU4BT6` opened the **LSASS** process and copied its memory
to disk using the built-in `comsvcs.dll` **MiniDump** function — a credential-theft
technique. LSASS holds, in memory, the credentials of every account that has
authenticated to the host since boot: cleartext passwords (where reversibly
stored), NTLM hashes, Kerberos tickets, and DPAPI keys. A successful dump is
treated as a **full credential-compromise event** for the host.

The activity was detected at the moment LSASS was accessed — *before* the dump
file was finished writing — by a Sysmon ProcessAccess (EID 10) tripwire. The dump
file (`lsass-comsvcs.dmp`) was confirmed written and must be treated as live
credential material. All credentials used on this host require rotation.

This is a **focused, single-alert investigation**, and in the broader picture it
is **Phase 6b of [INC-2026-001](INC-2026-001-multistage-intrusion.md)** — the
credential-theft step of the full intrusion. It is documented separately to show
fast, high-confidence triage of a single Critical alert.

> **Lab note:** real telemetry captured during validation of detection
> [T1003.001](../detections/T1003.001-lsass-access.md) (ART test `T1003.001-2`,
> 2026-05-20). All field values below are verbatim from Splunk.

---

## 2. Detection Trigger

The LSASS-access detection ([T1003.001](../detections/T1003.001-lsass-access.md))
fired on its primary Sysmon EID 10 search:

```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*\\lsass.exe"
| where NOT SourceImage IN (
    "C:\\Windows\\System32\\wininit.exe", "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\MsMpEng.exe", "C:\\Program Files\\Windows Defender\\MsMpEng.exe")
| where match(GrantedAccess, "(?i)^0x(1010|1410|1438|143a|1fffff)$")
   OR match(CallTrace, "(?i)(comsvcs\.dll|dbghelp\.dll|dbgcore\.dll|UNKNOWN)")
| table _time host SourceImage SourceProcessId TargetImage GrantedAccess CallTrace
```

The search deliberately excludes the handful of OS components that legitimately
open LSASS every boot (LSA, SCM, session manager, Defender), so a surviving hit is
inherently suspicious. The triggering event:

```
05/20/2026 10:07:46.745 AM   EventCode=10   ComputerName=DESKTOP-0DU4BT6
RuleName:       T1003
SourceImage:    C:\Windows\System32\rundll32.exe   (PID 4356)
TargetImage:    C:\Windows\system32\lsass.exe      (PID 668)
GrantedAccess:  0x1410
CallTrace:      ...KERNELBASE.dll+28d3e | C:\windows\System32\comsvcs.dll+273ff | rundll32.exe+46ab ...
SourceUser:     DESKTOP-0DU4BT6\analyst
TargetUser:     NT AUTHORITY\SYSTEM
```

---

## 3. Investigation & Analysis

**Step 1 — Is the source legitimate?** `SourceImage` is `rundll32.exe`. By itself
that is a normal Windows utility, but it is **not** one of the OS components that
should be opening LSASS, and it was not excluded by the allowlist. → proceed.

**Step 2 — Were the access rights consistent with reading memory?**
`GrantedAccess=0x1410` decodes to `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) +
`PROCESS_QUERY_INFORMATION` (0x400) + **`PROCESS_VM_READ`** (0x10) — the minimum
rights needed to enumerate *and read* the target's memory. `PROCESS_VM_READ` is
the tell: a process that only wants to *list* LSASS would not request it. (Worth
noting: `comsvcs.dll` is surgical and asks for exactly `0x1410`, not the
`0x1FFFFF` PROCESS_ALL_ACCESS that many writeups assume — a mask-only rule keyed on
all-access would have missed this.)

**Step 3 — Does the call stack confirm the technique?** `CallTrace` contains
**`comsvcs.dll+273ff`**. `comsvcs.dll` (COM+ Services) has no legitimate reason to
be on the call stack of an `OpenProcess()` against LSASS; its only function that
does this is **`MiniDump`** (export ordinal #-24). This is the smoking gun — the
LOLBAS `comsvcs.dll MiniDump` credential-dump method. → **confirmed malicious.**

**Step 4 — Corroborate with the command line (secondary search).** The paired
Sysmon EID 1 showed the invoking command:

```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> <out>.dmp full
```

confirming the method independently of the call stack.

**Step 5 — Did the dump succeed?** A paired Sysmon EID 11 (FileCreate) recorded the
output file **`C:\Users\analyst\AppData\Local\Temp\lsass-comsvcs.dmp`** (~55 MB).
The dump completed; the file contains real credential material.

**Step 6 — Who and what privilege?** `SourceUser=DESKTOP-0DU4BT6\analyst` (a local
admin) accessing `TargetUser=NT AUTHORITY\SYSTEM` (LSASS). A privileged-boundary
crossing by a local account that, in the full intrusion, was itself compromised by
a password spray (see INC-2026-001).

---

## 4. Scope & Impact

- **Credential compromise:** all credentials cached in LSASS at 10:07 on
  `DESKTOP-0DU4BT6` must be considered stolen — cleartext passwords where present,
  NTLM hashes, and Kerberos tickets for every account authenticated since boot.
- **Artifact:** `…\Temp\lsass-comsvcs.dmp` is live secret material until deleted;
  it is also the offline analysis input the attacker would run through Mimikatz/
  pypykatz.
- **Reuse risk:** stolen hashes/tickets enable pass-the-hash / pass-the-ticket
  lateral movement and offline cracking.
- **Host:** assume full compromise of `DESKTOP-0DU4BT6` (consistent with the
  SYSTEM-level access established in INC-2026-001).

---

## 5. Indicators of Compromise

| Type | Indicator |
|---|---|
| Process access | EID 10 → `lsass.exe`, `GrantedAccess` ∈ {`0x1010`,`0x1410`,`0x1438`,`0x143a`,`0x1fffff`} |
| Call stack | `comsvcs.dll` (also `dbghelp.dll`/`dbgcore.dll`, or `UNKNOWN` for reflective code) in `CallTrace` of an LSASS access |
| Command line | `rundll32.exe …comsvcs.dll MiniDump …` (also ordinal form `comsvcs.dll #+-24`) |
| File | `…\Temp\lsass-comsvcs.dmp` (or any `.dmp` of LSASS) |
| Source process | `rundll32.exe` opening `lsass.exe` (not in the OS allowlist) |

---

## 6. Containment, Eradication & Recovery

1. **Isolate** `DESKTOP-0DU4BT6` from the network.
2. **Rotate every credential** used on the host since its last boot — assume all
   are compromised. Prioritise privileged and reused accounts.
3. **Securely delete** `…\Temp\lsass-comsvcs.dmp` (and search for copies / renames
   / exfil).
4. **Rebuild** the host from known-good media (LSASS dump implies the box should
   not be trusted again).
5. **Harden against recurrence:**
   - Enable **LSA Protection (RunAsPPL)** so LSASS runs as a protected process —
     userland dumpers can no longer open it for read.
   - Re-enable/enforce the Defender **ASR rule
     `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`** ("Block credential stealing from
     LSASS"), which blocks this at `OpenProcess` even with RTP toggled.
   - Consider **Credential Guard** to move secrets out of LSASS entirely.

---

## 7. Analyst Notes & Lessons

- **Detect at the syscall, not the file.** The EID 10 tripwire fired on the
  `OpenProcess()` against LSASS — before the `.dmp` was written. That is more
  robust than waiting for a dump *file*, because dumpers can stream memory over the
  network without ever touching disk, rename the extension, or write to an
  alternate data stream.
- **The access mask carries intent.** `PROCESS_VM_READ` in the granted mask is the
  difference between "querying LSASS metadata" (benign, common) and "reading LSASS
  memory" (theft). Filtering on the read-capable masks is what keeps this alert
  quiet enough to be actionable.
- **`comsvcs.dll` on an LSASS call stack is dispositive.** No tuning, no scoring —
  if `comsvcs.dll` (or a bare `UNKNOWN` frame) appears in the CallTrace of an LSASS
  access, it is credential dumping until proven otherwise.
- **Known gap:** a kernel-mode "bring-your-own-vulnerable-driver" (BYOVD) dumper
  can read LSASS without a userland EID 10. That is addressed at a different tier
  (driver-load monitoring), out of scope for this rule.

## References

- Detection write-up (full SPL, raw event, tuning): [T1003.001 — LSASS Memory Access](../detections/T1003.001-lsass-access.md)
- Parent incident: [INC-2026-001 — Multi-Stage Intrusion](INC-2026-001-multistage-intrusion.md) (this is Phase 6b)
- MITRE ATT&CK: <https://attack.mitre.org/techniques/T1003/001/>
- LOLBAS: [comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/)
- Microsoft: [PROCESS_ Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
