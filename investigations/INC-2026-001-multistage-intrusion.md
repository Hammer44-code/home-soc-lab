# INC-2026-001 — Multi-Stage Intrusion: Network Credential Compromise → SYSTEM → Credential Theft → Anti-Forensics

| | |
|---|---|
| **Incident ID** | INC-2026-001 |
| **Title** | Multi-stage intrusion of a Windows endpoint via password spray, SMB lateral movement to SYSTEM, credential dumping, and event-log clearing |
| **Severity** | **Critical** |
| **Status** | Closed — contained (lab exercise) |
| **Classification** | Confirmed True Positive — hands-on-keyboard intrusion |
| **Affected host** | `DESKTOP-0DU4BT6` — soc-victim, `192.168.56.20` (Windows 10 22H2) |
| **Attacker source** | `192.168.56.30` — soc-kali (adversary-controlled host on the lab network) |
| **Compromised account** | `analyst` (local Administrator) — SID `S-1-5-21-2096176171-2890088598-4130571964-1001` |
| **Date of activity** | 2026-06-23 (scenario timeline — see Methodology & Provenance) |
| **Report date** | 2026-06-24 |
| **Analyst** | Nolan — Tier 1 SOC (home-soc-lab) |
| **ATT&CK coverage** | 7 tactics / 10 techniques (mapping below) |

---

## 1. Executive Summary

On 2026-06-23 an attacker operating from `192.168.56.30` compromised the Windows
workstation `DESKTOP-0DU4BT6` and obtained the highest possible level of control
(`NT AUTHORITY\SYSTEM`). The attacker began with a **password-spraying attack**
over SMB that guessed the password of the local administrator account `analyst`.
Using that single credential they moved laterally onto the host and executed code
as SYSTEM via the **Windows Service Control Manager** (an "smbexec"-style
service-install technique). With full control they performed reconnaissance,
**disabled Windows Defender**, **stole the host's stored password hashes** (the
SAM/SYSTEM/SECURITY registry hives — the full offline-crackable set), established
**persistence**, and finally **cleared the Windows event logs** in an attempt to
destroy the evidence of everything they had done.

The intrusion was detected and fully reconstructed. Critically, the attacker's
final log-clearing step **failed to hide anything**: because every event is
forwarded off-host to Splunk the moment it is written, the cleared logs were
already safely in the SIEM, and the act of clearing them generated its own
high-fidelity alert. The single compromised credential (`analyst`) and the host
itself must be treated as fully compromised; remediation requires credential
rotation across the environment and a host rebuild.

**Business impact:** complete compromise of one endpoint and one privileged local
credential, with theft of all local-account password hashes (enabling offline
cracking and pass-the-hash reuse). In a production environment this is a
containment-now incident.

---

## 2. Methodology & Provenance (lab disclosure)

This is a **detection-engineering lab exercise**, and this report is written to
the standard of a real Tier 1 incident investigation. In the interest of honesty:

- The telemetry is **real** — every command, IP, account, event ID, access mask,
  service binPath, and registry path quoted below was genuinely captured in
  `index=endpoint` in Splunk during controlled attack validations. Nothing is
  fabricated.
- The attacker stages were validated as **separate exercises** across several
  weeks (see Appendix A for the true per-stage capture dates). For this report
  they have been **assembled onto a single coherent incident timeline** (2026-06-23
  afternoon) to demonstrate the end-to-end investigative workflow — alert triage,
  cross-source correlation, scoping, MITRE mapping, and reporting — that a real
  multi-stage intrusion demands. The cred-reuse chain (spray → reuse `analyst`
  for lateral movement) is genuine: the smbexec stage really did reuse the
  credential the spray really did compromise.
- Each phase links to the corresponding **detection write-up** in
  [`../detections/`](../detections/README.md), which contains the full SPL, the
  verbatim raw event, and the tuning history behind that detection.

---

## 3. Detection Trigger

The case opened on a **self-escalating password-spray alert**. The spray
detection ([T1110.003](../detections/T1110.003-password-spraying.md)) ships two
correlated searches; the second one fired at **Critical**:

```spl
index=endpoint sourcetype=WinEventLog (EventCode=4625 OR EventCode=4624) Logon_Type=3
| eval target=mvindex(mvfilter(Account_Name!="-"),0)
| eval outcome=if(EventCode=4624,"success","failure")
| where isnotnull(target)
| bin _time span=5m
| stats dc(eval(if(outcome="failure",target,null()))) as failed_targets
        values(eval(if(outcome="success",target,null()))) as compromised
        count(eval(outcome="failure")) as failures
        count(eval(outcome="success")) as successes
        by _time src
| where failed_targets >= 3
| eval severity=if(successes>0,"CRITICAL - spray succeeded","HIGH - spray attempt")
```

**Alert output:** `src=192.168.56.30`, `failed_targets=5`, `successes=1`,
`compromised=analyst`, `severity=CRITICAL - spray succeeded`.

That one row is the whole reason this became an incident rather than a noise
alert: a wall of failed logons from a single host **with a success buried inside
it** means the attacker now holds a valid credential. The investigation below was
the work of answering *"what did they do with it?"*

---

## 4. Investigation Timeline

All times Central (US), 2026-06-23. Each row links to the data source that
established it.

| # | Time | Phase (ATT&CK) | What happened | Evidence (host = `DESKTOP-0DU4BT6`) |
|---|---|---|---|---|
| 1 | 17:08 | Recon | Anonymous SMB host fingerprint from `192.168.56.30` | `4625`, `Account_Name=-`, `Sub_Status=0x0` (null-session probe) |
| 2 | 17:10–17:11 | **Initial Access** — Password Spraying (T1110.003) | One password (`Sledge44`) sprayed across 6 local accounts over SMB | 5× `4625` (Type 3) + 1× `4624` success, all `src=192.168.56.30` |
| 3 | 17:11 | Credential validity leak | Spray's `Sub_Status` codes enumerate which accounts exist | `0xC000006A` (administrator, guest = real) vs `0xC0000064` (admin, user, jsmith = don't exist) |
| 4 | 17:30 | **Lateral Movement / Execution as SYSTEM** (T1021.002 / T1569.002) | `analyst` cred reused for smbexec — a LocalSystem service is created over `IPC$`/SVCCTL and runs `whoami` → `nt authority\system` | `7045` service install `cAlUxWGVPn`, `Service_Account=LocalSystem`; correlated `4624` Type 3 `analyst` / `.30` |
| 5 | 17:33 | **Discovery** (T1087.001, T1082) | Burst of account- and system-enumeration commands to orient on the host | EID 1 burst: `whoami`, `net user`, `net localgroup`, `systeminfo`, `hostname`, `ipconfig` |
| 6 | 17:38 | **Defense Evasion** — Impair Defenses (T1562.001) | Windows Defender real-time protection disabled to clear the way for credential theft | `Set-MpPreference -DisableRealtimeMonitoring $true`; EID 13 on Defender keys (committed by `MsMpEng.exe`/SYSTEM) |
| 7 | 17:40 | **Privilege Escalation** — Bypass UAC (T1548.002) | fodhelper auto-elevate registry hijack to obtain an interactive high-integrity session | EID 13 hijack-key write (`HKCU\…\ms-settings\…\command`) + elevated EID 1 child, `IntegrityLevel=High` |
| 8 | 17:44 | **Credential Access** — SAM dump (T1003.002) | The SAM + SYSTEM + SECURITY hives saved in one chained command — the full crackable set | 3× EID 1 `reg save HKLM\sam\|system\|security`, `IntegrityLevel=High`; secondary `crackable_set=yes` |
| 8b | 17:45 | **Credential Access** — LSASS dump (T1003.001) | LSASS process memory dumped via `comsvcs.dll MiniDump` for live credentials | EID 10 `rundll32.exe`→`lsass.exe`, `GrantedAccess=0x1410`, `comsvcs.dll` in CallTrace → **see [INC-2026-002](INC-2026-002-lsass-credential-dump.md)** |
| 9 | 17:50 | **Persistence** (T1547.001 / T1053.005) | Registry Run key + scheduled task planted to survive reboot | EID 13 Run-key value set; `4698` / EID 1 `schtasks /create` |
| 10 | 17:55 | **Defense Evasion** — Clear Event Logs (T1070.001) | Security + Application logs cleared to destroy local evidence | `1102` (Security cleared) + `104` (Application cleared), subject `analyst` |

---

## 5. Attack Narrative by Phase

### Phase 1 — Initial Access: Password Spraying (T1110.003)

The attacker ran a password spray from `192.168.56.30` against six local account
names, trying the single password `Sledge44` against each (the spray shape:
*one password, many accounts*, which stays under per-account lockout thresholds).
Five accounts failed (`4625`) and one — **`analyst`, a local Administrator** —
succeeded (`4624`). All events were network logons (`Logon_Type=3`) carrying
`Source_Network_Address=192.168.56.30`.

A free bonus for the attacker (and a useful triage signal for us) is the
`Sub_Status` field on the failures, which **leaks account validity**:

| `Sub_Status` | Meaning | Accounts |
|---|---|---|
| `0xC000006A` | Wrong password — **account exists** | `administrator`, `guest` |
| `0xC0000064` | No such user — **account does not exist** | `admin`, `user`, `jsmith` |

So in addition to compromising `analyst`, the spray confirmed `administrator` and
`guest` as real follow-up targets. The top-level `Status` (`0xC000006D`) is
generic and identical on every failure — triage must read `Sub_Status`.

> **Full detection, SPL, and raw `4625`:** [T1110.003 — Password Spraying](../detections/T1110.003-password-spraying.md)

### Phase 2 — Lateral Movement & Execution as SYSTEM (T1021.002 / T1569.002)

With a valid local-admin credential in hand, the attacker reused `analyst:Sledge44`
to move onto the host over SMB. They enumerated the administrative shares
(`ADMIN$`, `C$` returned `READ,WRITE` and the attacker tool reported `(Pwn3d!)`),
then executed code via the **smbexec method**: open the `IPC$` named pipe, talk to
the **Service Control Manager**, and create a temporary service whose image path
*is* a shell command. The service runs as **LocalSystem**, so the payload ran as
`NT AUTHORITY\SYSTEM` — lateral movement and privilege escalation in one primitive.

The smoking gun is the service-install event (`7045`):

```
EventCode=7045  LogName=System  SourceName=Microsoft-Windows-Service Control Manager
Service Name:      cAlUxWGVPn
Service File Name: %COMSPEC% /Q /c echo whoami ^> \\%COMPUTERNAME%\C$\aPgSmH 2^>^&1
                   > %TEMP%\WImZsu.bat & %COMSPEC% /Q /c %TEMP%\WImZsu.bat
                   & %COMSPEC% /Q /c del %TEMP%\WImZsu.bat
Service Account:   LocalSystem
```

The detection keys on the **shape of the binPath**, not any string (the service
name `cAlUxWGVPn` and bat name `WImZsu.bat` are random every run): a service whose
image is a command interpreter (`%COMSPEC%`) running an `echo … ^> C$\… 2^>^&1 >
%TEMP%\*.bat & … & del` chain is the smbexec fingerprint. No legitimate service
has this form.

The `7045` is a **local SCM event and carries no source IP** — the SCM doesn't
know the request arrived over SMB. The attacker's source was recovered by
**correlating the `7045` to the Type-3 `4624`** network logon in the same 5-minute
window: `logon_user=analyst`, `src=192.168.56.30`. This cross-channel correlation
(System log + Security log) is what turned "this host was popped" into "this host
was popped by `analyst` from `192.168.56.30`."

> **Full detection, SPL, correlation, and raw `7045`:** [T1021.002 — SMB Admin Shares / smbexec](../detections/T1021.002-smb-admin-shares.md)

### Phase 3 — Discovery (T1087.001, T1082)

Now executing on the host, the attacker ran a **burst of reconnaissance
commands** to orient — account discovery (`whoami`, `net user`, `net localgroup`)
and system information (`systeminfo`, `hostname`, `ipconfig`). Individually these
are everyday admin commands; the detectable signal is the **cluster** — several
distinct discovery commands from one session in a few minutes, which is the
hallmark of an operator (or an automated recon module) fingerprinting a freshly
accessed host. The burst-correlation searches surfaced it above the background of
single, legitimate invocations.

> **Full detections:** [T1087 — Account Discovery](../detections/T1087-account-discovery.md) · [T1082 — System Information Discovery](../detections/T1082-system-info-discovery.md)

### Phase 4 — Defense Evasion: Impair Defenses (T1562.001)

Before stealing credentials, the attacker **disabled Windows Defender real-time
protection** (`Set-MpPreference -DisableRealtimeMonitoring $true`) — a necessary
prerequisite, because Defender blocks SAM/LSASS dumping behaviour on a default
endpoint. A notable forensic subtlety surfaced here: the cmdlet **spawns no
process** (no EID 1), and the registry change is committed by **`MsMpEng.exe` as
`NT AUTHORITY\SYSTEM`** (Defender's own engine brokers the write), not by the
issuing shell — so the registry event (EID 13) attributes to the broker, not the
human. Identifying the actor required correlating to the surrounding session.

> **Full detection:** [T1562.001 — Impair Defenses](../detections/T1562.001-impair-defenses.md)

### Phase 5 — Privilege Escalation: Bypass UAC (T1548.002)

To obtain a reliable **interactive high-integrity session** (the smbexec exec is a
non-interactive one-shot), the attacker used a **fodhelper auto-elevate registry
hijack** — planting a command under `HKCU\…\ms-settings\…\command` and triggering
the auto-elevating `fodhelper.exe`, which launches the planted payload at **High**
integrity with no consent prompt. The detection caught both stages: the **plant**
(EID 13 hijack-key write) and the **payoff** (an elevated EID 1 child with
`IntegrityLevel=High`).

> **Full detection:** [T1548.002 — Bypass UAC](../detections/T1548.002-bypass-uac.md)

### Phase 6 — Credential Access: SAM hive dump (T1003.002)

With Defender blinded, the attacker dumped the on-disk credential store. In one
chained command they saved all three relevant registry hives:

```
ParentCommandLine: "cmd.exe" /c reg save HKLM\sam %temp%\sam
                   & reg save HKLM\system %temp%\system
                   & reg save HKLM\security %temp%\security
```

Each `reg save` produced its own EID 1 (`Image=reg.exe`, `IntegrityLevel=High`,
`User=DESKTOP-0DU4BT6\analyst`). The **secondary "crackable-set" search**
recognised that **SAM + SYSTEM were grabbed in the same window** and flagged
`crackable_set=yes` — meaning the attacker has the local password hashes *and* the
SYSTEM boot key needed to decrypt them: the complete, offline-crackable set. (SAM
alone is useless without SYSTEM; the detection specifically escalates on that
pairing.)

Note the detection fires on the **attempt, not the outcome**: even the parts that
errored (e.g. `reg export HKLM\security` → "Access is denied", since the SECURITY
hive denies read to Administrators) still produced their intent-bearing EID 1.

> **Full detection, crackable-set logic, and raw `reg save` EID 1:** [T1003.002 — SAM Credential Access](../detections/T1003.002-sam-credential-access.md)

### Phase 6b — Credential Access: LSASS memory dump (T1003.001)

In parallel the attacker dumped **LSASS process memory** with the `comsvcs.dll
MiniDump` living-off-the-land method to harvest live, cached credentials (cleartext
where available, NTLM hashes, Kerberos tickets). This produced a Sysmon EID 10
(`rundll32.exe` opening `lsass.exe` with `GrantedAccess=0x1410` and `comsvcs.dll`
on the call stack). **This phase is documented in depth as its own focused case,
[INC-2026-002](INC-2026-002-lsass-credential-dump.md)**, which doubles as an
example of fast single-alert Critical triage.

### Phase 7 — Persistence (T1547.001 / T1053.005)

To survive a reboot the attacker established two redundant persistence mechanisms:
a **registry Run key** (EID 13 value set under `…\CurrentVersion\Run`, the
tool-agnostic service-written tripwire) and a **scheduled task** (`schtasks
/create`; the task XML is written to `C:\Windows\System32\Tasks\…` by the Schedule
service). Both are caught by anchoring on the *effect* (the Run-key write / the
task registration) rather than any specific tool.

> **Full detections:** [T1547.001 — Registry Run Keys](../detections/T1547.001-registry-run-keys.md) · [T1053.005 — Scheduled Task](../detections/T1053.005-scheduled-task.md)

### Phase 8 — Anti-Forensics: Clear Event Logs (T1070.001)

Finally, the attacker **cleared the Windows event logs** to destroy evidence —
the Security audit log (`wevtutil cl Security` → EID **1102**) and the Application
log (→ EID **104**). The subject on the 1102 was `DESKTOP-0DU4BT6\analyst`.

**This step failed in its purpose, and that is the central lesson of the
incident.** The Splunk Universal Forwarder ships every event off the host the
instant it is written, so by the time the attacker ran `wevtutil cl`, everything
they were trying to erase was already in `index=endpoint` on a machine they did
not control. Worse for them, the **clear itself generates EID 1102/104**, which
also forwarded — so the anti-forensic action became a high-confidence alarm that
pinpoints exactly when the attacker decided to cover their tracks. Log clearing is
futile against a forwarding SIEM.

> **Full detection and raw 1102:** [T1070.001 — Clear Windows Event Logs](../detections/T1070.001-clear-event-logs.md)

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | Detection (lab) | Key evidence |
|---|---|---|---|
| Initial Access / Credential Access | T1110.003 — Password Spraying | [T1110.003](../detections/T1110.003-password-spraying.md) | 5× `4625` + 1× `4624`, `src=192.168.56.30`, `compromised=analyst` |
| Lateral Movement | T1021.002 — SMB/Windows Admin Shares | [T1021.002](../detections/T1021.002-smb-admin-shares.md) | `7045` `cAlUxWGVPn`, `LocalSystem`, smbexec binPath |
| Execution | T1569.002 — Service Execution | (same `7045`) | service runs as SYSTEM → `whoami` = `nt authority\system` |
| Discovery | T1087.001 — Account Discovery | [T1087](../detections/T1087-account-discovery.md) | EID 1 burst: `whoami` / `net user` / `net localgroup` |
| Discovery | T1082 — System Information Discovery | [T1082](../detections/T1082-system-info-discovery.md) | EID 1 burst: `systeminfo` / `hostname` / `ipconfig` |
| Defense Evasion | T1562.001 — Impair Defenses | [T1562.001](../detections/T1562.001-impair-defenses.md) | `Set-MpPreference -DisableRealtimeMonitoring`; EID 13 via `MsMpEng` |
| Privilege Escalation | T1548.002 — Bypass UAC | [T1548.002](../detections/T1548.002-bypass-uac.md) | fodhelper EID 13 hijack + elevated EID 1 (`IntegrityLevel=High`) |
| Credential Access | T1003.002 — SAM | [T1003.002](../detections/T1003.002-sam-credential-access.md) | `reg save HKLM\sam\|system\|security`, `crackable_set=yes` |
| Credential Access | T1003.001 — LSASS Memory | [T1003.001](../detections/T1003.001-lsass-access.md) | EID 10 → `lsass.exe`, `0x1410`, `comsvcs.dll` *(see INC-2026-002)* |
| Persistence | T1547.001 — Registry Run Keys | [T1547.001](../detections/T1547.001-registry-run-keys.md) | EID 13 Run-key value set |
| Persistence | T1053.005 — Scheduled Task | [T1053.005](../detections/T1053.005-scheduled-task.md) | `schtasks /create` / `4698` |
| Defense Evasion | T1070.001 — Clear Event Logs | [T1070.001](../detections/T1070.001-clear-event-logs.md) | `1102` (Security) + `104` (Application) cleared |

---

## 7. Scope & Impact Assessment

- **Host:** `DESKTOP-0DU4BT6` (`192.168.56.20`) is **fully compromised** — the
  attacker executed as `NT AUTHORITY\SYSTEM`. Assume total loss of confidentiality
  and integrity on this host. It must be rebuilt from known-good media; cleaning
  in place is not sufficient after SYSTEM-level access plus credential theft.
- **Credentials:** **All local-account hashes** on the host were exfiltrated (SAM +
  SYSTEM = full crackable set), plus any credentials cached in LSASS memory at the
  time (see INC-2026-002). Every local account must be considered compromised. The
  `analyst` password (`Sledge44`) is known-bad and was used interactively — it,
  and any place it is reused, requires immediate rotation.
- **Lateral movement risk:** the stolen hashes enable **pass-the-hash** reuse and
  offline cracking. In a multi-host environment, any host sharing the `analyst`
  credential (or a cracked local password) is at immediate risk. This single
  endpoint lab limits blast radius, but the technique scales directly.
- **Attacker source:** `192.168.56.30` is adversary-controlled and should be
  blocked/isolated at the network layer.
- **Evidence integrity:** despite the log-clearing attempt, **full forensic
  timeline is intact** in Splunk — the forwarded copy is authoritative and was not
  reachable by the attacker.

---

## 8. Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|---|---|---|
| Source IP | `192.168.56.30` | Attacker host (spray, SMB lateral movement) |
| Account | `analyst` (local Admin) | Compromised credential; password `Sledge44` (known-bad) |
| Auth pattern | ≥3 distinct `4625` `Logon_Type=3` from one `src` in 5 min | Password spray |
| Service install | `7045` with `%COMSPEC%` + `.bat` + `C$` redirection binPath | smbexec — random service/bat names (e.g. `cAlUxWGVPn` / `WImZsu.bat`) |
| Service account | `LocalSystem` on an unknown demand-start service | smbexec SYSTEM exec |
| Process access | EID 10 → `lsass.exe`, `GrantedAccess` ∈ {`0x1010`,`0x1410`,`0x1438`,`0x143a`,`0x1fffff`}, `comsvcs.dll` in CallTrace | LSASS dump |
| Command line | `reg save HKLM\sam\|system\|security`, `esentutl /vss …config\SAM` | SAM hive dump |
| Defender | `Set-MpPreference -DisableRealtimeMonitoring $true`; EID 13 on Defender keys via `MsMpEng` | Impair defenses |
| Registry | `HKCU\…\ms-settings\…\command` hijack value | fodhelper UAC bypass |
| File artifacts | `%TEMP%\sam`, `%TEMP%\system`, `%TEMP%\security`, `%TEMP%\lsass-comsvcs.dmp` | Dumped credential material (delete as secrets) |
| Event | `1102` (Security cleared) / `104` (Application cleared) | Anti-forensics |

---

## 9. Containment, Eradication & Recovery

**Immediate (containment):**
1. **Isolate** `DESKTOP-0DU4BT6` from the network (preserve it powered-on for
   forensics if needed; the SIEM copy is already safe regardless).
2. **Block / isolate** `192.168.56.30` at the network layer.
3. **Disable `analyst`** and force-expire the credential everywhere it exists.

**Eradication:**
4. **Rebuild the host** from known-good media — do not clean in place (SYSTEM-level
   compromise + credential theft).
5. **Rotate all local-account passwords** on the (rebuilt) host and anywhere the
   `analyst` credential or its password was reused. Treat all local hashes as
   cracked.
6. **Delete dumped credential files** if recovering any data from the host
   (`%TEMP%\sam`/`system`/`security`/`lsass-comsvcs.dmp`).

**Recovery & hardening:**
7. **Re-enable and re-arm Windows Defender** (real-time protection, Tamper
   Protection, the LSASS ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`).
8. **Address the root cause — the weak/guessable password.** Enforce a strong
   password policy and account-lockout threshold so spraying is not viable; the
   entire chain started from one guessable admin password.
9. **Restrict SMB admin-share access** / enable LSA protection (RunAsPPL) and
   consider blocking `Logon_Type=3` for local admin accounts where feasible.

---

## 10. Detection Gaps & Lessons Learned

- **The forwarding SIEM is the hero.** The single most important architectural
  decision — shipping events off-host in real time via the Universal Forwarder —
  is what made the attacker's log-clearing futile and preserved the full timeline.
  The anti-forensic step became an alert instead of a blind spot.
- **Correlation is the analyst skill on display.** No single event told the story.
  The incident only became coherent by joining across channels and time: the
  Critical verdict came from correlating `4625`+`4624` (spray), the attacker IP for
  the SYSTEM exec came from joining `7045` (System log) to `4624` (Security log),
  and the credential-theft severity came from recognising the SAM+SYSTEM *pairing*
  across multiple EID 1 events.
- **Some actors are invisible at the obvious layer.** Two stages hide the human
  actor: `Set-MpPreference` (no process; registry write brokered by `MsMpEng` as
  SYSTEM) and a bare in-session log-clear cmdlet (no new process). Both were still
  caught — by the *effect* (the registry change; the 1102/104 service-written
  events) rather than the actor. Anchoring detections on the effect, not the tool,
  is what closes these gaps.
- **`Sub_Status` is free intelligence.** The spray didn't just compromise an
  account — its failure sub-status codes handed us (and the attacker) a list of
  which accounts are real. Worth surfacing decoded in the alert.
- **Root cause is mundane.** A Critical, SYSTEM-level, multi-stage intrusion began
  with one weak admin password. The most valuable preventive control here is not a
  new detection — it is password policy and lockout.

---

## Appendix A — Provenance (true per-stage capture dates)

The stages were validated as independent lab exercises and assembled into the
single 2026-06-23 scenario above. Actual capture dates (all real telemetry):

| Phase | Technique | True validation date |
|---|---|---|
| 1 | T1110.003 Password Spraying | 2026-06-15 |
| 2 | T1021.002 SMB / smbexec | 2026-06-23 |
| 3 | T1087 / T1082 Discovery | 2026-06-03 |
| 4 | T1562.001 Impair Defenses | 2026-06-10 |
| 5 | T1548.002 Bypass UAC | 2026-06-10/11 |
| 6 | T1003.002 SAM dump | 2026-06-10 |
| 6b | T1003.001 LSASS dump | 2026-05-20 |
| 7 | T1547.001 / T1053.005 Persistence | 2026-06-03 / 2026-06-02 |
| 8 | T1070.001 Clear Event Logs | 2026-06-09 |

## Appendix B — References

- Detection library & coverage matrix: [`../detections/README.md`](../detections/README.md)
- Related focused investigation: [INC-2026-002 — LSASS Credential Dump](INC-2026-002-lsass-credential-dump.md)
- MITRE ATT&CK: <https://attack.mitre.org/>
- Lab topology & build: [repository root README](../README.md)
