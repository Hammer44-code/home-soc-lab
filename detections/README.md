# Detection Coverage Matrix

This directory holds the lab's detection engineering work product: one Markdown
write-up per MITRE ATT&CK (sub-)technique, each containing the detection logic
(Splunk SPL), an explanation of *why* it works, tuning / false-positive notes, a
reproducible test case, and a **real captured event** from the lab. Every
detection in the table below was **validated end-to-end** — the attack was
actually run on the lab (soc-victim `.20`, or from soc-kali `.30` for the
network-side ones), the event was confirmed in `index=endpoint`, and the SPL was
iterated against real telemetry until it fired correctly.

The two `sigma/` rules are portable [Sigma](https://github.com/SigmaHQ/sigma)
versions of the highest-fidelity tripwires, each carrying its `sigma convert`
Splunk output and a note mapping the generic fields to this lab's index.

## Coverage

| Detection | Tactic | Technique | Severity | Detection Model | Status |
|---|---|---|---|---|---|
| [PowerShell Encoded Command](T1059.001-powershell-encoded.md) | Execution | T1059.001 — Command & Scripting Interpreter: PowerShell | High | Single signature (regex) | ✅ Validated 2026-05-19 |
| [Windows Command Shell](T1059.003-windows-command-shell.md) | Execution | T1059.003 — Command & Scripting Interpreter: Windows Cmd | Variable (Low→High) | Weighted score | ✅ Validated 2026-06-08 |
| [Registry Run Keys](T1547.001-registry-run-keys.md) | Persistence | T1547.001 — Boot/Logon Autostart: Run Keys | Medium | Effect tripwire (EID 13) + attribution | ✅ Validated 2026-06-03 |
| [Scheduled Task](T1053.005-scheduled-task.md) | Persistence / Priv. Esc. / Execution | T1053.005 — Scheduled Task | Medium-High | Per-event triage | ✅ Validated 2026-06-02 |
| [Bypass User Account Control](T1548.002-bypass-uac.md) | Privilege Escalation / Defense Evasion | T1548.002 — Abuse Elevation Control: Bypass UAC | High | Two-stage plant→trigger | ✅ Validated 2026-06-11 |
| [Impair Defenses](T1562.001-impair-defenses.md) | Defense Evasion | T1562.001 — Impair Defenses: Disable/Modify Tools | High | Process classifier + EID 13 corroborator | ✅ Validated 2026-06-10 |
| [Clear Windows Event Logs](T1070.001-clear-event-logs.md) | Defense Evasion | T1070.001 — Indicator Removal: Clear Event Logs | High | Effect tripwire (1102/104) + attribution · **[Sigma](sigma/clear-event-logs.yml)** | ✅ Validated 2026-06-09 |
| [LSASS Memory Access](T1003.001-lsass-access.md) | Credential Access | T1003.001 — OS Credential Dumping: LSASS Memory | Critical | Syscall tripwire (EID 10) + mask/calltrace · **[Sigma](sigma/lsass-unusual-parent.yml)** | ✅ Validated 2026-05-20 |
| [SAM Credential Access](T1003.002-sam-credential-access.md) | Credential Access | T1003.002 — OS Credential Dumping: SAM | High | Single signature + crackable-set burst | ✅ Validated 2026-06-10 |
| [Password Spraying](T1110.003-password-spraying.md) | Credential Access | T1110.003 — Brute Force: Password Spraying | Medium→Critical | Burst + success-correlation (self-escalating) | ✅ Validated 2026-06-15 |
| [Account Discovery](T1087-account-discovery.md) | Discovery | T1087.001 — Account Discovery: Local Account | Low-Medium | Burst correlation | ✅ Validated 2026-06-03 |
| [System Information Discovery](T1082-system-info-discovery.md) | Discovery | T1082 — System Information Discovery | Low-Medium | Burst correlation | ✅ Validated 2026-06-03 |
| [SMB Admin Shares / smbexec](T1021.002-smb-admin-shares.md) | Lateral Movement | T1021.002 — Remote Services: SMB/Admin Shares | Critical | Service binPath signature (EID 7045) + IP correlation | ✅ Validated 2026-06-23 |

**13 validated detections** across **8 ATT&CK tactics** (Execution, Persistence,
Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral
Movement) — built on a single Windows endpoint with Sysmon (SwiftOnSecurity
config) and the Windows Security/System/PowerShell channels, forwarded to Splunk
via the Universal Forwarder.

## Detection models used

The lab deliberately reuses a small vocabulary of detection patterns rather than
writing every rule ad hoc. Picking the right model for a technique is most of the
engineering — they're documented in [`../notes/splunk-spl-cheatsheet.md`](../notes/splunk-spl-cheatsheet.md):

- **Single signature** — the command/event *shape* is intrinsically malicious; a
  plain `| where` is enough (SAM dump, encoded PowerShell).
- **Effect tripwire** — alert on the OS-service-written record of the action
  completing (EID 1102/104 log-clear, EID 13 registry write, EID 7045 service
  install). Tool-agnostic, near-zero evasion; paired with a process-attribution
  layer for *who*.
- **Burst correlation** — alert on *repetition* of similar low-signal commands in
  a time window (account/system discovery, the failure wall of a password spray).
- **Weighted score** — one noisy binary (`cmd.exe`) scored across several
  unrelated malicious shapes, alert over a threshold.
- **Two-stage plant→trigger** — corroborate a setup write (UAC registry hijack)
  with the elevated payoff process for complementary coverage.

## Sigma rules

| Rule | Technique | Converted target |
|---|---|---|
| [`sigma/clear-event-logs.yml`](sigma/clear-event-logs.yml) | T1070.001 | Splunk (`sigma convert -t splunk`) |
| [`sigma/lsass-unusual-parent.yml`](sigma/lsass-unusual-parent.yml) | T1003.001 | Splunk (`sigma convert -t splunk -p sysmon`) |

Each file ends with a comment block containing the Splunk query the rule converts
to, plus a mapping note for this lab's `index=endpoint` / `EventCode` field names
(and the post-`Splunk_TA_windows` sourcetype collapse).

## Lab context

See the repository [root README](../README.md) for the full lab topology
(3-VM host-only network: Splunk SIEM `.10`, Windows victim `.20`, Kali attacker
`.30`) and build notes.
