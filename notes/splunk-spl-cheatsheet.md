# Splunk SPL Patterns — Home SOC Lab Playbook

A working reference of the SPL patterns I leaned on while writing the Sprint 2 detections (T1059.001 PowerShell encoded, T1003.001 LSASS access, T1053.005 scheduled task). Every pattern here paid for itself with an iteration loop in the lab — they're not theoretical; each one solves a specific problem I hit and remembered.

The point isn't to substitute for the official Splunk docs. It's to capture the *why* behind each pattern, the gotcha that taught me to use it, and the detection where it first showed up — so when I'm writing a new detection two months from now and reach for one of these, I have the context to use it correctly instead of cargo-culting.

---

## 1. Scope every search on `sourcetype` + `EventCode` first

```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

**Why.** Splunk searches read every event in the time range that matches the leading constraints. Putting `index=`, `sourcetype=`, and `EventCode=` as the very first tokens lets Splunk push the filter down into the bloom-filter / TSIDX layer, which is dramatically faster than filtering after a pipe. A search that starts `index=endpoint | search EventCode=1` reads every event in `endpoint` and *then* drops the non-1s — slow on a real-world index, instant on lab data which is small enough that you won't notice until production.

**Sourcetypes in this lab** (confirmed by the SIEM-half completion search `index=endpoint | stats count by sourcetype`):

| Sourcetype | Channel | What it carries |
|---|---|---|
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon | EID 1 process create, 3 net connect, 7 image load, 10 process access, 11 file create, etc. |
| `WinEventLog:Security` | Windows Security | 4624 logon, 4625 failed logon, 4698 scheduled task created, 4688 process create if enabled |
| `WinEventLog:Microsoft-Windows-PowerShell/Operational` | PowerShell | 4104 script block logging (with `EnableScriptBlockLogging=1`) |
| `WinEventLog:System` | Windows System | service start/stop, driver load, kernel events |

**When you reach for it.** Always. Every detection SPL in this lab starts with these three tokens.

**Sanity-check pattern.** Before iterating on detection logic, confirm the data is actually in the index:
```spl
index=endpoint | stats count by sourcetype EventCode
```
Lesson from T1003.001: I had a fully tuned SPL before realizing Sysmon wasn't emitting EID 10 at all (the stub config that shipped only had the always-on EIDs). The `stats count by` search would have surfaced that in 10 seconds. Now I run it as step zero on any new detection.

---

## 2. Auto-extracted fields vs `rex`-extracted fields

Splunk's `WinEventLog` parser auto-extracts the named fields from a Sysmon event's `Message` block. They come out **PascalCase**, matching the on-wire field names:

```
Image, CommandLine, ParentImage, ParentCommandLine, User, Hashes,
IntegrityLevel, ProcessId, ParentProcessId, CurrentDirectory,
SourceImage, TargetImage, GrantedAccess, CallTrace, TargetFilename
```

Custom fields I extract myself with `rex` use **lowercase snake_case** by convention:

```
task_name, task_run, task_run_as, task_schedule, subject_user, task_user_id
```

**Why this matters.** When you read my SPL and see a PascalCase field, that's free — Splunk gave it to me. When you see snake_case, that's a downstream `rex` I had to write. Keeps the source of each field obvious at a glance.

**Gotcha — `WinEventLog:Security` does NOT auto-extract cleanly** without the `Splunk_TA_windows` add-on. EID 4624 logon fields, EID 4698 task XML — all of it requires either the TA or a `rex` against `_raw`. The lab doesn't have the TA installed (Sprint 3 follow-up), so the secondary SPL in T1053.005 uses regex extraction against `_raw`. See Pattern 7.

---

## 3. Whitespace-anchored CLI flag matching

```spl
| where match(CommandLine, "(?i)\s-(EncodedCommand|EncodedComman|EncodedComma|...|E)\s")
```

**The lesson** (T1059.001, first iteration). The naive version was:

```spl
| where like(CommandLine, "%-EncodedCommand%")
```

That broke in **two directions** simultaneously:

1. **False positive:** matched against the parameter name `-EncodedCommandParamVariation` embedded inside the ART test's own wrapper text, because `%-EncodedCommand%` is a substring search.
2. **False negative:** PowerShell accepts every valid prefix of `-EncodedCommand` (`-E`, `-En`, `-Enc`, `-Encod`, …). A real attacker abuses the shortest form, so `-E` is the *most* important to catch, and the substring search missed all of them.

**Fix pattern.** Whitespace-anchor on both sides and enumerate every valid prefix as a regex alternation:

```spl
| where match(CommandLine, "(?i)\s-(EncodedCommand|EncodedComman|...|En|E)\s")
```

`\s` on both sides forces it to be a standalone CLI argument. `(?i)` makes it case-insensitive. The alternation explicitly lists every valid prefix.

**T1053.005 application.** Same pattern, slash-prefix flags:

```spl
| where match(CommandLine, "(?i)\s/(create|cr)\s")
```

`schtasks` accepts `/Create` and the short form `/Cr`. Both anchored on whitespace.

**When you reach for it.** Any time the detection logic keys on the presence of a specific CLI flag. Never substring-match a flag; always whitespace-anchor and enumerate.

---

## 4. `rex` field extraction — quoted args, unquoted args, single capture

Basic shape:

```spl
| rex field=CommandLine "(?i)/TN\s+\"?(?<task_name>[^\"\s]+)"
```

- `field=CommandLine` — operate on the auto-extracted CommandLine, not the raw event
- `(?i)` — case-insensitive (matches `/TN`, `/tn`, `/Tn`)
- `/TN\s+` — the flag and one-or-more whitespace
- `\"?` — optional opening quote (matches whether or not the value is quoted)
- `(?<task_name>[^\"\s]+)` — named capture: anything that's not a quote and not whitespace, one or more

**Output:** a new field `task_name` populated whenever the regex matches; null otherwise.

**When the value can contain spaces** (e.g. `/TR "cmd.exe /c calc.exe"`), see Pattern 5 — naive extraction will truncate at the first space inside the value.

---

## 5. Two-pass `coalesce` for quoted-or-unquoted CLI values

**The bug** (T1053.005, first iteration). I had:

```spl
| rex field=CommandLine "(?i)/TR\s+\"?(?<task_run>[^\"]+?)\"?(?=\s/|$)"
```

Intended to extract `cmd.exe /c calc.exe` from `/tr "cmd.exe /c calc.exe"`. Instead it returned `cmd.exe`. Why: the non-greedy `+?` plus the lookahead `(?=\s/|$)` stops at the *first* space-slash sequence it sees — which inside the quoted value is the space before `/c`. The regex doesn't respect the quote as a "safe zone."

**The natural one-regex fix** doesn't compile in Splunk:

```spl
| rex field=CommandLine "(?i)/TR\s+(?:\"(?<task_run>[^\"]+)\"|(?<task_run>\S+))"
```

Returns: `Regex: two named subpatterns have the same name (PCRE2_DUPNAMES not set)`. Splunk's PCRE2 build rejects duplicate group names across alternation branches and there's no way to flip the flag from `rex`.

**The pattern that works.** Two passes with different names, then `coalesce`:

```spl
| rex field=CommandLine "(?i)/TR\s+\"(?<task_run_q>[^\"]+)\""
| rex field=CommandLine "(?i)/TR\s+(?<task_run_u>[^\"\s]\S*)"
| eval task_run=coalesce(task_run_q, task_run_u)
```

- First pass matches the quoted form. The opening quote is required, so it only fires when the value is quoted.
- Second pass matches the unquoted form. The leading `[^\"\s]` excludes a quote, so it *won't* fire on the already-quoted case — the two passes are mutually exclusive by construction.
- `coalesce` returns the first non-null. Downstream SPL sees a single field `task_run` regardless of whether the source was quoted.

**When you reach for it.** Any time you're parsing a CLI argument that may or may not be quoted depending on whether its value contains spaces — `/TR`, `/IN`, file path arguments, anywhere a user might or might not have wrapped the value in quotes. This pattern recurs constantly in Windows CLI parsing.

---

## 6. Bitmask matching for access rights (`GrantedAccess`, etc.)

**T1003.001 lesson.** I expected `comsvcs.dll MiniDump` to use `0x1FFFFF` (`PROCESS_ALL_ACCESS`) because every blog post on LSASS detection says so. Real captured event: `0x1410` — `PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_QUERY_INFORMATION + PROCESS_VM_READ`. The blog-default detection would have missed it cold.

**Pattern.** Enumerate every known suspicious mask as a regex alternation against the hex string:

```spl
| where match(GrantedAccess, "(?i)^0x(1010|1410|1438|143A|1FFFFF)$")
```

Then validate against the test, observe the actual mask, and add it to the alternation if it's new.

**When you reach for it.** Sysmon EID 10 ProcessAccess (`GrantedAccess`), EID 8 CreateRemoteThread (`SourceProcessId` context), token-impersonation patterns, anything where the OS reports a permission as a hex bitmask.

**Don't try to AND/OR the bitmask in SPL itself** — Splunk has no clean bitwise operator in SPL syntax. Match the hex string literally. If you genuinely need bitwise math, `eval bits=tonumber(GrantedAccess, 16)` and then arithmetic — but for detection work, string-match the known-bad masks.

---

## 7. Multi-line `_raw` extraction (the Security-log fallback)

When `Splunk_TA_windows` isn't installed (the lab's current state), Security-channel events like 4698 don't auto-extract their nested fields. The `Message` body is a structured multi-line text block with sections like `Subject:`, `Task Name:`, `Task Content:`. The pattern is:

```spl
| rex field=_raw "(?ms)Subject:.*?Account Name:\s+(?<subject_user>\S+).*?Account Domain:\s+(?<subject_domain>\S+)"
| rex field=_raw "(?ms)Task Name:\s+(?<task_name>\S+)"
| rex field=_raw "(?ms)Task Content:\s+(?<task_content_xml>.*?)(?=\n[A-Z]|\Z)"
```

Two regex flags matter:
- **`(?m)`** — multi-line mode. `^` and `$` match line boundaries, not just string boundaries.
- **`(?s)`** — single-line mode. `.` matches `\n`. Required when the value you're capturing spans multiple lines (e.g. the embedded XML in `Task Content:`).

`(?ms)` enables both at once.

**Nested extraction:** after pulling `task_content_xml` out of the raw event, run another `rex` against *that field* to pull the XML's child elements:

```spl
| rex field=task_content_xml "(?s)<Command>(?<task_cmd>[^<]+)</Command>"
| rex field=task_content_xml "(?s)<Arguments>(?<task_args>[^<]+)</Arguments>"
| rex field=task_content_xml "(?s)<UserId>(?<task_user_id>[^<]+)</UserId>"
```

This is fragile compared to a real XML parser — won't survive attribute reordering or namespace prefixes — but the Windows-generated XML in 4698 is consistent enough that it works in practice.

**When you reach for it.** Any Security-channel detection while `Splunk_TA_windows` is not installed. Once we install the TA in Sprint 3, this whole pattern can be retired in favor of native field access.

---

## 8. Risk-indicator flagging with `eval` + `if` + `match`

The "decorate every event with risk flags" pattern:

```spl
| eval suspicious_run_as=if(match(task_run_as, "(?i)^(SYSTEM|S-1-5-18|NT AUTHORITY\\\\SYSTEM)$"), "yes", "no")
| eval suspicious_target=if(match(task_run, "(?i)(powershell|cmd\.exe|rundll32|regsvr32|mshta|wscript|cscript|bitsadmin|certutil)"), "yes", "no")
```

**Why this shape works for triage.** Instead of writing a hard `| where` that drops events, decorate each row with `yes`/`no` indicator fields. The analyst sorts on the indicators in the UI to get an instant priority queue: SYSTEM run-as + LOLBin target at the top, everything else below. False negatives don't hide events — they just leave the indicator at `no`, so the analyst can still pivot through them.

**Backslash escaping warning.** Notice `NT AUTHORITY\\\\SYSTEM` — that's *four* backslashes in the SPL source. Splunk's string parser consumes one level (`\\\\` → `\\`), then the regex engine consumes another (`\\` → `\`). Net result: the regex literally matches a single backslash. Every backslash in a Splunk regex literal needs to be `\\\\` in the source. This is one of the most common bug sources in SPL regex.

**When you reach for it.** Every detection that wants to flag risk levels rather than threshold-drop events. Especially useful when the false-positive rate on a single indicator is high but the conjunction (`run_as=yes AND target=yes`) is sharp — that's the textbook scheduled-task persistence-plus-privesc pattern.

---

## 9. `table | sort -_time` for analyst-friendly output

```spl
| table _time host User ParentImage Image task_name task_run task_run_as task_schedule suspicious_run_as suspicious_target CommandLine
| sort - _time
```

Two operational notes:

1. **`table` enforces field order** — the columns appear in the order you list them. Put the high-signal fields first (`_time host User`, then the structured extractions, then the noisy `CommandLine` at the end so it doesn't push the indicators off-screen).
2. **`sort - _time`** — minus sign means descending. Most recent event at top, which is what an analyst expects when triaging.

**Don't use `fields` instead of `table`** unless you specifically want to keep additional context fields available downstream. `table` is the cleaner finisher for a detection SPL.

---

## 10. Weighted-score alert for noisy, multi-shape techniques

```spl
... EventCode=1 Image="*\\cmd.exe"
| eval susp_parent = if(match(ParentImage, "(?i)\\\\(winword|excel|mshta|wscript|cscript)\.exe$"), 3, 0)
| eval encoded_ps  = if(match(CommandLine, "(?i)(powershell|pwsh)\b") AND match(CommandLine, "(?i)\s-(e|en|enc|...|encodedcommand)\s"), 3, 0)
| eval obfuscation = if(match(CommandLine, "(?i)(\^|%comspec%|%[a-z0-9_]+:~)"), 2, 0)
| eval stdin_redir = if(match(CommandLine, "(?i)\s/r\b") OR match(CommandLine, "(?i)\bcmd(\.exe)?\s*<"), 2, 0)
| eval script_drop = if(match(CommandLine, "(?i)>\s*\S+\.(vbs|js|hta|bat|ps1)\b"), 2, 0)
| eval recon_chain = if(match(CommandLine, "(?i)\b(whoami|ipconfig|systeminfo)\b"), 1, 0)
| eval score = susp_parent + encoded_ps + obfuscation + stdin_redir + script_drop + recon_chain
| where score >= 2
| sort - score, - _time
```

**Why.** Some techniques are too noisy for a single `| where` and too *varied* for the burst pattern (§ none — that's T1087/T1082). `cmd.exe` (T1059.003) is the case study: the binary runs thousands of times a day benignly, and "malicious cmd" has many unrelated shapes (Office-spawned, encoded-PS hand-off, env-var obfuscation, stdin-redirection, script-dropping). No one regex separates good from bad. The weighted score encodes the analyst's triage model directly — *where did this shell come from, and what is it about to do* — as additive evidence, then thresholds the sum. The output is a **ranked queue** (`sort - score`), not a binary alarm.

**The two design rules that make it work** (both learned validating T1059.003):

1. **One technique trips one flag, so the threshold must be ≤ the smallest "should-alert" weight.** Each sub-technique lights exactly one indicator, so a single-technique event scores just that flag's weight. I first set `threshold=3` with the obfuscation flag at weight 2 — and the canonical "suspicious execution" atomic (weight 2) silently missed. Fix: threshold `>= 2`. The bigger weights (3) no longer change *whether* something fires — they rank the queue (Office-macro-plus-encoded-PS = 6 sits above lone obfuscation = 2). Keep the lowest-signal corroborator (`recon_chain`) at weight 1 so it stays *below* threshold alone but tips a borderline event over.
2. **Decorate-don't-drop for the hunting twin** (see § 8). Ship two SPLs: a classifier that emits every flag as `yes/no` and drops nothing (hunting), and the scored `where score >= N` (the alert). Same split as the burst detections.

**The pre-flight that saved the detection.** Before running anything, dump the *actual* atomic commands with `Invoke-AtomicTest <T> -ShowDetails` and hand-score them against the draft. This caught two fatal gaps on paper: (a) the threshold-vs-weight bug above, and (b) two whole sub-techniques (stdin-redirection, script-dropping) the draft had no flag for — they'd have scored 0 and "validated" as false negatives. **Lesson: for a multi-shape detection, read the test payloads and predict each score before you execute.** Same family as the §1 "confirm the data is in the index first" lesson — verify your assumptions cheaply before the expensive loop.

**ART harness caveat worth carrying forward.** Atomic Red Team parents every atomic under its runner (`powershell.exe`), so any flag keyed on a *suspicious parent* is structurally unexercisable via ART — it can only be reasoned about, not lab-proven. Note which flags your test harness can and cannot exercise.

**When you reach for it.** A high-volume binary/event class with several independent malicious shapes and no clean single discriminator — `cmd.exe`, `rundll32.exe`, `regsvr32.exe`, `wmic.exe`, LOLBin execution generally. If the technique instead manifests as *repetition* of similar commands, use the burst-correlation pattern (T1087/T1082) instead; if it's a single sharp signature, a plain `| where` is enough.

---

## Quirks & gotchas

- **Time picker syntax** — `earliest=-15m` goes in the **initial search line**, not after a `|`. Easier to just use the time picker dropdown. (Memory from Sprint 2.)
- **`_time` vs Sysmon `UtcTime`** — `_time` is Splunk's indexed timestamp displayed in the user's preferred timezone; Sysmon's `UtcTime` field is the on-event UTC string from the source. Both should reference the same instant. If they diverge by hours, the source VM's timezone is wrong (Win10 default is sometimes Pacific even on a host in another zone — bit me on 2026-06-02).
- **`NOT_TRANSLATED` in event header** — Splunk's WinEventLog parser couldn't resolve the channel publisher's name (often the SYSTEM SID). Cosmetic only; the real per-process `User` field further down is correct.
- **Stale events from hung tests** — if an ART test hits an interactive prompt and times out, partial events still land in the index. Always check the timestamps when validating: today's run vs the leftover hung-run events from earlier.

---

## Event ID quick reference

EIDs I've used so far in this lab:

| EID | Channel | What it means | Used in |
|---|---|---|---|
| 1 | Sysmon | Process create | T1059.001, T1053.005, T1087, T1082, T1059.003 |
| 13 | Sysmon | Registry value set | T1547.001 (Run-key tripwire) |
| 10 | Sysmon | Process access (handle open) | T1003.001 |
| 11 | Sysmon | File create | T1053.005 (Tasks folder pivot) |
| 4624 | Security | Successful logon | (Sprint 3 — needs `Splunk_TA_windows`) |
| 4698 | Security | Scheduled task created | T1053.005 (secondary SPL) |

**EID 11 surprise** — file writes to `C:\Windows\System32\Tasks\` come from `svchost.exe` (Task Scheduler service), not `schtasks.exe`. A detection that anchors on `Image=*\\schtasks.exe` for EID 11 returns zero. Anchor on `TargetFilename`, not `Image`.

---

## How I add to this doc

When a new detection or investigation uses a pattern that isn't in here yet, add it. Each entry should answer four questions in this order:

1. **What's the SPL?** (the code block)
2. **What problem does it solve?** (the *why*)
3. **What gotcha taught me to use this?** (the lab-validation lesson)
4. **When do I reach for it?** (the trigger condition for future-me)

If the entry doesn't have all four, it's not earning its place. The purpose of the doc is to *transfer the context*, not just list syntax.
