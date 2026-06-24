# Clearing the Logs Told Me Exactly When You Panicked

*A home-SOC story about why the most common anti-forensic move on Windows is also
one of the loudest alarms you can trip — if your logs leave the host.*

**Nolan · 2026-06-24**

---

The last thing the attacker did on my victim box was run `wevtutil cl Security`.

It's the move you'd expect at the end of an intrusion. They'd sprayed a password
to get in, reused the cracked credential to execute code as SYSTEM, dumped the
machine's stored password hashes, set up persistence — and then, on the way out,
they reached for the eraser and cleared the Windows event log to cover their
tracks.

It didn't hide a thing. And the act of trying told me precisely when they decided
the job was done and the cleanup had begun — which, it turns out, is some of the
most useful information in the whole investigation.

This post is about why. The short version is an architectural one: **if your logs
leave the host the instant they're written, clearing them locally is closing the
barn door from inside the barn.** But there's a more interesting detection-design
idea underneath it, and it shows up all over my lab, so let me build up to it.

## The setup

My lab is small on purpose: one Windows 10 endpoint, one Ubuntu box running
Splunk, one Kali box playing the attacker, all on a host-only network. The
endpoint runs Sysmon and a **Splunk Universal Forwarder**. That forwarder is the
whole game. Every Windows event — Security, System, Sysmon, PowerShell — gets
shipped off the host to the Splunk indexer **the moment it's written**, into an
index the endpoint's user can't reach, on a machine the attacker never touched.

The intrusion I'm describing is real telemetry, captured and written up in full as
[INC-2026-001](../investigations/INC-2026-001-multistage-intrusion.md). The chain:

1. **Password spray** from the Kali box (`192.168.56.30`) guesses the password of
   a local admin account, `analyst`.
2. That one credential is **reused over SMB** to create a service that runs as
   LocalSystem — instant code execution as `NT AUTHORITY\SYSTEM`.
3. The attacker does discovery, **disables Defender**, **dumps the SAM and LSASS**
   (every stored and cached credential on the box), and plants persistence.
4. On the way out: `wevtutil cl Security`.

Step 4 is where it gets interesting.

## What actually happened when they cleared the log

Two things happened the instant `wevtutil cl Security` ran, and the attacker
controlled neither.

**First, nothing was hidden.** Every event they were trying to erase had already
been forwarded. By the time the clear command ran, the spray's failed logons, the
`7045` service install that gave them SYSTEM, the `reg save HKLM\sam`, all of it
was sitting in `index=endpoint` on the Splunk box. Clearing the *local* Security
log emptied a copy. The authoritative record was somewhere they couldn't reach.

**Second, the clear announced itself.** Clearing the Security log generates a
Windows event — **EID 1102, "The audit log was cleared"** — and that event
forwarded too, before the attacker could do anything about it. Here's the real one
from my lab:

```
EventCode=1102   LogName=Security   ComputerName=DESKTOP-0DU4BT6
Message=The audit log was cleared.
Subject:
    Account Name:  analyst
    Domain Name:   DESKTOP-0DU4BT6
```

So the anti-forensic step produced a high-fidelity, named, timestamped alert
pointing straight at the compromised account — and it did so at the most
diagnostically valuable moment in the entire intrusion: the moment the attacker
decided to clean up. In incident response, "when did they start covering their
tracks?" brackets the active phase of the attack. They handed me that timestamp.

There's a sibling event, **EID 104**, for clearing any *other* log (System,
Application, even Sysmon's own channel), so an attacker who clears the very logs my
other detections rely on still trips this one. Between 1102 and 104, every log
clear on the box produces an alarm.

## The design idea: detect the *effect*, not the *tool*

Here's the part I think is genuinely worth internalizing, because it's the
difference between a detection that's easy to evade and one that basically isn't.

A naive log-clearing detection watches for the **tool**: alert when
`wevtutil.exe` runs with the `cl` argument. That works right up until the attacker
uses PowerShell's `Clear-EventLog` instead, or WMI, or calls the `EvtClearLog`
Windows API directly from inside a process that never shows up as a new command
line. Now your `wevtutil`-watching rule sees nothing.

EID 1102 and 104 don't have that problem, because **they aren't written by the
attacker's tool — they're written by the Windows Event Log service itself, as the
clear completes.** It doesn't matter how you ask for the clear; if it succeeds, the
service writes the record. The detection anchors on the *effect* (a log got
cleared) instead of the *actor* (which binary asked). That's tool-agnostic and
close to evasion-proof, because to avoid the signal you'd have to avoid actually
clearing the log.

Once I saw that pattern, I saw it everywhere in my lab:

- **Registry persistence** ([T1547.001](../detections/T1547.001-registry-run-keys.md)):
  don't watch for `reg.exe` writing a Run key — watch Sysmon **EID 13**, the
  registry-value-set event the OS emits no matter who writes it (reg.exe,
  PowerShell, or a raw API call).
- **Lateral movement via SMB** ([T1021.002](../detections/T1021.002-smb-admin-shares.md)):
  don't watch for a tool name — watch **EID 7045**, the service-install event the
  Service Control Manager writes when *any* "smbexec"-style attack creates its
  payload service. The service name is random every run; the event is not.

The common thread: **find the event the operating system writes when the action
completes, and alert on that.** The attacker can choose their tools; they can't
choose whether Windows records that the thing happened.

## The honest caveats

I'd be selling you something if I said this is airtight, so two real limits:

- **Direct-API and kernel tricks can dodge the *process* layer.** If credential
  theft or a log clear happens via injected code calling an API, there's no new
  process to catch — which is exactly why the *effect* event (1102/104/13/7045) is
  the alert and the process event is just attribution. Detect the effect; use the
  process to find out *who*.
- **Surgical record deletion isn't a "clear."** A tool that snips individual log
  records instead of clearing the whole log won't fire 1102/104. That's a real,
  advanced gap — caught by a different technique (looking for gaps in the record
  sequence), not this one.

And the process-attribution layer earns its keep: when the clear *does* go through
a process, pairing the 1102 with Sysmon's process events tells me which account and
parent process did it. In INC-2026-001 that's how the clear ties back to the same
`analyst` credential the spray compromised at the very start.

## The takeaway

The cleverest SPL I wrote all month was not what beat the attacker's anti-forensics.
A boring infrastructure decision was: **forward the logs off the host in real
time.** That one choice turned the attacker's eraser into a beacon. It meant the
"covering their tracks" step couldn't cover anything — the evidence was already
gone, to the one place that mattered — and it converted their last action into a
timestamped confession.

If you take one thing from this: **detection is downstream of architecture.** Get
the telemetry off the box and anchor your rules on the events the OS writes when an
action completes, not on the tools an attacker chooses. Do that, and the most
common move in the post-exploitation playbook — "clear the logs" — stops being a
blind spot and starts being one of the best signals you've got.

They told me exactly when they panicked. I just had to be listening from somewhere
they couldn't reach.

---

*Full technical write-ups behind this post: the incident report
[INC-2026-001](../investigations/INC-2026-001-multistage-intrusion.md), the
log-clearing detection
[T1070.001](../detections/T1070.001-clear-event-logs.md), and the
[detection library](../detections/README.md) it's part of. The whole lab is
[on GitHub](https://github.com/Hammer44-code/home-soc-lab).*
