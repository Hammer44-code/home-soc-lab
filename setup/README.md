# Lab Setup Guide

End-to-end build instructions for the Home SOC Lab: three VMs on a host-only
network, Splunk Free ingesting Windows telemetry from a Sysmon-instrumented
victim, and Kali staged to run Atomic Red Team against it.

Target build time: **one focused weekend** (~8 hours). If you hit 12+ hours,
check the [Common Pitfalls](#common-pitfalls) section — almost every delay at
this stage is one of four well-known problems.

---

## 1. Hardware budget

Designed to fit on a single laptop with 16 GB of RAM.

| VM | RAM | vCPU | Disk | Purpose |
|---|---|---|---|---|
| Ubuntu Server (Splunk) | 4 GB | 2 | 60 GB | SIEM indexer + search head |
| Windows 10 Eval (victim) | 4 GB | 2 | 60 GB | Endpoint telemetry source |
| Kali Linux (attacker) | 2–3 GB | 2 | 30 GB | Offensive tooling |
| Host OS reserve | 4–5 GB | — | — | Keep the host responsive |

**Total VM footprint:** ~14 GB RAM, ~150 GB disk.

Only run the VMs you actively need. Shut down Kali when you're writing SPL;
shut down the victim when you're just poking at Splunk.

---

## 2. Network design

Use a **host-only network** in VirtualBox or VMware Workstation Player. All
attack traffic stays inside the hypervisor — no risk to the home network, no
accidental internet exposure of the victim.

### IP scheme

| Host | IP | Role |
|---|---|---|
| Ubuntu Splunk | `192.168.56.10` | SIEM |
| Windows victim | `192.168.56.20` | Telemetry source / target |
| Kali attacker | `192.168.56.30` | Offensive tooling |

Give each VM a **static** address on the host-only adapter. Disable internet
on the victim after initial patching so Defender cloud lookups don't
interfere with attack simulations. Toggle internet back on briefly when you
need to pull down Atomic Red Team payloads, then disable again.

### Architecture diagram

See [`architecture-diagram.md`](./architecture-diagram.md) for the Mermaid and
ASCII versions. Export to PNG with draw.io or Excalidraw once the lab is up,
and drop the PNG next to this file as `architecture-diagram.png`.

---

## 3. Build the Ubuntu / Splunk host

1. **Create the VM.** Ubuntu Server 22.04 LTS, minimal install. 4 GB RAM, 2
   vCPU, 60 GB disk. Attach to the host-only adapter.
2. **Set a static IP** via `/etc/netplan/*.yaml`:
   ```yaml
   network:
     version: 2
     ethernets:
       enp0s8:
         dhcp4: no
         addresses: [192.168.56.10/24]
   ```
   Apply with `sudo netplan apply`.
3. **Install Splunk Free.** Download the `.deb` from
   [splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html)
   (a free account is required). Install and start:
   ```bash
   sudo dpkg -i splunk-*.deb
   sudo /opt/splunk/bin/splunk start --accept-license
   sudo /opt/splunk/bin/splunk enable boot-start
   ```
4. **Open the receiver.** In Splunk Web (`http://192.168.56.10:8000`) go to
   *Settings → Forwarding and receiving → Configure receiving → New* and add
   port `9997`. Equivalent CLI:
   ```bash
   sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:<password>
   ```
5. **Create the `endpoint` index.** *Settings → Indexes → New Index →*
   Name: `endpoint`. All forwarded Windows logs will land here.
6. **Firewall.** If ufw is enabled: `sudo ufw allow from 192.168.56.0/24 to any port 9997`
   and `sudo ufw allow from 192.168.56.0/24 to any port 8000`.

---

## 4. Build the Windows 10 victim

1. **Create the VM.** Microsoft's [Windows 10 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise)
   ISO (90-day free). 4 GB RAM, 2 vCPU, 60 GB disk. Attach to the host-only
   adapter with a static IP of `192.168.56.20`.
2. **Baseline the OS.** Complete OOBE, install pending patches, take a
   snapshot named `baseline-clean` before installing any tooling — you'll
   roll back to this between attack runs.
3. **Install Sysmon with the bundled config.**
   - Download Sysmon from Microsoft:
     https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
   - Drop `setup/sysmon-config.xml` from this repo onto the VM.
   - Open an elevated PowerShell and run:
     ```powershell
     .\Sysmon64.exe -accepteula -i sysmon-config.xml
     ```
   - Verify with `Get-Service sysmon64` and by checking the
     `Microsoft-Windows-Sysmon/Operational` channel in Event Viewer.
4. **Install the Splunk Universal Forwarder.** Download the MSI from Splunk
   (same page as the indexer). During install:
   - Deployment server: *leave blank*.
   - Receiving indexer: `192.168.56.10:9997`.
   - Run the service as `LocalSystem` so it can read the Security log.
5. **Drop `setup/splunk-inputs.conf` into the UF.** Copy to
   `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
   (or better: a deployment app under `etc\apps\home-soc-lab\local\`). Restart
   the forwarder:
   ```powershell
   Restart-Service SplunkForwarder
   ```
6. **Enable PowerShell Script Block Logging.** Local Group Policy (`gpedit.msc`):
   *Computer Configuration → Administrative Templates → Windows Components →
   Windows PowerShell → Turn on PowerShell Script Block Logging → Enabled.*
   Confirm by running a PowerShell one-liner and seeing Event ID 4104 land in
   the `Microsoft-Windows-PowerShell/Operational` channel.

---

## 5. Build the Kali attacker

1. **Create the VM.** Kali 2024.x minimal install. 2–3 GB RAM, 2 vCPU, 30 GB
   disk. Static IP `192.168.56.30` on the host-only adapter.
2. **No Splunk forwarder** — this box should look like an attacker, not
   another telemetry source.
3. **Baseline tooling** (`sudo apt update && sudo apt install -y`):
   `impacket-scripts`, `smbclient`, `netcat`, `responder`. More gets added in
   Sprint 3 as specific techniques need it.
4. **Snapshot** the VM as `kali-clean` before any engagement.

---

## 6. Verify ingestion

Once all three VMs are up:

1. From Splunk Web, run:
   ```spl
   index=endpoint | stats count by sourcetype
   ```
   You should see rows for:
   - `WinEventLog:Security`
   - `WinEventLog:Microsoft-Windows-Sysmon/Operational`
   - `WinEventLog:Microsoft-Windows-PowerShell/Operational`
   - `WinEventLog:System`
2. On the victim, open Notepad and run `whoami` in PowerShell. Within ~30
   seconds, both should appear:
   ```spl
   index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
     EventCode=1 (Image="*notepad.exe" OR CommandLine="*whoami*")
   | table _time host Image CommandLine
   ```
3. **Capture 3–4 screenshots** into `setup/screenshots/`:
   - `01-splunk-sourcetypes.png` — the `stats count by sourcetype` result.
   - `02-sysmon-process-create.png` — a Sysmon EID 1 event expanded.
   - `03-security-logon.png` — a Windows Security EID 4624 event expanded.
   - `04-uf-forwarder-status.png` — UF status on the victim
     (`splunk list forward-server` from an elevated prompt).

If any sourcetype is missing, jump to [Common Pitfalls](#common-pitfalls).

---

## 7. Handoff to Sprint 2

When ingestion is verified, paste **one real Sysmon EID 1 event** and **one
real Security EID 4624 event** from your lab back into the working session.
Claude Code uses them to calibrate exact field names (some Splunk versions
rename fields, e.g. `CommandLine` vs `process.command_line`) before authoring
the Sprint 2 SPL queries.

---

## Common pitfalls

- **Sysmon installs but events don't appear in Splunk.** Check the UF
  `inputs.conf` — the channel names are exact. `Microsoft-Windows-Sysmon/Operational`
  must be spelled exactly that way, slash included.
- **VMs can't reach each other.** All three need to be on the *same* host-only
  adapter, not NAT. `ping 192.168.56.10` from the victim is the fastest
  sanity check.
- **Splunk won't start on Ubuntu.** Usually a permissions issue on first run.
  Re-run `sudo /opt/splunk/bin/splunk start --accept-license` with `sudo`.
- **Windows victim is unbearably slow.** Disable unneeded services, use an
  SSD-backed virtual disk, and don't run Kali at the same time unless
  actively attacking.
- **Defender keeps eating Atomic Red Team payloads.** You want Defender *on*
  for realistic baseline telemetry, but add broad exclusions for the ART
  folder only (e.g. `C:\AtomicRedTeam\`). Don't disable Defender globally —
  that itself is the T1562.001 detection you'll write in Sprint 3.

---

## Deliverables checklist (Sprint 1)

- [ ] `setup/README.md` — this file.
- [ ] `setup/sysmon-config.xml` — config wrapper.
- [ ] `setup/splunk-inputs.conf` — UF input stanzas.
- [ ] `setup/architecture-diagram.md` — Mermaid + ASCII source.
- [ ] `setup/screenshots/` — 3–4 images proving logs flow (user-supplied).
- [ ] Real Sysmon EID 1 + Security EID 4624 sample events handed off for
      Sprint 2 SPL calibration.
