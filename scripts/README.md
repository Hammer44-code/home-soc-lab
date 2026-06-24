# Automation Scripts

Small, dependency-light tools that automate the repetitive parts of running this
detection library. Two of them ship here: one that operates purely on the repo
files (runs anywhere), and one that talks to the lab's Splunk over its REST API.

| Script | What it does | Needs Splunk? |
|---|---|---|
| [`gen_coverage.py`](gen_coverage.py) | Generates the coverage matrix from the detection docs | No |
| [`run_detections.py`](run_detections.py) | Fires each detection's primary SPL against Splunk and reports hits | Yes |
| [`detections.yml`](detections.yml) | The SPL + metadata registry both the runner and a deploy consume | — |

---

## `gen_coverage.py` — coverage matrix generator

Parses every `detections/T*.md` write-up and emits the Markdown coverage table
(Technique | Detection | Tactic | Severity | Status), ordered along the ATT&CK
kill chain. The technique ID comes from the filename and everything else from the
document body, so the table **cannot drift** out of sync with the write-ups —
which is the point: run it and diff against
[`../detections/README.md`](../detections/README.md) to catch a doc whose severity
or status changed without the matrix being updated.

```bash
python3 scripts/gen_coverage.py            # print the matrix to stdout
python3 scripts/gen_coverage.py --check    # exit 1 if any field is unparseable (CI guard)
```

Standard library only — no install step.

## `run_detections.py` — Splunk detection runner

Loads [`detections.yml`](detections.yml) and runs each detection's **primary**
search against the Splunk REST API over a chosen time window, then prints a
per-detection hit report. This is the smoke test a SOC runs after changing
detection content or the telemetry pipeline: *do all my rules still parse and
still find their known events?*

```bash
# All detections over the last 30 days against the lab indexer (self-signed cert):
export SPLUNK_PASSWORD=...                  # or pass --password, or be prompted
python3 scripts/run_detections.py --host 192.168.56.10 --insecure --earliest -30d

# One technique, wider window, fail the run if it finds nothing (CI gate):
python3 scripts/run_detections.py --host 192.168.56.10 --insecure \
    --only T1003.001 --earliest -90d --strict

# Just show the registry, no Splunk needed:
python3 scripts/run_detections.py --list
```

**Key flags:** `--host` / `--port` (default `192.168.56.10:8089` — the REST/management
port, *not* the 8000 web UI), `--user` / `--password` (or `SPLUNK_PASSWORD` env, or
interactive prompt), `--earliest` / `--latest`, `--only T1xxx …`, `--insecure`
(skip TLS verification for the lab's self-signed cert), `--strict` (exit non-zero
if a detection marked `expect_hits: true` returns zero rows).

Example output:

```
# Running 13 detection(s) against https://192.168.56.10:8089
# Window: earliest=-30d latest=now

TECHNIQUE      HITS  RESULT   DETECTION
----------------------------------------------------------------
T1003.001         1  HIT      LSASS Memory Access
T1110.003         6  HIT      Password Spraying
T1021.002         1  HIT      SMB Admin Shares / smbexec
...
----------------------------------------------------------------
# 13 run, 0 expected-but-missed, 0 error(s)
```

**Requirements:** `pip install pyyaml`. Splunk access is via stdlib `urllib` — no
`splunk-sdk` dependency. The hit counts are subject to Splunk Free's index
retention, so old validation events may have aged out of very long windows.

## `detections.yml` — the registry

One entry per detection: `id` (technique), `name`, `tactic`, `severity`, `doc`
(the write-up it came from), `expect_hits`, and the exact validated primary
`search`. Think of it as a portable `savedsearches.conf` for the library — the
single manifest you would feed into a deployment. To add a detection, copy its
primary ```` ```spl ```` block from the write-up into a new entry.
