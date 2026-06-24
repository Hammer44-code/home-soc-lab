#!/usr/bin/env python3
"""
run_detections.py — fire the lab's detection library against Splunk and report hits.

Loads scripts/detections.yml (the SPL + metadata registry) and runs each
detection's PRIMARY search against the Splunk REST API over a chosen time window,
then prints a per-detection report of how many events each returned. This is the
automation a SOC uses to smoke-test a detection library after a content change or
a pipeline change: "do all my rules still parse and still find their known events?"

The lab's Splunk runs at 192.168.56.10; the REST/management port is 8089 (separate
from the 8000 web UI). The free/dev Splunk uses a self-signed cert, so --insecure
is the norm on the lab network.

Examples:
    # All detections over the last 30 days, lab indexer, prompt-free via env var:
    export SPLUNK_PASSWORD=...   # or pass --password
    python3 scripts/run_detections.py --host 192.168.56.10 --insecure --earliest -30d

    # One technique, custom window, fail the run if it finds nothing (CI gate):
    python3 scripts/run_detections.py --host 192.168.56.10 --insecure \
        --only T1003.001 --earliest -90d --strict

Requires: PyYAML (pip install pyyaml). Splunk access is via stdlib urllib — no
splunk-sdk needed.
"""
import argparse
import getpass
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "detections.yml")


def load_registry(only=None):
    data = yaml.safe_load(open(REGISTRY, encoding="utf-8"))
    dets = data.get("detections", [])
    if only:
        wanted = {x.strip().upper() for x in only}
        dets = [d for d in dets if d["id"].upper() in wanted]
    return dets


def splunk_search(opener, base, search, earliest, latest):
    """Run one blocking search via the export endpoint; return result-row count.

    The export endpoint streams newline-delimited JSON; each line with a
    "result" key is one returned row. Counting them is exactly the hit count an
    analyst would see in the Splunk UI for that search + time window.
    """
    if not search.lstrip().startswith(("search ", "|")):
        search = "search " + search
    body = urllib.parse.urlencode({
        "search": search,
        "earliest_time": earliest,
        "latest_time": latest,
        "output_mode": "json",
        "exec_mode": "oneshot",
    }).encode()
    url = base + "/services/search/jobs/export"
    req = urllib.request.Request(url, data=body, method="POST")
    count = 0
    with opener.open(req, timeout=120) as resp:
        for raw in resp:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if "result" in obj:
                count += 1
    return count


def build_opener(user, password, insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    pw_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    # realm/uri filled per-opener below via auth handler
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    auth = urllib.request.HTTPBasicAuthHandler(pw_mgr)
    handlers.append(auth)
    return urllib.request.build_opener(*handlers), pw_mgr, auth


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="192.168.56.10", help="Splunk host (default: lab indexer)")
    ap.add_argument("--port", type=int, default=8089, help="management/REST port (default: 8089)")
    ap.add_argument("--user", default="admin", help="Splunk username (default: admin)")
    ap.add_argument("--password", default=os.environ.get("SPLUNK_PASSWORD"),
                    help="Splunk password (or set SPLUNK_PASSWORD; prompts if omitted)")
    ap.add_argument("--earliest", default="-30d", help="earliest_time (default: -30d)")
    ap.add_argument("--latest", default="now", help="latest_time (default: now)")
    ap.add_argument("--only", nargs="+", metavar="TID",
                    help="run only these technique IDs (e.g. --only T1003.001 T1070.001)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (lab self-signed cert)")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if a detection with expect_hits:true returns 0 rows")
    ap.add_argument("--list", action="store_true", help="list the registry and exit (no Splunk)")
    args = ap.parse_args()

    dets = load_registry(args.only)
    if not dets:
        sys.exit("No detections matched. Check --only IDs against detections.yml.")

    if args.list:
        for d in dets:
            print(f"{d['id']:12} {d['severity']:22} {d['name']}")
        return 0

    password = args.password or getpass.getpass(f"Splunk password for {args.user}@{args.host}: ")
    base = f"https://{args.host}:{args.port}"
    opener, pw_mgr, _ = build_opener(args.user, password, args.insecure)
    pw_mgr.add_password(None, base, args.user, password)

    print(f"# Running {len(dets)} detection(s) against {base}")
    print(f"# Window: earliest={args.earliest} latest={args.latest}\n")
    print(f"{'TECHNIQUE':12} {'HITS':>6}  {'RESULT':8} DETECTION")
    print("-" * 64)

    failures = 0
    errors = 0
    for d in dets:
        try:
            hits = splunk_search(opener, base, d["search"], args.earliest, args.latest)
        except Exception as e:  # network/auth/search error — report, keep going
            errors += 1
            print(f"{d['id']:12} {'--':>6}  {'ERROR':8} {d['name']}  ({e})")
            continue
        expected = d.get("expect_hits", False)
        if hits > 0:
            status = "HIT"
        elif expected:
            status = "MISS"
            failures += 1
        else:
            status = "none"
        print(f"{d['id']:12} {hits:>6}  {status:8} {d['name']}")

    print("-" * 64)
    print(f"# {len(dets)} run, {failures} expected-but-missed, {errors} error(s)")

    if errors:
        return 2
    if args.strict and failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
