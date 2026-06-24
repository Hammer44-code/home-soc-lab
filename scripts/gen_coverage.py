#!/usr/bin/env python3
"""
gen_coverage.py — generate the detection coverage matrix from the detection docs.

Parses every detections/T*.md write-up and emits a Markdown table
(Technique | Title | Tactic | Severity | Status). The technique ID is taken from
the filename, everything else from the document body, so the matrix can never
drift out of sync with the write-ups — run this and diff against
detections/README.md to catch a doc that changed but the table didn't.

Usage:
    python3 scripts/gen_coverage.py                 # print the table to stdout
    python3 scripts/gen_coverage.py --check         # exit 1 if any field is unparseable

No third-party dependencies — standard library only.
"""
import argparse
import os
import re
import sys

# Repo layout: this file lives in scripts/, detections live in ../detections/.
HERE = os.path.dirname(os.path.abspath(__file__))
DETECTIONS_DIR = os.path.join(HERE, os.pardir, "detections")

# Kill-chain ordering so the table reads like an attack, not an alphabet.
TACTIC_ORDER = [
    "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


def tactic_rank(tactic):
    """Sort key: first named tactic that appears in the (possibly multi-) line."""
    for i, name in enumerate(TACTIC_ORDER):
        if name.lower() in tactic.lower():
            return i
    return len(TACTIC_ORDER)


def parse_doc(path):
    """Pull (technique, title, tactic, severity, status) out of one write-up."""
    fname = os.path.basename(path)
    text = open(path, encoding="utf-8").read()

    # Technique ID is the leading token of the filename: T1003.001-... / T1082-...
    m = re.match(r"(T\d+(?:\.\d+)?)", fname)
    technique = m.group(1) if m else "?"

    # Title: first "# Detection: <title>" heading.
    m = re.search(r"^#\s*(?:Detection:\s*)?(.+)$", text, re.M)
    title = m.group(1).strip() if m else "?"

    # Tactic: the "- **Tactic:** ..." bullet.
    m = re.search(r"\*\*Tactic:\*\*\s*(.+)", text)
    tactic = m.group(1).strip() if m else "?"
    # Trim the "(TA0005)" code and any trailing markdown for a clean cell.
    tactic = re.sub(r"\s*\(TA\d+\).*", "", tactic).strip()

    # Severity: first bolded token under the "## Severity" heading.
    severity = "?"
    m = re.search(r"^##\s*Severity\s*\n+(.+)", text, re.M)
    if m:
        line = m.group(1)
        b = re.search(r"\*\*(.+?)\*\*", line)
        severity = (b.group(1) if b else line.split()[0]).strip(" .")

    # Status: first ISO date within ~80 chars after a "validated" mention
    # (the window tolerates a technique ID like `T1003.001-2` sitting between
    # the word and the date, which a "." stop-class would truncate on).
    m = re.search(r"validated[^\n]{0,80}?(\d{4}-\d{2}-\d{2})", text, re.I)
    status = f"Validated {m.group(1)}" if m else "Validated"

    return {
        "technique": technique, "title": title, "tactic": tactic,
        "severity": severity, "status": status, "file": fname,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if any field failed to parse")
    args = ap.parse_args()

    docs = sorted(
        os.path.join(DETECTIONS_DIR, f)
        for f in os.listdir(DETECTIONS_DIR)
        if re.match(r"T\d+.*\.md$", f)
    )
    rows = [parse_doc(p) for p in docs]
    rows.sort(key=lambda r: (tactic_rank(r["tactic"]), r["technique"]))

    print("| Technique | Detection | Tactic | Severity | Status |")
    print("|---|---|---|---|---|")
    for r in rows:
        link = f"[{r['title']}](detections/{r['file']})"
        print(f"| {r['technique']} | {link} | {r['tactic']} | "
              f"{r['severity']} | {r['status']} |")

    tactics = sorted({r["tactic"] for r in rows}, key=tactic_rank)
    print(f"\n_{len(rows)} validated detections across {len(tactics)} ATT&CK "
          f"tactics: {', '.join(tactics)}._")

    if args.check:
        bad = [r for r in rows if "?" in (r["technique"], r["title"],
                                          r["tactic"], r["severity"])]
        if bad:
            sys.stderr.write(f"PARSE FAILURE in {len(bad)} doc(s): "
                             f"{', '.join(b['file'] for b in bad)}\n")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
