#!/usr/bin/env python3
"""
csf_assess.py - NIST CSF 2.0 self-assessment worksheet + report generator.

A small, dependency-free tool for running a Cybersecurity Framework 2.0
self-assessment and producing portfolio-ready artifacts: a scored report and a
seeded risk register.

Two commands:
  init     Download the official NIST CSF 2.0 Core and write a blank worksheet CSV.
  report   Read the filled-in worksheet and produce a Markdown report + risk register.

Why it downloads from NIST instead of hard-coding the controls: the identifiers
and wording come from NIST's own CSF 2.0 reference spreadsheet (csf2.xlsx), so the
assessment cites the authoritative text rather than a possibly-wrong copy. NIST
CSF 2.0 is US-government public domain, so you can publish the resulting report,
control text and all.

Requires Python 3.8+ (standard library only; no pip installs). The official file
is an .xlsx (a zip of XML); this script reads it with zipfile + ElementTree.

Usage:
  python3 csf_assess.py init
  # ... edit csf-worksheet.csv: put 0-3 in the `rating` column, fill `evidence`/`notes` ...
  python3 csf_assess.py report

Rating scale (a common self-assessment convention, stated in the report):
  0 = Not Implemented   1 = Partially Implemented
  2 = Largely Implemented   3 = Fully Implemented
`target` defaults to 3; lower it per control if full implementation is not your goal.
"""

import argparse
import csv
import datetime as dt
import io
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import OrderedDict

CSF_XLSX_URL = "https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all"
SSML = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS = {"m": SSML}

RATING_SCALE = {
    0: "Not Implemented",
    1: "Partially Implemented",
    2: "Largely Implemented",
    3: "Fully Implemented",
}
DEFAULT_TARGET = 3

WORKSHEET = "csf-worksheet.csv"
REPORT_MD = "csf-assessment-report.md"
RISK_CSV = "csf-risk-register.csv"
SCOPE_FILE = "scope.txt"

FIELDS = [
    "function_id", "function", "category_id", "category",
    "subcategory_id", "subcategory", "rating", "target", "evidence", "notes",
]


# ----------------------------- fetch + parse ------------------------------- #

def fetch_bytes(local=None):
    if local:
        with open(local, "rb") as f:
            return f.read()
    req = urllib.request.Request(CSF_XLSX_URL, headers={"User-Agent": "csf-assess/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def _text(node):
    """All <t> text under an element, concatenated."""
    return "".join(t.text or "" for t in node.iter(f"{{{SSML}}}t"))


def _sheet_sort_key(name):
    mt = re.search(r"sheet(\d+)\.xml$", name)
    return int(mt.group(1)) if mt else 0


def parse_xlsx_sheets(data):
    """Return every worksheet as a list of row dicts ({column_letter: value}),
    in workbook sheet-number order. The CSF file keeps a cover sheet first and
    the control catalog on a later sheet, so the caller scans all of them."""
    z = zipfile.ZipFile(io.BytesIO(data))
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        for si in root.findall("m:si", NS):
            shared.append(_text(si))
    sheet_names = sorted((n for n in z.namelist()
                          if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")),
                         key=_sheet_sort_key)
    if not sheet_names:
        raise ValueError("No worksheet found inside the .xlsx.")
    sheets = []
    for sn in sheet_names:
        root = ET.fromstring(z.read(sn))
        rows = []
        for row in root.iter(f"{{{SSML}}}row"):
            cells = {}
            for c in row.findall("m:c", NS):
                col = re.match(r"[A-Z]+", c.get("r", "A")).group(0)
                ctype = c.get("t")
                v = c.find("m:v", NS)
                isn = c.find("m:is", NS)
                if ctype == "s" and v is not None:
                    val = shared[int(v.text)]
                elif ctype == "inlineStr" and isn is not None:
                    val = _text(isn)
                elif v is not None:
                    val = v.text or ""
                else:
                    val = ""
                cells[col] = (val or "").strip()
            rows.append(cells)
        sheets.append(rows)
    return sheets


def _split_func_cat(cell):
    """'GOVERN (GV): desc' -> ('GV', 'GOVERN'); 'Organizational Context (GV.OC): desc'
    -> ('GV.OC', 'Organizational Context'). The ID is not always at the end."""
    m = re.search(r"\(([A-Z]{2}(?:\.[A-Z]{2})?)\)", cell)
    if m:
        return m.group(1), cell[:m.start()].strip()
    return None, cell


def _split_sub(cell):
    """'GV.OC-01: The mission is understood ...' -> ('GV.OC-01', 'The mission ...')."""
    m = re.match(r"^\s*([A-Z]{2}\.[A-Z]{2}-\d{2})\s*:?\s*(.*)$", cell, re.S)
    if m:
        return m.group(1), m.group(2).strip()
    return None, cell


def _is_withdrawn(text):
    """The informative-references export carries retired CSF v1.1 controls, each
    flagged '[Withdrawn: ...]'. They are not part of CSF 2.0, so they are dropped."""
    return bool(re.match(r"\s*\[withdrawn", text or "", re.I))


def extract_elements(data):
    """Parse csf2.xlsx bytes into an ordered {id: element} map, forward-filling
    merged Function/Category cells and de-duplicating repeated subcategory rows
    (the informative-references export repeats a subcategory once per reference)."""
    sheets = parse_xlsx_sheets(data)
    rows, header_idx, cols = None, None, {}
    for sheet in sheets:
        for i, cells in enumerate(sheet):
            low = {k: v.lower() for k, v in cells.items()}
            if {"function", "category", "subcategory"} <= set(low.values()):
                rows, header_idx, cols = sheet, i, {}
                for k, v in low.items():
                    if v in ("function", "category", "subcategory"):
                        cols[v] = k
                break
        if header_idx is not None:
            break
    if header_idx is None:
        raise ValueError("Could not find the Function/Category/Subcategory header row.")

    seen = OrderedDict()
    cur_f = cur_c = ""
    for cells in rows[header_idx + 1:]:
        fcell = cells.get(cols["function"], "")
        ccell = cells.get(cols["category"], "")
        scell = cells.get(cols["subcategory"], "")
        if fcell:
            cur_f = fcell
        if ccell:
            cur_c = ccell
        if not scell:
            continue
        fid, fname = _split_func_cat(cur_f)
        cid, cname = _split_func_cat(cur_c)
        sid, stext = _split_sub(scell)
        if not sid:
            continue
        if _is_withdrawn(stext):
            continue
        if fid and fid not in seen:
            seen[fid] = {"type": "function", "id": fid, "title": fname, "text": fname}
        if cid and cid not in seen:
            seen[cid] = {"type": "category", "id": cid, "title": cname, "text": cname}
        if sid not in seen:
            seen[sid] = {"type": "subcategory", "id": sid, "title": "", "text": stext}
    return seen


def build_rows(seen):
    funcs = {k: v for k, v in seen.items() if v["type"] == "function"}
    cats = {k: v for k, v in seen.items() if v["type"] == "category"}
    subs = sorted((v for v in seen.values() if v["type"] == "subcategory"),
                  key=lambda s: s["id"])
    rows = []
    for s in subs:
        fid = s["id"].split(".")[0]      # GV.OC-01 -> GV
        cid = s["id"].split("-")[0]      # GV.OC-01 -> GV.OC
        rows.append({
            "function_id": fid,
            "function": funcs.get(fid, {}).get("title", fid),
            "category_id": cid,
            "category": cats.get(cid, {}).get("title", cid),
            "subcategory_id": s["id"],
            "subcategory": s["text"] or s["title"],
            "rating": "",
            "target": DEFAULT_TARGET,
            "evidence": "",
            "notes": "",
        })
    return rows


# -------------------------------- commands --------------------------------- #

def cmd_init(args):
    if os.path.exists(WORKSHEET) and not args.force:
        sys.exit(f"{WORKSHEET} already exists. Use --force to overwrite (you will lose your ratings).")
    print("Downloading the official NIST CSF 2.0 reference spreadsheet ...")
    try:
        data = fetch_bytes(args.local)
    except Exception as e:
        sys.exit(
            f"Could not fetch the CSF Core: {e}\n"
            "Fallback: open the CSF 2.0 Reference Tool at "
            "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/CSF_2_0_0/home , "
            "export the Core as Excel, save it, and run:\n"
            "  python3 csf_assess.py init --local path/to/csf2.xlsx"
        )
    try:
        seen = extract_elements(data)
        rows = build_rows(seen)
    except Exception as e:
        sys.exit(f"Downloaded the file but could not parse it: {e}")
    if not rows:
        sys.exit("Parsed the file but found no subcategories; inspect the spreadsheet layout.")
    with open(WORKSHEET, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    nfunc = len({r["function_id"] for r in rows})
    ncat = len({r["category_id"] for r in rows})
    print(f"Wrote {WORKSHEET}: {len(rows)} subcategories across {ncat} categories, {nfunc} functions.")
    print("Next: open it, put 0-3 in `rating` for each control, and fill `evidence`/`notes`.")
    print("Then:  python3 csf_assess.py report")


def parse_int(val, default=None):
    val = (val or "").strip()
    if val == "":
        return default
    try:
        return int(float(val))
    except ValueError:
        return default


NA_TOKENS = {"n/a", "na", "n.a.", "not applicable", "n\\a"}


def classify_rating(val):
    """Classify a rating cell into one of three kinds:
      ('na', None)      -> control does not apply here; excluded from scoring
      ('scored', 0..3)  -> a real rating
      ('unrated', None) -> blank or unreadable; counts as 0 so it still shows as a gap
    """
    s = (val or "").strip().lower()
    if s in NA_TOKENS:
        return ("na", None)
    n = parse_int(val)
    if n is None:
        return ("unrated", None)
    return ("scored", max(0, min(3, n)))


def load_worksheet():
    if not os.path.exists(WORKSHEET):
        sys.exit(f"{WORKSHEET} not found. Run `python3 csf_assess.py init` first.")
    # utf-8-sig tolerates a BOM if the sheet was saved from Excel.
    with open(WORKSHEET, "r", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        kind, score = classify_rating(r.get("rating"))
        r["_kind"] = kind
        r["_rating"] = score
        r["_target"] = parse_int(r.get("target"), default=DEFAULT_TARGET)
    return rows


def _score_of(r):
    """In-scope score: the rating, or 0 for an unrated (blank) in-scope control."""
    return r["_rating"] if r["_rating"] is not None else 0


def _clean(text):
    """Make a cell safe for a Markdown table."""
    return (text or "").replace("|", "/").replace("\n", " ").replace("\r", " ").strip()


def cmd_report(args):
    rows = load_worksheet()
    scored = [r for r in rows if r["_kind"] == "scored"]
    na = [r for r in rows if r["_kind"] == "na"]
    unrated = [r for r in rows if r["_kind"] == "unrated"]

    func_order, func_stats = [], {}
    for r in rows:
        fid = r["function_id"]
        if fid not in func_stats:
            func_stats[fid] = {"name": r["function"], "scores": [], "na": 0, "gaps": 0}
            func_order.append(fid)
        if r["_kind"] == "na":
            func_stats[fid]["na"] += 1
            continue
        s = _score_of(r)
        t = r["_target"] if r["_target"] is not None else DEFAULT_TARGET
        func_stats[fid]["scores"].append(s)
        if s < t:
            func_stats[fid]["gaps"] += 1

    gaps = []
    for r in rows:
        if r["_kind"] == "na":
            continue
        s = _score_of(r)
        t = r["_target"] if r["_target"] is not None else DEFAULT_TARGET
        if s < t:
            gaps.append((t - s, r, s, t))
    gaps.sort(key=lambda g: (-g[0], g[1]["subcategory_id"]))

    today = dt.date.today().isoformat()
    write_report_md(func_order, func_stats, gaps, na, scored, unrated, today)
    if os.path.exists(RISK_CSV) and not getattr(args, "fresh_risk", False):
        print(f"Kept existing {RISK_CSV} (your risk analysis is preserved). "
              f"Use --fresh-risk to regenerate it from scratch.")
    else:
        write_risk_register(gaps)

    all_scores = [_score_of(r) for r in scored]
    overall = sum(all_scores) / len(all_scores) if all_scores else 0
    print(f"Wrote {REPORT_MD} and {RISK_CSV}.")
    print(f"Scored: {len(scored)}  N/A: {len(na)}  Unrated: {len(unrated)}  "
          f"Overall maturity: {overall:.2f}/3  Gaps: {len(gaps)}.")
    if unrated:
        print(f"Note: {len(unrated)} control(s) had a blank/unreadable rating and were counted as 0.")


def write_report_md(func_order, func_stats, gaps, na, scored, unrated, today):
    all_scores = [_score_of(r) for r in scored]
    overall = sum(all_scores) / len(all_scores) if all_scores else 0

    out = []
    out.append("# NIST CSF 2.0 Self-Assessment")
    out.append("")
    out.append("**Assessor:** Daniel Paluck  ")
    out.append(f"**Date:** {today}  ")
    scope = "(state what you assessed, e.g. \"home lab / Proxmox environment\")"
    if os.path.exists(SCOPE_FILE):
        try:
            with open(SCOPE_FILE, "r", encoding="utf-8") as sf:
                s = sf.read().strip()
            if s:
                scope = s
        except OSError:
            pass
    out.append(f"**Scope:** {scope}  ")
    out.append("**Framework:** NIST Cybersecurity Framework 2.0 Core (control text is NIST public domain)")
    out.append("")
    out.append("## Methodology")
    out.append("")
    out.append("Each CSF 2.0 subcategory was rated on an implementation scale:")
    out.append("")
    out.append("| Rating | Meaning |")
    out.append("|--------|---------|")
    for k in sorted(RATING_SCALE):
        out.append(f"| {k} | {RATING_SCALE[k]} |")
    out.append("")
    out.append("`target` is the desired state per control (default 3). A control is a **gap** when "
               "its rating is below target. Controls marked **N/A** do not apply to this environment "
               "and are excluded from scoring; a blank rating counts as 0. This 0-3 scale is a "
               "self-assessment convention, not part of the CSF standard itself.")
    out.append("")
    out.append("## Overall Maturity")
    out.append("")
    out.append(f"**{overall:.2f} / 3** across {len(scored)} scored controls "
               f"({len(na)} marked N/A, {len(gaps)} gaps below target"
               + (f", {len(unrated)} unrated" if unrated else "") + ").")
    out.append("")
    out.append("## Summary by Function")
    out.append("")
    out.append("| Function | Scored | N/A | Avg rating | Gaps |")
    out.append("|----------|--------|-----|------------|------|")
    for fid in func_order:
        s = func_stats[fid]
        scored_n = len(s["scores"])
        avg = sum(s["scores"]) / scored_n if scored_n else 0
        avg_txt = f"{avg:.2f} / 3" if scored_n else "n/a"
        out.append(f"| {fid} {s['name']} | {scored_n} | {s['na']} | {avg_txt} | {s['gaps']} |")
    out.append("")
    out.append("## Prioritized Gaps")
    out.append("")
    out.append("Ordered by gap size (target minus current), then control ID. These feed the risk register.")
    out.append("")
    out.append("| Control | What it means | Current | Target | Observed state (evidence) |")
    out.append("|---------|---------------|---------|--------|---------------------------|")
    for _, r, score, target in gaps:
        meaning = _clean(r.get("plain_english") or r.get("subcategory"))
        ev = _clean(r.get("evidence"))
        out.append(f"| {r['subcategory_id']} | {meaning} | {score} | {target} | {ev} |")
    if not gaps:
        out.append("| (none) | all in-scope controls meet target | | | |")
    out.append("")
    if na:
        out.append("## Not Applicable")
        out.append("")
        out.append("Controls judged not applicable to this environment and excluded from scoring.")
        out.append("")
        out.append("| Control | What it means |")
        out.append("|---------|---------------|")
        for r in na:
            out.append(f"| {r['subcategory_id']} | {_clean(r.get('plain_english') or r.get('subcategory'))} |")
        out.append("")
    out.append("## How to use this")
    out.append("")
    out.append("1. Fill in the Scope line above.")
    out.append("2. Work the gap list top-down: each row is a finding; add a short remediation plan.")
    out.append("3. `csf-risk-register.csv` seeds a risk statement per gap for you to refine "
               "(add likelihood, impact, and a treatment plan).")
    out.append("")
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(out))


def write_risk_register(gaps):
    with open(RISK_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "risk_id", "control", "what_it_means", "current", "target",
            "observed_state", "risk_statement", "likelihood", "impact",
            "risk_level", "treatment_plan", "owner",
        ])
        for i, (_, r, score, target) in enumerate(gaps, start=1):
            statement = (
                f"Because '{r['subcategory_id']}' is only {RATING_SCALE.get(score, score)}, "
                "there is a risk that a related threat event is not adequately prevented, detected, "
                "or recovered from, leading to a potential impact on confidentiality, integrity, or "
                "availability."
            )
            w.writerow([
                f"R-{i:03d}", r["subcategory_id"],
                (r.get("plain_english") or r.get("subcategory") or ""),
                score, target, (r.get("evidence") or ""),
                statement, "", "", "", "", "Daniel Paluck",
            ])


def main():
    p = argparse.ArgumentParser(description="NIST CSF 2.0 self-assessment tool.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("init", help="download the CSF Core and write a blank worksheet")
    pi.add_argument("--local", help="use a local csf2.xlsx file instead of downloading")
    pi.add_argument("--force", action="store_true", help="overwrite an existing worksheet")
    pi.set_defaults(func=cmd_init)
    pr = sub.add_parser("report", help="build the report + risk register from the worksheet")
    pr.add_argument("--fresh-risk", action="store_true",
                    help="regenerate the risk register, discarding any manual risk analysis")
    pr.set_defaults(func=cmd_report)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
