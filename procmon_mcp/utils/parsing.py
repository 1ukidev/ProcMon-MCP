"""Parsing helpers for PowerShell pipe output and ETW summaries."""

from __future__ import annotations

import csv
import re
from pathlib import Path


def parse_pipe_output(lines: list[str], fields: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.upper().startswith("ERROR:"):
            continue
        parts = line.split("|")
        if len(parts) < len(fields):
            continue
        row = {fields[i]: parts[i].strip() for i in range(len(fields))}
        rows.append(row)
    return rows


def parse_etw_summary(summary_path: str) -> list[dict[str, str]]:
    p = Path(summary_path)
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    rows: list[dict[str, str]] = []
    kv_pattern = re.compile(r"^\s*([A-Za-z][A-Za-z0-9\s\./%]+?)\s*:\s*(.+?)\s*$")
    for line in text.splitlines():
        m = kv_pattern.match(line)
        if m:
            rows.append({"key": m.group(1).strip(), "value": m.group(2).strip()})
    return rows


def parse_etw_csv_rows(
    csv_path: str,
    max_rows: int = 5000,
    process_filter: str | None = None,
) -> list[dict[str, str]]:
    path = Path(csv_path)
    if not path.is_file():
        return []
    pf = (process_filter or "").strip().lower()
    out: list[dict[str, str]] = []
    encodings = ("utf-8", "utf-16", "utf-16-le", "cp1252")
    for enc in encodings:
        try:
            with path.open(newline="", encoding=enc, errors="replace") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= max_rows:
                        break
                    if not row:
                        continue
                    norm = {str(k).strip(): (v if v is not None else "") for k, v in row.items()}
                    if pf:
                        blob = " ".join(str(v).lower() for v in norm.values())
                        if pf not in blob:
                            continue
                    out.append(norm)
            break
        except Exception:
            out = []
            continue
    return out
