"""Minimal library usage (not via MCP): import core helpers and print summaries."""

from __future__ import annotations

import json
import os

from procmon_mcp.core.pe_analysis import analyze_pe
from procmon_mcp.core.processes import list_processes
from procmon_mcp.core.system import check_elevation


def main() -> None:
    elev = check_elevation()
    print("elevation:")
    print(json.dumps(elev, indent=2)[:1200])

    procs = list_processes(name_filter="explorer")
    print("\nexplorer processes (first row):")
    rows = procs.get("processes") or []
    print(json.dumps(rows[0], indent=2) if rows else "(none)")

    path = os.environ.get("WINDIR", r"C:\Windows")
    candidate = os.path.join(path, "System32", "notepad.exe")
    pe = analyze_pe(candidate)
    print("\nPE sample keys:", list(pe.keys()))
    if pe.get("error"):
        print("PE error:", pe)
    else:
        imps = pe.get("imports") or []
        print("import count:", len(imps))


if __name__ == "__main__":
    main()
