"""Services, drivers, and minifilters."""

from __future__ import annotations

from typing import Any

from ..utils.parsing import parse_pipe_output
from ..utils.powershell import run_cmd, run_ps_script


def list_services(
    name_filter: str | None = None,
    status_filter: str | None = None,
) -> dict[str, Any]:
    nf = (name_filter or "").strip().replace("'", "''")
    sf = (status_filter or "").strip().replace("'", "''")
    conds: list[str] = []
    if nf:
        conds.append(f"($_.Name -like '*{nf}*' -or $_.DisplayName -like '*{nf}*')")
    if sf:
        conds.append(f"($_.State.ToString() -eq '{sf}')")
    where_block = " -and ".join(conds) if conds else "$true"
    script = rf"""
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object {{ {where_block} }} |
  ForEach-Object {{
    Write-Output ("$($_.Name)|$($_.State)|$($_.StartMode)|$($_.DisplayName)|$($_.PathName)")
  }}
"""
    proc = run_ps_script(script.strip(), timeout=120)
    warnings = []
    if proc.stderr and proc.stderr.strip():
        warnings.append(proc.stderr.strip()[:2000])
    rows = parse_pipe_output(
        [ln for ln in (proc.stdout or "").split("\n") if ln.strip()],
        ["name", "status", "start_type", "display_name", "path"],
    )
    return {"services": rows, "warnings": warnings}


def list_drivers(name_filter: str | None = None) -> dict[str, Any]:
    nf = (name_filter or "").strip().replace("'", "''")
    where = ""
    if nf:
        where = f"| Where-Object {{ $_.Name -like '*{nf}*' }}"
    script = rf"""
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue {where} | ForEach-Object {{
  Write-Output ("$($_.Name)|$($_.State)|$($_.StartMode)|$($_.DisplayName)|$($_.PathName)")
}}
"""
    proc = run_ps_script(script.strip(), timeout=180)
    warnings = []
    if proc.stderr and proc.stderr.strip():
        warnings.append(proc.stderr.strip()[:2000])
    rows = parse_pipe_output(
        [ln for ln in (proc.stdout or "").split("\n") if ln.strip()],
        ["name", "state", "start_mode", "display_name", "path"],
    )
    return {"drivers": rows, "warnings": warnings}


def get_minifilters() -> dict[str, Any]:
    warnings: list[str] = []
    filt = run_cmd("fltmc filters", timeout=30)
    inst = run_cmd("fltmc instances", timeout=30)
    if filt.stderr and filt.stderr.strip():
        warnings.append(filt.stderr.strip()[:2000])
    if inst.stderr and inst.stderr.strip():
        warnings.append(inst.stderr.strip()[:2000])
    return {
        "filters_raw": [ln.strip() for ln in (filt.stdout or "").splitlines() if ln.strip()],
        "instances_raw": [ln.strip() for ln in (inst.stdout or "").splitlines() if ln.strip()],
        "warnings": warnings,
    }
