"""Windows Defender preset constants and helpers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

DEFENDER_PROCESSES = ["MsMpEng", "MpCmdRun", "NisSrv", "MsSense", "SecurityHealthService"]

DEFENDER_SERVICES = ["WinDefend", "WdNisSvc", "SecurityHealthService"]

DEFENDER_DRIVERS = ["WdFilter", "WdNisDrv", "WdBoot"]


def find_mpcmdrun() -> str | None:
    base = Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform")
    if not base.exists():
        return None
    candidates = sorted(base.rglob("MpCmdRun.exe"), reverse=True)
    return str(candidates[0]) if candidates else None


def find_defender_binaries() -> list[dict[str, Any]]:
    binaries: list[dict[str, Any]] = []
    base = Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform")
    if base.exists():
        for ext in ("*.exe", "*.dll"):
            for f in base.rglob(ext):
                binaries.append(
                    {
                        "path": str(f),
                        "name": f.name,
                        "size": f.stat().st_size,
                        "type": f.suffix[1:].upper(),
                    }
                )

    for sys_path in [
        r"C:\Windows\System32\drivers\WdFilter.sys",
        r"C:\Windows\System32\drivers\WdNisDrv.sys",
        r"C:\Windows\System32\drivers\WdBoot.sys",
    ]:
        p = Path(sys_path)
        if p.exists():
            binaries.append(
                {
                    "path": str(p),
                    "name": p.name,
                    "size": p.stat().st_size,
                    "type": "SYS",
                }
            )

    return binaries


def trigger_scan(scan_path: str | None = None, timeout: int = 30) -> dict[str, Any]:
    mpcmdrun = find_mpcmdrun()
    if not mpcmdrun:
        return {"ok": False, "error": "mpcmdrun_not_found", "message": "MpCmdRun.exe not found"}

    target = scan_path or os.environ.get("TEMP", r"C:\Windows\Temp")
    cmd = f'"{mpcmdrun}" -Scan -ScanType 3 -File "{target}"'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=int(timeout))
        return {
            "ok": result.returncode == 0,
            "command": cmd,
            "exit_code": result.returncode,
            "stdout": (result.stdout or "")[:2000],
            "stderr": (result.stderr or "")[:2000],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "status": "timeout", "message": f"Scan timed out after {timeout}s"}


def get_preset_config() -> dict[str, Any]:
    return {
        "process_names": list(DEFENDER_PROCESSES),
        "services": list(DEFENDER_SERVICES),
        "drivers": list(DEFENDER_DRIVERS),
        "mpcmdrun_path": find_mpcmdrun(),
    }
