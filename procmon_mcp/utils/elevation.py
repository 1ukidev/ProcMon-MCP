"""Elevation detection and UAC helpers."""

from __future__ import annotations

import base64
import os
import subprocess
import tempfile
from pathlib import Path

try:
    import ctypes
except ImportError:
    ctypes = None


def is_elevated() -> bool:
    if ctypes is None:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def capability_report() -> dict[str, dict[str, object]]:
    return {
        "list_processes": {"requires_elevation": False, "notes": "Works as standard user"},
        "get_process_details": {
            "requires_elevation": False,
            "notes": "Protected processes may hide modules or metadata; partial data possible",
        },
        "capture_snapshot": {"requires_elevation": False, "notes": "Same limits as process details"},
        "timed_capture": {"requires_elevation": False, "notes": "Same limits as capture_snapshot"},
        "start_etw_trace": {
            "requires_elevation": True,
            "notes": "logman create trace uses -ets and needs an elevated token",
        },
        "stop_etw_trace": {
            "requires_elevation": True,
            "notes": "Stopping kernel trace sessions typically requires elevation",
        },
        "list_etw_providers": {"requires_elevation": False, "notes": "logman query providers usually works"},
        "get_network_connections": {"requires_elevation": False, "notes": "May omit some endpoints without admin"},
        "list_services": {"requires_elevation": False, "notes": "Get-Service is readable by standard users"},
        "list_drivers": {"requires_elevation": False, "notes": "Driver enumeration via CIM is usually readable"},
        "get_minifilters": {
            "requires_elevation": False,
            "notes": "fltmc may return partial output without elevation",
        },
        "analyze_pe": {"requires_elevation": False, "notes": "Reads files from disk only"},
        "find_pe_files": {"requires_elevation": False, "notes": "Directory scan only"},
        "query_event_log": {
            "requires_elevation": False,
            "notes": "Some logs (Security) require privileges even when readable remotely",
        },
        "get_security_events": {
            "requires_elevation": True,
            "notes": "Security log normally requires admin or specialized audit rights",
        },
        "get_system_info": {"requires_elevation": False, "notes": "Anti-virus WMI may fail without elevation"},
        "check_elevation": {"requires_elevation": False, "notes": "Diagnostic only"},
        "request_elevation": {"requires_elevation": False, "notes": "Launches an elevated helper via UAC"},
    }


def request_elevation(command: str, timeout: int = 60) -> dict[str, object]:
    """
    Launch command in an elevated cmd.exe session via UAC (blocking Wait).
    command is inserted into a temporary .cmd script.
    """
    if not command or not command.strip():
        return {"ok": False, "error": "empty_command", "message": "Provide a non-empty command string"}

    script_lines = ["@echo off", "setlocal", command.strip()]
    fd, tmp_path = tempfile.mkstemp(prefix="procmon_mcp_elev_", suffix=".cmd", text=True)
    path = Path(tmp_path)
    try:
        os.close(fd)
        path.write_text("\r\n".join(script_lines) + "\r\n", encoding="utf-8")
        ps = (
            "$p = Start-Process cmd.exe -Verb RunAs "
            f"-ArgumentList '/c','\"{str(path).replace(chr(39), chr(39) + chr(39))}\"' "
            "-Wait -PassThru -ErrorAction Stop; "
            "exit $p.ExitCode"
        )
        encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[-4000:],
            "stderr": (proc.stderr or "")[-4000:],
            "temp_script": str(path),
            "hint": "If exit_code is non-zero the user may have declined UAC or the script failed",
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "message": f"Elevation flow exceeded {timeout}s"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "message": str(e)}
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
