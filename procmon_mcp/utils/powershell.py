"""PowerShell and shell execution helpers."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def run_ps(script: str, timeout: int = 30) -> list[str]:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (result.stdout or "").strip()
        return out.split("\n") if out else []
    except subprocess.TimeoutExpired:
        return [f"ERROR: timeout after {timeout}s"]
    except Exception as e:
        return [f"ERROR: {e}"]


def run_ps_script(script_body: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    fd, tmp_path = tempfile.mkstemp(prefix="procmon_mcp_", suffix=".ps1", text=True)
    path = Path(tmp_path)
    try:
        os.close(fd)
        path.write_text(script_body, encoding="utf-8")
        return subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def run_cmd(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
