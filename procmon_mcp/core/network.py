"""Network endpoints keyed by owning process."""

from __future__ import annotations

from typing import Any

from ..utils.parsing import parse_pipe_output
from ..utils.powershell import run_ps_script


def get_connections(
    process_name: str | None = None,
    pid: int | None = None,
    protocol: str = "tcp",
) -> dict[str, Any]:
    warnings: list[str] = []
    proto = (protocol or "tcp").lower().strip()

    filter_tcp = ""
    filter_udp = ""
    if pid is not None:
        filter_tcp = f"Get-NetTCPConnection -OwningProcess {int(pid)} -ErrorAction SilentlyContinue"
        filter_udp = f"Get-NetUDPEndpoint -OwningProcess {int(pid)} -ErrorAction SilentlyContinue"
    elif process_name and str(process_name).strip():
        esc = str(process_name).strip().replace("'", "''")
        filter_tcp = (
            f"$pn = '{esc}'; "
            "Get-NetTCPConnection -ErrorAction SilentlyContinue "
            "| Where-Object { $_.OwningProcess -ne 0 -and "
            "(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName -eq $pn }"
        )
        filter_udp = (
            f"$pn = '{esc}'; "
            "Get-NetUDPEndpoint -ErrorAction SilentlyContinue "
            "| Where-Object { $_.OwningProcess -ne 0 -and "
            "(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName -eq $pn }"
        )
    else:
        filter_tcp = "Get-NetTCPConnection -ErrorAction SilentlyContinue"
        filter_udp = "Get-NetUDPEndpoint -ErrorAction SilentlyContinue"

    blocks: list[str] = []
    if proto in ("tcp", "both", "all"):
        blocks.append(
            rf"""
{filter_tcp} | ForEach-Object {{
  $proc = (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName
  $lo = "$($_.LocalAddress):$($_.LocalPort)"
  $re = "$($_.RemoteAddress):$($_.RemotePort)"
  Write-Output ("$proc|$($_.OwningProcess)|$lo|$re|$($_.State)|TCP")
}}
"""
        )
    if proto in ("udp", "both", "all"):
        blocks.append(
            rf"""
{filter_udp} | ForEach-Object {{
  $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
  Write-Output ("$proc|$($_.OwningProcess)|$($_.LocalAddress):$($_.LocalPort)||BOUND|UDP")
}}
"""
        )

    script = "\n".join(blocks)
    proc = run_ps_script(script.strip(), timeout=120)
    if proc.stderr and proc.stderr.strip():
        warnings.append(proc.stderr.strip()[:2000])
    fields = ["process", "pid", "local", "remote", "state", "protocol"]
    rows = parse_pipe_output([ln for ln in (proc.stdout or "").split("\n") if ln.strip()], fields)
    return {"connections": rows, "warnings": warnings}
