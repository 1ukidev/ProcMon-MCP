"""System metadata and elevation wrappers."""

from __future__ import annotations

from typing import Any

from ..utils.elevation import capability_report, is_elevated
from ..utils.elevation import request_elevation as elevate_run
from ..utils.powershell import run_ps_script


def get_system_info() -> dict[str, Any]:
    warnings: list[str] = []
    script = r"""
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
$av = @()
try {
  $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
} catch {}

$c = ''; $v = ''; $b = ''; $arch = ''; $hn = ''
if ($null -ne $os) {
  try { $c = [string]$os.Caption } catch { $c = '' }
  try { $v = [string]$os.Version } catch { $v = '' }
  try { $b = [string]$os.BuildNumber } catch { $b = '' }
}
if ($null -ne $cs) {
  try { $arch = [string]$cs.SystemType } catch { $arch = '' }
}
try { $hn = [string]$env:COMPUTERNAME } catch { $hn = '' }
Write-Output ("OS|$c|$v|$b|$arch|$hn")

foreach ($p in $av) {
  $name = ''
  try { $name = $p.displayName } catch { $name = '' }
  $st = ''
  try { $st = $p.productState } catch { $st = '' }
  Write-Output ("AV|$name|$st")
}

Write-Output ("PS|" + ($PSVersionTable.PSVersion.ToString()))
"""
    proc = run_ps_script(script.strip(), timeout=120)
    if proc.stderr and proc.stderr.strip():
        warnings.append(proc.stderr.strip()[:2000])

    os_row: dict[str, str] = {}
    av_rows: list[dict[str, str]] = []
    ps_ver = ""

    for ln in (proc.stdout or "").split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split("|")
        if parts[0] == "OS" and len(parts) >= 6:
            os_row = {
                "caption": parts[1],
                "version": parts[2],
                "build": parts[3],
                "architecture": parts[4],
                "hostname": parts[5],
            }
        elif parts[0] == "AV" and len(parts) >= 3:
            av_rows.append({"display_name": parts[1], "product_state": parts[2]})
        elif parts[0] == "PS" and len(parts) >= 2:
            ps_ver = parts[1]

    return {
        "os": os_row,
        "computer": {"hostname": os_row.get("hostname", "")},
        "security_products": av_rows,
        "powershell_version": ps_ver,
        "elevated": is_elevated(),
        "warnings": warnings,
    }


def check_elevation() -> dict[str, Any]:
    return {
        "elevated": is_elevated(),
        "capabilities": capability_report(),
    }


def request_elevation(command: str, timeout: int = 60) -> dict[str, Any]:
    return elevate_run(command, timeout=timeout)
