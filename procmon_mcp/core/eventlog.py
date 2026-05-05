"""Windows Event Log queries via PowerShell."""

from __future__ import annotations

from typing import Any

from ..utils.elevation import is_elevated
from ..utils.parsing import parse_pipe_output
from ..utils.powershell import run_ps_script


def query_event_log(
    log_name: str = "System",
    event_ids: list[int] | None = None,
    max_events: int = 50,
    hours_back: int = 24,
    level: str | None = None,
) -> dict[str, Any]:
    log_esc = log_name.replace("'", "''")
    ids = event_ids or []
    extra_assign = ""
    if ids:
        id_join = ",".join(str(int(i)) for i in ids)
        extra_assign += f'$filter["Id"] = @({id_join})\n'

    lvl_esc = (level or "").strip()
    if lvl_esc.isdigit():
        extra_assign += f'$filter["Level"] = [int]{lvl_esc}\n'

    script = rf"""
$filter = @{{
  LogName = '{log_esc}'
  StartTime = (Get-Date).AddHours(-{int(hours_back)})
}}
{extra_assign}
try {{
  Get-WinEvent -FilterHashtable $filter -MaxEvents {int(max_events)} -ErrorAction Stop |
    ForEach-Object {{
      $msg = ''
      try {{ $msg = $_.Message }} catch {{ $msg = '' }}
      $msg = ($msg -replace '[|`r`n]',' ')
      if ($msg.Length -gt 1200) {{ $msg = $msg.Substring(0,1200) }}
      Write-Output ("$($_.TimeCreated.ToString('o'))|$($_.Id)|$($_.LevelDisplayName)|$($_.ProviderName)|$msg")
    }}
}} catch {{
  Write-Output ("ERROR|" + ($_ -replace '[|`r`n]',' '))
}}
"""
    proc = run_ps_script(script.strip(), timeout=180)
    warnings: list[str] = []
    if proc.stderr and proc.stderr.strip():
        warnings.append(proc.stderr.strip()[:2000])

    rows_out: list[dict[str, str]] = []
    for ln in (proc.stdout or "").split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        if ln.startswith("ERROR|"):
            warnings.append(ln.split("|", 1)[1].strip())
            continue
        parsed = parse_pipe_output([ln], ["time", "id", "level", "source", "message"])
        rows_out.extend(parsed)

    return {"events": rows_out, "warnings": warnings}


def get_security_events(max_events: int = 50, hours_back: int = 24) -> dict[str, Any]:
    tool = "get_security_events"
    if not is_elevated():
        return {
            "error": "elevation_required",
            "tool": tool,
            "message": "This tool requires administrator privileges",
            "hint": "Use check_elevation to see capability matrix",
        }
    return query_event_log(
        log_name="Security",
        event_ids=[4688, 4624, 4672, 4648],
        max_events=max_events,
        hours_back=hours_back,
        level=None,
    )
