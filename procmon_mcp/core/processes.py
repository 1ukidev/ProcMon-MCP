"""Process listing, snapshots, and timed capture."""

from __future__ import annotations

import subprocess
import time
from datetime import datetime
from typing import Any

from ..utils.parsing import parse_pipe_output
from ..utils.powershell import run_ps_script


def list_processes(
    name_filter: str | None = None,
    pid_filter: int | None = None,
) -> dict[str, Any]:
    nf = name_filter or ""
    pf = pid_filter
    ps_filter = ""
    if pf is not None:
        ps_filter = f"$list = @(Get-Process -Id {int(pf)} -ErrorAction SilentlyContinue)"
    elif nf.strip():
        esc = nf.strip().replace("'", "''")
        ps_filter = f"$list = @(Get-Process -Name '{esc}' -ErrorAction SilentlyContinue)"
    else:
        ps_filter = "$list = @(Get-Process -ErrorAction SilentlyContinue)"

    script = rf"""
{ps_filter}
foreach ($proc in $list) {{
  $path = ''
  try {{ $path = $proc.MainModule.FileName }} catch {{ $path = '' }}
  $ppid = ''
  try {{
    $ppid = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -EA SilentlyContinue).ParentProcessId
  }} catch {{ $ppid = '' }}
  $start = ''
  try {{ $start = $proc.StartTime.ToString('o') }} catch {{ $start = '' }}
  $ws = [math]::Round($proc.WorkingSet64/1MB,2)
  $line = "$($proc.ProcessName)|$($proc.Id)|$($proc.HandleCount)|$($proc.Threads.Count)|$ws|$path|$ppid|$start"
  Write-Output $line
}}
"""
    result_proc = run_ps_script(script.strip(), timeout=120)
    lines_out = [ln for ln in (result_proc.stdout or "").split("\n") if ln.strip()]
    fields = ["name", "pid", "handles", "threads", "working_set_mb", "path", "parent_pid", "start_time"]
    rows = parse_pipe_output(lines_out, fields)
    warn = []
    if result_proc.stderr and result_proc.stderr.strip():
        warn.append(result_proc.stderr.strip()[:2000])
    return {"processes": rows, "warnings": warn}


def get_process_details(pid: int | None = None, name: str | None = None) -> dict[str, Any]:
    warnings: list[str] = []
    if pid is None and (not name or not str(name).strip()):
        return {"error": "bad_arguments", "message": "Provide pid or name"}
    target = ""
    if pid is not None:
        target = f"-Id {int(pid)}"
    else:
        esc = str(name).strip().replace("'", "''")
        target = f"-Name '{esc}'"

    script = rf"""
$p = @(Get-Process {target} -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($null -eq $p -or $p.Count -eq 0) {{ Write-Output 'MISSING'; exit 0 }}
$p = $p[0]
$procId = $p.Id
$pname = $p.ProcessName
$path = ''
try {{ $path = $p.MainModule.FileName }} catch {{ $path = '' }}
$cmdline = ''
try {{
  $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue).CommandLine
}} catch {{ $cmdline = '' }}
$modules = New-Object System.Collections.Generic.List[string]
try {{
  foreach ($m in @($p.Modules)) {{
    $mn = ''
    try {{ $mn = $m.ModuleName }} catch {{ $mn = '' }}
    $fp = ''
    try {{ $fp = $m.FileName }} catch {{ $fp = '' }}
    [void]$modules.Add("$mn`t$fp")
  }}
}} catch {{
  Write-Output "MODULE_WARN|$($_ -replace '[|`r`n]',' ')"
}}
$threads = @($p.Threads | ForEach-Object {{ "$($_.Id)" }}) -join ','
$ws = [math]::Round($p.WorkingSet64/1MB,2)
$pg = [math]::Round($p.PagedMemorySize64/1MB,2)
$pv = [math]::Round($p.PrivateMemorySize64/1MB,2)
$vm = [math]::Round($p.VirtualMemorySize64/1MB,2)
Write-Output ("BASE|$pname|$procId|$path|$cmdline|$($p.HandleCount)|$threads|$ws|$pg|$pv|$vm")
foreach ($line in $modules) {{
  Write-Output ("MOD|" + ($line -replace '\|',' '))
}}
"""
    proc = run_ps_script(script.strip(), timeout=180)
    stdout = proc.stdout or ""
    if proc.stderr and proc.stderr.strip():
        warnings.append(proc.stderr.strip()[:2000])
    lines = [ln.strip() for ln in stdout.split("\n") if ln.strip()]
    if not lines or lines[0] == "MISSING":
        return {"found": False, "warnings": warnings}

    base_line = None
    mods: list[dict[str, str]] = []
    for ln in lines:
        if ln.startswith("MODULE_WARN|"):
            warnings.append(ln.split("|", 1)[1].strip())
            continue
        if ln.startswith("BASE|"):
            base_line = ln
        elif ln.startswith("MOD|"):
            rest = ln[4:]
            parts = rest.split("`t", 1)
            mods.append({"module_name": parts[0].strip(), "module_path": parts[1].strip() if len(parts) > 1 else ""})

    if not base_line:
        return {"found": False, "warnings": warnings}

    bp = base_line.split("|")
    detail = {
        "found": True,
        "name": bp[1] if len(bp) > 1 else "",
        "pid": bp[2] if len(bp) > 2 else "",
        "path": bp[3] if len(bp) > 3 else "",
        "command_line": bp[4] if len(bp) > 4 else "",
        "handle_count": bp[5] if len(bp) > 5 else "",
        "thread_ids": (bp[6] if len(bp) > 6 else "").split(",") if len(bp) > 6 else [],
        "memory_breakdown_mb": {
            "working_set": bp[7] if len(bp) > 7 else "",
            "paged": bp[8] if len(bp) > 8 else "",
            "private": bp[9] if len(bp) > 9 else "",
            "virtual": bp[10] if len(bp) > 10 else "",
        },
        "modules": mods,
        "handles": [],
        "warnings": warnings,
    }
    return detail


def _snapshot_for_targets(process_names: list[str] | None, pids: list[int] | None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "processes": [],
        "modules": [],
        "network": [],
        "warnings": [],
    }

    names_clean = [str(n).strip().replace("'", "''") for n in (process_names or []) if str(n).strip()]
    name_ps = ",".join(f"'{n}'" for n in names_clean)
    if pids:
        id_join = ",".join(str(int(x)) for x in pids)
        proc_src = (
            f"$pids = @({id_join}); $targets = @($pids |"
            " ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })"
        )
    elif name_ps:
        proc_src = f"$targets = @(Get-Process -Name @({name_ps}) -ErrorAction SilentlyContinue)"
    else:
        proc_src = "$targets = @(Get-Process -ErrorAction SilentlyContinue)"

    ps_procs = rf"""
{proc_src}
foreach ($proc in $targets) {{
  $path = ''
  try {{ $path = $proc.MainModule.FileName }} catch {{ $path = '' }}
  $ppid = ''
  try {{
    $ppid = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -EA SilentlyContinue).ParentProcessId
  }} catch {{ $ppid = '' }}
  $start = ''
  try {{ $start = $proc.StartTime.ToString('o') }} catch {{ $start = '' }}
  $ws = [math]::Round($proc.WorkingSet64/1MB,2)
  Write-Output ("$($proc.ProcessName)|$($proc.Id)|$($proc.HandleCount)|$($proc.Threads.Count)|$ws|$path|$ppid|$start")
}}
"""
    r1 = run_ps_script(ps_procs.strip(), timeout=120)
    if r1.stderr and r1.stderr.strip():
        data["warnings"].append(r1.stderr.strip()[:2000])
    fields = ["name", "pid", "handles", "threads", "working_set_mb", "path", "parent_pid", "start_time"]
    data["processes"] = parse_pipe_output([ln for ln in (r1.stdout or "").split("\n") if ln.strip()], fields)

    pid_expr = ""
    if data["processes"]:
        plist = ",".join(str(int(p["pid"])) for p in data["processes"] if str(p.get("pid", "")).isdigit())
        if plist:
            pid_expr = plist
    elif pids:
        pid_expr = ",".join(str(int(x)) for x in pids)
    elif name_ps:
        ps_ids = rf"""
{proc_src}
$targets | ForEach-Object {{ $_.Id }} | Sort-Object -Unique | ForEach-Object {{ Write-Output $_ }}
"""
        r_ids = run_ps_script(ps_ids.strip(), timeout=60)
        ids = [ln.strip() for ln in (r_ids.stdout or "").split("\n") if ln.strip().isdigit()]
        pid_expr = ",".join(ids)

    if pid_expr:
        ps_mod = rf"""
$pids = @({pid_expr})
foreach ($procId in $pids) {{
  $pn = ''
  try {{ $pn = (Get-Process -Id $procId -ErrorAction SilentlyContinue).ProcessName }} catch {{ $pn = '' }}
  try {{
    $dp = [System.Diagnostics.Process]::GetProcessById($procId)
    foreach ($mo in @($dp.Modules)) {{
      $mn = ''
      try {{ $mn = $mo.ModuleName }} catch {{ $mn = '' }}
      $fp = ''
      try {{ $fp = $mo.FileName }} catch {{ $fp = '' }}
      Write-Output ("$pn|$procId|$mn|$fp")
    }}
  }} catch {{
    Write-Output ("WARN|module_enum_failed|$procId|" + ($_ -replace '[|`r`n]',' '))
  }}
}}
"""
        r2 = run_ps_script(ps_mod.strip(), timeout=180)
        if r2.stderr and r2.stderr.strip():
            data["warnings"].append(r2.stderr.strip()[:2000])
        for ln in (r2.stdout or "").split("\n"):
            ln = ln.strip()
            if not ln:
                continue
            if ln.startswith("WARN|"):
                parts = ln.split("|", 3)
                if len(parts) >= 4:
                    data["warnings"].append(parts[3].strip())
                continue
            parts = ln.split("|")
            if len(parts) >= 4:
                data["modules"].append(
                    {
                        "process": parts[0],
                        "pid": parts[1],
                        "module_name": parts[2],
                        "module_path": parts[3],
                    }
                )

        ps_net = rf"""
$pids = @({pid_expr})
Get-NetTCPConnection -OwningProcess $pids -EA SilentlyContinue | ForEach-Object {{
  $proc = (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName
  $lo = "$($_.LocalAddress):$($_.LocalPort)"
  $re = "$($_.RemoteAddress):$($_.RemotePort)"
  Write-Output ("$proc|$($_.OwningProcess)|$lo|$re|$($_.State)|TCP")
}}
Get-NetUDPEndpoint -OwningProcess $pids -EA SilentlyContinue | ForEach-Object {{
  $proc = (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName
  Write-Output ("$proc|$($_.OwningProcess)|:$($_.LocalPort)||LISTENING|UDP")
}}
"""
        r3 = run_ps_script(ps_net.strip(), timeout=120)
        if r3.stderr and r3.stderr.strip():
            data["warnings"].append(r3.stderr.strip()[:2000])
        nf = ["process", "pid", "local", "remote", "state", "protocol"]
        data["network"] = parse_pipe_output([ln for ln in (r3.stdout or "").split("\n") if ln.strip()], nf)

    return data


def capture_snapshot(
    process_names: list[str] | None = None,
    pids: list[int] | None = None,
) -> dict[str, Any]:
    return _snapshot_for_targets(process_names, pids)


def timed_capture(
    process_names: list[str] | None = None,
    duration: int = 15,
    interval: int = 3,
    trigger_command: str | None = None,
) -> dict[str, Any]:
    snapshots: list[dict[str, Any]] = []
    started = time.time()
    if trigger_command and trigger_command.strip():
        try:
            subprocess.Popen(trigger_command.strip(), shell=True)
        except Exception as e:
            snapshots.append({"error": "trigger_failed", "message": str(e)})

    dur = max(1, int(duration))
    gap = max(1, int(interval))
    while time.time() - started < dur:
        snapshots.append(_snapshot_for_targets(process_names, None))
        remaining = dur - (time.time() - started)
        if remaining <= 0:
            break
        time.sleep(min(gap, remaining))

    return {
        "snapshot_count": len(snapshots),
        "duration_seconds": dur,
        "interval_seconds": gap,
        "snapshots": snapshots,
    }
