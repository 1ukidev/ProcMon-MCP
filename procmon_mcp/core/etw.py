"""ETW tracing via logman and tracerpt."""

from __future__ import annotations

import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from ..utils.elevation import is_elevated
from ..utils.parsing import parse_etw_csv_rows, parse_etw_summary
from ..utils.powershell import run_cmd

ETW_PROVIDERS = {
    "Microsoft-Windows-Kernel-Process": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
    "Microsoft-Windows-Kernel-File": "{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
    "Microsoft-Windows-Kernel-Registry": "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}",
    "Microsoft-Windows-Kernel-Network": "{7DD42A49-5329-4832-8DFD-43D979153A88}",
}


def _resolve_guids(provider_keys: list[str] | None) -> list[str]:
    if not provider_keys:
        return list(ETW_PROVIDERS.values())
    seen: dict[str, None] = {}
    for key in provider_keys:
        k = key.strip()
        if k.startswith("{"):
            seen.setdefault(k, None)
            continue
        if k in ETW_PROVIDERS:
            seen.setdefault(ETW_PROVIDERS[k], None)
            continue
        hit = False
        for name, guid in ETW_PROVIDERS.items():
            if k.lower() in name.lower():
                seen.setdefault(guid, None)
                hit = True
                break
        if not hit:
            for guid in ETW_PROVIDERS.values():
                if k.lower() == guid.lower():
                    seen.setdefault(guid, None)
                    break
    return list(seen.keys()) if seen else list(ETW_PROVIDERS.values())


def _cleanup_session(session_name: str) -> None:
    safe = session_name.replace('"', "")
    run_cmd(f'logman stop "{safe}" -ets', timeout=60)
    run_cmd(f'logman delete "{safe}" -ets', timeout=60)


def start_trace(
    session_name: str,
    providers: list[str] | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    tool = "start_etw_trace"
    if not is_elevated():
        return {
            "error": "elevation_required",
            "tool": tool,
            "message": "This tool requires administrator privileges",
            "hint": "Use check_elevation to see capability matrix",
        }

    guids = _resolve_guids(providers or [])
    if not session_name.strip():
        return {"error": "bad_arguments", "message": "session_name is required"}

    out_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="procmon_etw_"))
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = session_name.strip().replace('"', "")
    etl_path = out_dir / f"{safe}_{ts}.etl"

    _cleanup_session(safe)

    first = guids[0]
    create = (
        f'logman create trace "{safe}" -ets '
        f'-o "{etl_path}" -bs 64 -nb 64 128 '
        f"-mode Circular -max 256 "
        f'-p "{first}" 0xFFFFFFFF 0x5'
    )
    res = run_cmd(create, timeout=120)
    if res.returncode == 0:
        for g in guids[1:]:
            run_cmd(f'logman update trace "{safe}" -ets -p "{g}" 0xFFFFFFFF 0x5', timeout=120)

    if res.returncode != 0:
        _cleanup_session(safe)
        fallback_guid = ETW_PROVIDERS["Microsoft-Windows-Kernel-Process"]
        create2 = f'logman create trace "{safe}" -ets -o "{etl_path}" -p "{fallback_guid}" 0xFFFFFFFF 0x5'
        res2 = run_cmd(create2, timeout=120)
        if res2.returncode != 0:
            return {
                "ok": False,
                "exit_code": res2.returncode,
                "stderr": (res2.stderr or "")[-4000:],
                "stdout": (res2.stdout or "")[-4000:],
            }

    return {
        "ok": True,
        "session_name": safe,
        "etl_path": str(etl_path),
        "output_dir": str(out_dir),
        "providers": guids,
    }


def stop_trace(
    session_name: str,
    output_dir: str | None = None,
    process_filter: str | None = None,
) -> dict[str, Any]:
    tool = "stop_etw_trace"
    if not is_elevated():
        return {
            "error": "elevation_required",
            "tool": tool,
            "message": "This tool requires administrator privileges",
            "hint": "Use check_elevation to see capability matrix",
        }

    safe = session_name.strip().replace('"', "")
    base_dir = Path(output_dir) if output_dir else Path(tempfile.gettempdir())
    base_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = base_dir / f"{safe}_{ts}_trace.csv"
    summary_path = base_dir / f"{safe}_{ts}_summary.txt"

    stop_res = run_cmd(f'logman stop "{safe}" -ets', timeout=120)

    etl_guess = None
    for p in sorted(base_dir.glob(f"{safe}_*.etl"), key=lambda x: x.stat().st_mtime, reverse=True):
        etl_guess = p
        break

    etl_path_str = str(etl_guess) if etl_guess else ""

    trace_ok = False
    if etl_path_str and Path(etl_path_str).is_file():
        tr = run_cmd(
            f'tracerpt "{etl_path_str}" -o "{csv_path}" -summary "{summary_path}" -of CSV -y',
            timeout=300,
        )
        trace_ok = tr.returncode == 0 and csv_path.is_file()

    summary_rows = parse_etw_summary(str(summary_path)) if summary_path.is_file() else []
    events_preview = parse_etw_csv_rows(str(csv_path), max_rows=2000, process_filter=process_filter)

    run_cmd(f'logman delete "{safe}" -ets', timeout=60)

    return {
        "ok": stop_res.returncode == 0 or trace_ok,
        "session_name": safe,
        "stop_stdout": (stop_res.stdout or "")[-2000:],
        "stop_stderr": (stop_res.stderr or "")[-2000:],
        "etl_path": etl_path_str,
        "csv_path": str(csv_path) if csv_path.is_file() else "",
        "summary_path": str(summary_path) if summary_path.is_file() else "",
        "summary_kv": summary_rows[:500],
        "events_preview": events_preview[:500],
        "event_preview_truncated": len(events_preview) >= 500,
    }


def list_providers(keyword: str | None = None) -> dict[str, Any]:
    warnings: list[str] = []
    res = run_cmd("logman query providers", timeout=120)
    if res.stderr and res.stderr.strip():
        warnings.append(res.stderr.strip()[:2000])
    rows: list[dict[str, str]] = []
    kw = (keyword or "").strip().lower()
    for line in (res.stdout or "").splitlines():
        line_st = line.strip()
        if not line_st:
            continue
        if kw and kw not in line_st.lower():
            continue
        rows.append({"line": line_st})
    return {"providers": rows[:2000], "warnings": warnings}


def get_active_sessions() -> dict[str, Any]:
    warnings: list[str] = []
    res = run_cmd("logman query -ets", timeout=60)
    if res.stderr and res.stderr.strip():
        warnings.append(res.stderr.strip()[:2000])
    names: list[str] = []
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("data collector"):
            continue
        if "---" in line:
            continue
        parts = re.split(r"\s{2,}", line)
        if parts and parts[0] and not parts[0].startswith("-"):
            names.append(parts[0].strip())
    return {"sessions": sorted(set(names)), "warnings": warnings}
