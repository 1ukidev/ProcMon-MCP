#!/usr/bin/env python3
"""MCP server: Windows process monitoring, ETW, and PE analysis (tool routing)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    HAS_MCP = True
except ImportError:
    HAS_MCP = False

from .core import etw as mod_etw
from .core import eventlog as mod_eventlog
from .core import network as mod_network
from .core import pe_analysis as mod_pe
from .core import processes as mod_processes
from .core import services as mod_services
from .core import system as mod_system


def _arg_int(arguments: dict[str, Any], key: str, default: Any = None) -> Any:
    if key not in arguments or arguments[key] is None:
        return default
    v = arguments[key]
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _arg_str(arguments: dict[str, Any], key: str, default: str | None = None) -> str | None:
    v = arguments.get(key, default)
    if v is None:
        return default
    return str(v)


def _arg_list(arguments: dict[str, Any], key: str) -> list[Any]:
    v = arguments.get(key)
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


if HAS_MCP:

    def _dump(data: Any):
        return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]

    app = Server("procmon-mcp")

    @app.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="list_processes",
                description=(
                    "List processes with optional name or PID filter."
                    " Returns handles, threads, working set, path, parent PID, start time."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name_filter": {"type": "string", "description": "Filter by process name"},
                        "pid_filter": {"type": "integer", "description": "Filter by PID"},
                    },
                    "required": [],
                },
            ),
            Tool(
                name="get_process_details",
                description=(
                    "Deep process details: modules, handle count, threads, command line,"
                    " memory breakdown. May warn on protected processes."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer"},
                        "name": {"type": "string"},
                    },
                    "required": [],
                },
            ),
            Tool(
                name="capture_snapshot",
                description="Point-in-time snapshot of matching processes: processes, modules, network connections.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "process_names": {"type": "array", "items": {"type": "string"}},
                        "pids": {"type": "array", "items": {"type": "integer"}},
                    },
                    "required": [],
                },
            ),
            Tool(
                name="timed_capture",
                description="Repeated snapshots over a duration with optional shell trigger command launched at start.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "process_names": {"type": "array", "items": {"type": "string"}},
                        "duration": {"type": "integer", "description": "Seconds (default 15)"},
                        "interval": {"type": "integer", "description": "Seconds between snapshots (default 3)"},
                        "trigger_command": {
                            "type": "string",
                            "description": "Optional shell command to launch at start",
                        },
                    },
                    "required": [],
                },
            ),
            Tool(
                name="start_etw_trace",
                description=(
                    "Start a kernel ETW trace via logman (requires elevation)."
                    " providers are Microsoft-Windows-Kernel-* names or GUID strings."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_name": {"type": "string", "description": "Trace session name"},
                        "providers": {"type": "array", "items": {"type": "string"}},
                        "output_dir": {"type": "string", "description": "Directory for ETL output"},
                    },
                    "required": ["session_name"],
                },
            ),
            Tool(
                name="stop_etw_trace",
                description=(
                    "Stop ETW trace, run tracerpt to CSV and summary, return parsed preview (requires elevation)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_name": {"type": "string"},
                        "output_dir": {"type": "string"},
                        "process_filter": {"type": "string", "description": "Substring filter across CSV columns"},
                    },
                    "required": ["session_name"],
                },
            ),
            Tool(
                name="list_etw_providers",
                description="Parse logman query providers with optional keyword filter.",
                inputSchema={
                    "type": "object",
                    "properties": {"keyword": {"type": "string"}},
                    "required": [],
                },
            ),
            Tool(
                name="get_network_connections",
                description="TCP and/or UDP endpoints with owning process. protocol: tcp, udp, both, all.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "process_name": {"type": "string"},
                        "pid": {"type": "integer"},
                        "protocol": {"type": "string", "default": "tcp"},
                    },
                    "required": [],
                },
            ),
            Tool(
                name="list_services",
                description="Enumerate services via Win32_Service (name, state, start mode, display name, path).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name_filter": {
                            "type": "string",
                            "description": "Substring filter on name or display name",
                        },
                        "status_filter": {
                            "type": "string",
                            "description": "Exact Win32_Service.State match, e.g. Running",
                        },
                    },
                    "required": [],
                },
            ),
            Tool(
                name="list_drivers",
                description="Enumerate kernel drivers via Win32_SystemDriver.",
                inputSchema={
                    "type": "object",
                    "properties": {"name_filter": {"type": "string"}},
                    "required": [],
                },
            ),
            Tool(
                name="get_minifilters",
                description="Run fltmc filters and instances and return raw parsed lines.",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            Tool(
                name="analyze_pe",
                description="Parse a PE file with pefile: imports, exports, category summary.",
                inputSchema={
                    "type": "object",
                    "properties": {"file_path": {"type": "string"}},
                    "required": ["file_path"],
                },
            ),
            Tool(
                name="find_pe_files",
                description="Recursively discover PE files under a directory.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "directory": {"type": "string"},
                        "extensions": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["directory"],
                },
            ),
            Tool(
                name="query_event_log",
                description="Query a Windows event log via Get-WinEvent FilterHashtable.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "log_name": {"type": "string", "default": "System"},
                        "event_ids": {"type": "array", "items": {"type": "integer"}},
                        "max_events": {"type": "integer", "default": 50},
                        "hours_back": {"type": "integer", "default": 24},
                        "level": {"type": "string", "description": "Numeric level if needed"},
                    },
                    "required": [],
                },
            ),
            Tool(
                name="get_security_events",
                description="Security log convenience: IDs 4688, 4624, 4672, 4648 (requires elevation).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "max_events": {"type": "integer", "default": 50},
                        "hours_back": {"type": "integer", "default": 24},
                    },
                    "required": [],
                },
            ),
            Tool(
                name="get_system_info",
                description="OS build, architecture, hostname, SecurityCenter2 AV products, PowerShell version.",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            Tool(
                name="check_elevation",
                description="Whether the server is elevated plus a capability matrix for all tools.",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            Tool(
                name="request_elevation",
                description="Launch a cmd script via UAC (Start-Process -Verb RunAs) to run the given command.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "timeout": {"type": "integer", "default": 60},
                    },
                    "required": ["command"],
                },
            ),
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None):
        arguments = arguments or {}

        if name == "list_processes":
            pid = _arg_int(arguments, "pid_filter")
            nf = _arg_str(arguments, "name_filter")
            data = mod_processes.list_processes(name_filter=nf, pid_filter=pid)
            return _dump(data)

        if name == "get_process_details":
            pid = _arg_int(arguments, "pid")
            nm = _arg_str(arguments, "name")
            data = mod_processes.get_process_details(pid=pid, name=nm)
            return _dump(data)

        if name == "capture_snapshot":
            names = [str(x) for x in _arg_list(arguments, "process_names")]
            pids_raw = _arg_list(arguments, "pids")
            pids: list[int] = []
            for x in pids_raw:
                try:
                    pids.append(int(x))
                except (TypeError, ValueError):
                    continue
            data = mod_processes.capture_snapshot(
                process_names=names or None,
                pids=pids or None,
            )
            return _dump(data)

        if name == "timed_capture":
            names = [str(x) for x in _arg_list(arguments, "process_names")]
            duration = _arg_int(arguments, "duration", 15) or 15
            interval = _arg_int(arguments, "interval", 3) or 3
            trig = _arg_str(arguments, "trigger_command", None)
            data = mod_processes.timed_capture(
                process_names=names or None,
                duration=duration,
                interval=interval,
                trigger_command=trig,
            )
            return _dump(data)

        if name == "start_etw_trace":
            session = (_arg_str(arguments, "session_name", "") or "").strip()
            if not session:
                return _dump({"error": "bad_arguments", "message": "session_name is required"})
            providers = [str(x) for x in _arg_list(arguments, "providers")]
            out_dir = _arg_str(arguments, "output_dir", None)
            data = mod_etw.start_trace(
                session_name=session,
                providers=providers or None,
                output_dir=out_dir,
            )
            return _dump(data)

        if name == "stop_etw_trace":
            session = (_arg_str(arguments, "session_name", "") or "").strip()
            if not session:
                return _dump({"error": "bad_arguments", "message": "session_name is required"})
            out_dir = _arg_str(arguments, "output_dir", None)
            pf = _arg_str(arguments, "process_filter", None)
            data = mod_etw.stop_trace(session_name=session, output_dir=out_dir, process_filter=pf)
            return _dump(data)

        if name == "list_etw_providers":
            kw = _arg_str(arguments, "keyword", None)
            data = mod_etw.list_providers(keyword=kw)
            return _dump(data)

        if name == "get_network_connections":
            pn = _arg_str(arguments, "process_name", None)
            pid = _arg_int(arguments, "pid")
            proto = _arg_str(arguments, "protocol", "tcp") or "tcp"
            data = mod_network.get_connections(process_name=pn, pid=pid, protocol=proto)
            return _dump(data)

        if name == "list_services":
            nf = _arg_str(arguments, "name_filter", None)
            sf = _arg_str(arguments, "status_filter", None)
            data = mod_services.list_services(name_filter=nf, status_filter=sf)
            return _dump(data)

        if name == "list_drivers":
            nf = _arg_str(arguments, "name_filter", None)
            data = mod_services.list_drivers(name_filter=nf)
            return _dump(data)

        if name == "get_minifilters":
            data = mod_services.get_minifilters()
            return _dump(data)

        if name == "analyze_pe":
            fp = (_arg_str(arguments, "file_path", "") or "").strip()
            if not fp:
                return _dump({"error": "bad_arguments", "message": "file_path is required"})
            data = mod_pe.analyze_pe(fp)
            return _dump(data)

        if name == "find_pe_files":
            d = (_arg_str(arguments, "directory", "") or "").strip()
            if not d:
                return _dump({"error": "bad_arguments", "message": "directory is required"})
            exts = [str(x) for x in _arg_list(arguments, "extensions")]
            data = mod_pe.find_pe_files(d, extensions=exts or None)
            return _dump(data)

        if name == "query_event_log":
            log_name = _arg_str(arguments, "log_name", "System") or "System"
            ids_raw = _arg_list(arguments, "event_ids")
            event_ids = []
            for x in ids_raw:
                try:
                    event_ids.append(int(x))
                except (TypeError, ValueError):
                    continue
            max_ev = _arg_int(arguments, "max_events", 50) or 50
            hours = _arg_int(arguments, "hours_back", 24) or 24
            level = _arg_str(arguments, "level", None)
            data = mod_eventlog.query_event_log(
                log_name=log_name,
                event_ids=event_ids or None,
                max_events=max_ev,
                hours_back=hours,
                level=level,
            )
            return _dump(data)

        if name == "get_security_events":
            max_ev = _arg_int(arguments, "max_events", 50) or 50
            hours = _arg_int(arguments, "hours_back", 24) or 24
            data = mod_eventlog.get_security_events(max_events=max_ev, hours_back=hours)
            return _dump(data)

        if name == "get_system_info":
            return _dump(mod_system.get_system_info())

        if name == "check_elevation":
            return _dump(mod_system.check_elevation())

        if name == "request_elevation":
            cmd = _arg_str(arguments, "command", "") or ""
            timeout = _arg_int(arguments, "timeout", 60) or 60
            return _dump(mod_system.request_elevation(cmd, timeout=timeout))

        return _dump({"error": "unknown_tool", "name": name})

    async def main_async() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )

    def main() -> None:
        asyncio.run(main_async())

else:

    def main() -> None:
        print("MCP SDK not installed. Install with: pip install mcp")
        print("Running diagnostic snapshot instead...")
        print(json.dumps(mod_system.check_elevation(), indent=2))


if __name__ == "__main__":
    main()
