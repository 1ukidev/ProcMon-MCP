# procmon-mcp

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://github.com/0xhackerfren/ProcMon-MCP)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/0xhackerfren/ProcMon-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/0xhackerfren/ProcMon-MCP/actions/workflows/ci.yml)

An MCP server that gives AI assistants deep visibility into Windows internals: processes, ETW kernel traces, event logs, services, drivers, minifilters, and static PE analysis. Built for security researchers, reverse engineers, and anyone who wants an LLM that can actually see what Windows is doing.

> **This is a proof of concept (POC). Use at your own risk.**
>
> procmon-mcp interacts directly with sensitive Windows internals: kernel ETW traces, process memory, security event logs, service/driver enumeration, and UAC elevation requests. These operations can affect system stability, expose sensitive data, and require administrator privileges. There are no guardrails beyond what Windows itself enforces. **Review the tool list, understand what each tool does, and run this only in environments you control.** The authors assume no liability for misuse or unintended consequences.

## Why?

LLMs are blind to what your OS is doing. Every time you need process info, network connections, or trace data, you're alt-tabbing to Task Manager, Process Monitor, or PowerShell and pasting results back. procmon-mcp eliminates that loop -- your AI assistant can directly query 18 tools covering live process state, kernel ETW traces, PE internals, event logs, services, drivers, and minifilters. Ask a question, get structured data, stay in flow.

## Quickstart

```
pip install procmon-mcp
```

Or run without installing:

```
uvx procmon-mcp
```

## Example prompts

Once connected, try asking your AI assistant:

- "What processes are making network connections right now?"
- "Start an ETW trace, launch notepad, stop the trace, and show me what happened"
- "Analyze the PE imports of C:\Windows\System32\cmd.exe and categorize the APIs"
- "Are any non-Microsoft services running? Show me their binary paths"
- "Show me recent logon events from the Security log"
- "Take a 30-second timed capture of all svchost processes and summarize the changes"
- "List all minifilter drivers and their altitudes"
- "What AV products does SecurityCenter2 report?"

## Features

- **Processes** -- list, detailed metadata (modules, threads, command line, memory), point-in-time snapshots, timed multi-snapshots with optional trigger commands
- **ETW** -- start/stop kernel traces with logman and tracerpt, list providers, preview CSV and summary output
- **Network** -- TCP and UDP endpoint enumeration with owning process filters
- **Services and drivers** -- service listing with binary paths, kernel driver enumeration, fltmc minifilter output
- **PE analysis** -- static import/export extraction with API category tags (Kernel API, Native API, Win32, Driver)
- **Event logs** -- Get-WinEvent queries and a Security log convenience wrapper for audit event IDs (4688, 4624, 4672, 4648)
- **System** -- OS build, AV product snapshot, elevation capability matrix, UAC helper
- **Presets** -- Defender process/service/driver constants and scan trigger helpers

## How it compares

procmon-mcp is the most comprehensive live Windows monitoring MCP server available. With 18 tools spanning processes, ETW kernel tracing, PE analysis, event logs, services, drivers, and minifilters, it covers more ground than any other single MCP server for live Windows internals. Other tools in this space either focus narrowly (process listing only, event logs only) or do offline forensics from Linux. procmon-mcp gives your AI assistant direct, real-time access to the full Windows instrumentation stack.

## MCP client configuration

### Cursor

Add to your MCP settings (`.cursor/mcp.json` or global settings):

```json
{
  "mcpServers": {
    "procmon-mcp": {
      "command": "procmon-mcp",
      "args": []
    }
  }
}
```

If you installed into a virtual environment, use `python -m procmon_mcp`:

```json
{
  "mcpServers": {
    "procmon-mcp": {
      "command": "python",
      "args": ["-m", "procmon_mcp"],
      "cwd": "C:\\path\\to\\your\\venv\\Scripts"
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "procmon-mcp": {
      "command": "procmon-mcp",
      "args": []
    }
  }
}
```

## Tool reference

| Tool | Description | Required parameters |
|------|-------------|---------------------|
| `list_processes` | Processes with optional name/PID filter | none |
| `get_process_details` | Modules, threads, command line, memory | none |
| `capture_snapshot` | Point-in-time process, module, and network snapshot | none |
| `timed_capture` | Repeated snapshots over a duration | none |
| `start_etw_trace` | Start a kernel ETW trace (requires elevation) | `session_name` |
| `stop_etw_trace` | Stop trace and convert ETL output | `session_name` |
| `list_etw_providers` | Parse `logman query providers` | none |
| `get_network_connections` | TCP/UDP endpoints by process | none |
| `list_services` | Win32 services with paths | none |
| `list_drivers` | Kernel drivers via WMI | none |
| `get_minifilters` | `fltmc` filter and instance output | none |
| `analyze_pe` | Static PE imports and exports | `file_path` |
| `find_pe_files` | Recursive PE file discovery | `directory` |
| `query_event_log` | `Get-WinEvent` FilterHashtable query | none |
| `get_security_events` | Security log (IDs 4688, 4624, 4672, 4648) | none |
| `get_system_info` | OS build and AV snapshot | none |
| `check_elevation` | Capability matrix | none |
| `request_elevation` | UAC helper for a shell command | `command` |

All tools accept optional parameters beyond those listed. See tool schemas for details.

## Elevation

Several capabilities require an elevated (administrator) token:

- **`start_etw_trace`** and **`stop_etw_trace`** use `logman` real-time sessions (`-ets`).
- **`get_security_events`** reads the Security log.

Other tools run without elevation but may return partial results when Windows blocks enumeration (protected processes, restricted logs). Use **`check_elevation`** for the full capability matrix.

## Presets

The Defender preset (`procmon_mcp.presets.defender`) provides constants (`DEFENDER_PROCESSES`, `DEFENDER_SERVICES`, `DEFENDER_DRIVERS`), binary discovery, `MpCmdRun` resolution, `trigger_scan`, and `get_preset_config`. MCP tools stay generic and preset-agnostic.

## Development

```
pip install -e ".[dev]"
ruff check .
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

## Security

**This is a POC. The operations performed are sensitive by nature.** This tool reads process memory, enumerates kernel drivers, starts ETW trace sessions, queries security audit logs, and can trigger UAC elevation prompts. Run it only on machines you own or have explicit authorization to instrument. Never point it at production systems without understanding the implications. See [SECURITY.md](SECURITY.md) for our security policy and responsible disclosure process.

## License

MIT. See [LICENSE](LICENSE).
