# Changelog

All notable changes to **procmon-mcp** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI workflow (GitHub Actions, Python 3.10-3.13 on Windows)
- Release workflow (PyPI trusted publisher, GitHub Releases)
- Test suite covering server registration, parsing utils, PE classification, and elevation
- SECURITY.md with responsible disclosure policy
- CHANGELOG.md
- CONTRIBUTING.md with code style, testing, and commit conventions
- GitHub issue and PR templates
- MCP Registry server.json
- .editorconfig for consistent formatting
- pyproject.toml metadata (classifiers, keywords, URLs, dev dependencies, ruff/pytest config)

## [0.1.0] - 2026-05-05

### Added

- MCP server with stdio transport for Windows process monitoring
- 18 tools: list_processes, get_process_details, capture_snapshot, timed_capture, start_etw_trace, stop_etw_trace, list_etw_providers, get_network_connections, list_services, list_drivers, get_minifilters, analyze_pe, find_pe_files, query_event_log, get_security_events, get_system_info, check_elevation, request_elevation
- ETW kernel tracing via logman and tracerpt
- Static PE import/export analysis with API category classification
- Windows event log queries via Get-WinEvent
- Service, driver, and minifilter enumeration
- Elevation detection and UAC helper
- Defender preset with process, service, and driver constants
- Cursor and Claude Desktop configuration support
