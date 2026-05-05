"""Tests for elevation detection and capability reporting."""

from procmon_mcp.utils.elevation import capability_report, is_elevated

EXPECTED_TOOLS = {
    "list_processes",
    "get_process_details",
    "capture_snapshot",
    "timed_capture",
    "start_etw_trace",
    "stop_etw_trace",
    "list_etw_providers",
    "get_network_connections",
    "list_services",
    "list_drivers",
    "get_minifilters",
    "analyze_pe",
    "find_pe_files",
    "query_event_log",
    "get_security_events",
    "get_system_info",
    "check_elevation",
    "request_elevation",
}


def test_is_elevated_returns_bool():
    assert isinstance(is_elevated(), bool)


def test_capability_report_keys():
    report = capability_report()
    assert set(report.keys()) == EXPECTED_TOOLS


def test_capability_report_structure():
    report = capability_report()
    for tool_name, info in report.items():
        assert "requires_elevation" in info, f"{tool_name} missing requires_elevation"
        assert "notes" in info, f"{tool_name} missing notes"
        assert isinstance(info["requires_elevation"], bool)
        assert isinstance(info["notes"], str)


def test_etw_requires_elevation():
    report = capability_report()
    assert report["start_etw_trace"]["requires_elevation"] is True
    assert report["stop_etw_trace"]["requires_elevation"] is True
