"""Tests for MCP server tool registration and dispatch."""

import json

import pytest

from procmon_mcp.server import HAS_MCP

pytestmark = pytest.mark.skipif(not HAS_MCP, reason="mcp SDK not installed")

if HAS_MCP:
    from procmon_mcp.server import call_tool, list_tools

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


@pytest.mark.asyncio
async def test_list_tools_count():
    tools = await list_tools()
    assert len(tools) == 18


@pytest.mark.asyncio
async def test_list_tools_names():
    tools = await list_tools()
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS


@pytest.mark.asyncio
async def test_list_tools_have_schemas():
    tools = await list_tools()
    for tool in tools:
        assert tool.inputSchema["type"] == "object"


@pytest.mark.asyncio
async def test_call_tool_unknown():
    result = await call_tool("nonexistent_tool", {})
    data = json.loads(result[0].text)
    assert data["error"] == "unknown_tool"
