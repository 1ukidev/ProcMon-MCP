"""Tests for parsing utilities."""

import tempfile
from pathlib import Path

from procmon_mcp.utils.parsing import (
    parse_etw_csv_rows,
    parse_etw_summary,
    parse_pipe_output,
)


def test_parse_pipe_output_basic():
    lines = ["foo | bar | baz", "one | two | three"]
    fields = ["a", "b", "c"]
    result = parse_pipe_output(lines, fields)
    assert len(result) == 2
    assert result[0] == {"a": "foo", "b": "bar", "c": "baz"}
    assert result[1] == {"a": "one", "b": "two", "c": "three"}


def test_parse_pipe_output_skips_errors():
    lines = ["ERROR: something went wrong", "foo|bar"]
    fields = ["a", "b"]
    result = parse_pipe_output(lines, fields)
    assert len(result) == 1
    assert result[0]["a"] == "foo"


def test_parse_pipe_output_skips_short_lines():
    lines = ["only_one_field"]
    fields = ["a", "b", "c"]
    result = parse_pipe_output(lines, fields)
    assert result == []


def test_parse_pipe_output_empty():
    assert parse_pipe_output([], ["a"]) == []


def test_parse_etw_summary_missing_file():
    result = parse_etw_summary("/nonexistent/path/summary.txt")
    assert result == []


def test_parse_etw_summary_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("Total Events: 1234\n")
        f.write("Lost Events: 0\n")
        f.write("\n")
        f.write("Some random line without colon\n")
        tmp = f.name
    try:
        result = parse_etw_summary(tmp)
        assert len(result) == 2
        assert result[0] == {"key": "Total Events", "value": "1234"}
        assert result[1] == {"key": "Lost Events", "value": "0"}
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_parse_etw_csv_rows_missing_file():
    result = parse_etw_csv_rows("/nonexistent/path/data.csv")
    assert result == []
