# Contributing

## Development setup

Install the package in editable mode with development dependencies from the repository root:

```text
pip install -e ".[dev]"
```

## Running the MCP server

```text
python -m procmon_mcp
```

## Code style

Use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```text
ruff check .
ruff format .
```

## Testing

From the repository root:

```text
pytest
```

New MCP tools should include tests. For suites that only run on Windows, mark them with `@pytest.mark.skipif` so non-Windows environments can skip them cleanly.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) style prefixes, for example:

- `feat:` for new behavior or tools
- `fix:` for bug fixes
- `docs:` for documentation only
- `test:` for test-only changes
- `chore:` for maintenance, tooling, or other non-user-facing work

## Pull request guidelines

- Summarize what changed and why so reviewers can follow the intent.
- Add or extend tests for behavior you introduce or fix.
- Update documentation when behavior, setup, or public contracts change.
- Confirm CI passes on your branch before requesting review.

Additional expectations for this repo:

- Keep tool handlers returning structured `dict` results (consistent keys, JSON-serializable values where the wire format requires it).
- When you add a new MCP tool, register it in `procmon_mcp/server.py` alongside the existing tools and route it through the same dispatch pattern.

## Platform notes

This project is **Windows only**. Process and trace behavior depends on PowerShell, WMI/CIM, and ETW tooling that is not available on Linux or macOS.

ETW trace start and stop (`logman`, kernel session control) normally require an elevated administrator token. Run the host shell or IDE as administrator when you need full ETW coverage.
