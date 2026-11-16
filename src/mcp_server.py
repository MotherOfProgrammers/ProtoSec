from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from utils.incremental_scan import scan_incremental_project


server = FastMCP("ProtoSec")


def _scan_local_project(project_path: str) -> dict:
    root = Path(project_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")
    return scan_incremental_project(root)


@server.tool()
def scan_project(project_path: str) -> dict:
    """Scan a local project directory and return the JSON findings."""
    return _scan_local_project(project_path)


@server.tool()
def verify_fix(project_path: str) -> dict:
    """Re-scan a local project after a change and report whether it is clean."""
    report = _scan_local_project(project_path)
    return {
        "verified": report.get("total_issues", len(report.get("findings", []))) == 0,
        "remaining_findings": report.get("findings", []),
        "security_score": report.get("security_score"),
    }


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
