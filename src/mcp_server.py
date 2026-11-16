from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from src.main import scan_repository, scanner_binary_path
from utils.custom_rules import scan_custom_rules
from utils.cve_audit import merge_findings


server = FastMCP("ProtoSec")


def _scan_local_project(project_path: str) -> dict:
    root = Path(project_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")

    scanner = scanner_binary_path()
    if not scanner.is_file():
        return scan_repository(root)

    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW
    try:
        completed = subprocess.run(
            [str(scanner), str(root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=300,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("The local scan exceeded its 5-minute limit.") from exc
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "The C++ scanner failed.")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("The C++ scanner returned an invalid report.") from exc
    return merge_findings(report, scan_custom_rules(root))


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
