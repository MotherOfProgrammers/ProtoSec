import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from src.scanner_rules import ALLOWED_EXTENSIONS, SKIP_DIRS, analyze_file

try:
    from pydantic import BaseModel, ConfigDict
except ImportError:  # pragma: no cover - fallback for older Pydantic
    class ConfigDict(dict):
        pass

    class BaseModel:
        model_config = ConfigDict(extra="allow")

        def __init__(self, **data):
            self.__dict__.update(data)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCANNER_SOURCE_FILES = {
    path.resolve()
    for path in (
        Path(__file__),
        PROJECT_ROOT / "main.cpp",
        PROJECT_ROOT / "src" / "scanner_rules.py",
        PROJECT_ROOT / "core" / "src" / "main.cpp",
        PROJECT_ROOT / "core" / "src" / "scanner.cpp",
        PROJECT_ROOT / "core" / "include" / "mmap_file.hpp",
        PROJECT_ROOT / "core" / "include" / "rules.hpp",
        PROJECT_ROOT / "core" / "include" / "scanner.hpp",
    )
}


def scan_repository(root_path: Path | str, progress_callback=None) -> dict:
    root = Path(root_path)
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {root}")

    def raise_walk_error(error):
        raise error

    candidates = []
    for current_root, dirs, filenames in os.walk(root, onerror=raise_walk_error):
        dirs[:] = sorted(
            directory for directory in dirs
            if directory not in SKIP_DIRS
        )
        if progress_callback:
            relative_root = Path(current_root).relative_to(root).as_posix()
            progress_callback("discovering", 0, 0, relative_root)

        for filename in sorted(filenames):
            candidate = Path(current_root) / filename
            if candidate.resolve() in SCANNER_SOURCE_FILES:
                continue
            if candidate.suffix.lower() in ALLOWED_EXTENSIONS or candidate.name.lower().startswith(".env"):
                candidates.append(candidate)

    started = time.perf_counter()
    findings: list[dict] = []
    lines_scanned = 0
    progress_interval = max(1, len(candidates) // 100)
    for index, candidate in enumerate(candidates, start=1):
        file_findings, line_count = analyze_file(candidate, root)
        findings.extend(file_findings)
        lines_scanned += line_count
        if progress_callback and (
            index % progress_interval == 0 or index == len(candidates)
        ):
            progress_callback(
                "scanning",
                index,
                len(candidates),
                candidate.relative_to(root).as_posix(),
            )

    elapsed_ms = (time.perf_counter() - started) * 1000
    summary = {
        "critical": sum(item["severity"] == "CRITICAL" for item in findings),
        "high": sum(item["severity"] == "HIGH" for item in findings),
        "medium": sum(item["severity"] == "MEDIUM" for item in findings),
        "low": sum(item["severity"] == "LOW" for item in findings),
        "total": len(findings),
    }
    total_penalty = 0
    for finding in findings:
        severity = finding["severity"]
        if severity == "CRITICAL":
            total_penalty += 25
        elif severity == "HIGH":
            total_penalty += 12
        elif severity == "MEDIUM":
            total_penalty += 5
        else:
            total_penalty += 2

    report = {
        "total_issues": len(findings),
        "findings": findings,
        "security_score": max(0, 100 - total_penalty),
        "files_scanned": len(candidates),
        "lines_scanned": lines_scanned,
        "elapsed_ms": round(elapsed_ms, 2),
        "summary": summary,
    }
    return report


def scanner_binary_path() -> Path:
    binary_name = "scanner_core.exe" if sys.platform == "win32" else "scanner_core"
    application_dir = PROJECT_ROOT
    candidates = (
        application_dir / binary_name,
        application_dir / "build" / "bin" / binary_name,
        application_dir / "build" / "cmake" / "bin" / binary_name,
    )
    return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])


async def run_cpp_scanner(repo_path: str) -> dict:
    process = await asyncio.create_subprocess_exec(
        str(scanner_binary_path()),
        repo_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr.decode() or "Scanner error")
    return json.loads(stdout.decode())


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    repo_url: str


async def trigger_scan(payload: ScanRequest) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        proc = await asyncio.create_subprocess_exec(
            "git",
            "clone",
            "--depth",
            "1",
            payload.repo_url,
            tmpdir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(stderr.decode() or "Git clone failed")

        if scanner_binary_path().is_file():
            return await run_cpp_scanner(tmpdir)
        return scan_repository(tmpdir)


def create_app():
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError:  # pragma: no cover
        return None

    app = FastAPI(title="ProtoSec API")

    @app.post("/api/scan")
    async def trigger_scan_api(payload: ScanRequest):
        try:
            return await trigger_scan(payload)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ProtoSec scanner")
    parser.add_argument("--version", action="version", version="ProtoSec v1.0.0")
    parser.add_argument("repo_path", nargs="?", default=".")
    parser.add_argument("--serve", action="store_true", help="Run the FastAPI app if FastAPI is installed")
    args = parser.parse_args(argv)

    if args.serve:
        app = create_app()
        if app is None:
            print("FastAPI is not installed; cannot start the API server.", file=sys.stderr)
            return 1
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=8000)
        return 0

    report = scan_repository(args.repo_path)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())