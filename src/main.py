import argparse
import asyncio
import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from src.scanner_rules import ALLOWED_EXTENSIONS, SKIP_DIRS, analyze_file
from utils.custom_rules import scan_custom_rules
from utils.cve_audit import merge_findings

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
MAX_REPOSITORY_URL_LENGTH = 2048
CLONE_TIMEOUT_SECONDS = 120
DNS_RESOLUTION_TIMEOUT_SECONDS = 5
MAX_CLONE_SIZE_BYTES = 250 * 1024 * 1024
CLONE_SIZE_CHECK_INTERVAL_SECONDS = 0.75
SCAN_TIMEOUT_SECONDS = 180
MAX_CONCURRENT_API_SCANS = 2
_API_SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_API_SCANS)
_LOGGER = logging.getLogger(__name__)


class RepositoryUrlError(ValueError):
    pass


class CloneLimitError(RuntimeError):
    pass


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
            if candidate.is_symlink():
                continue
            if candidate.name == ".vibeguard.toml":
                continue
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
    return merge_findings(report, scan_custom_rules(root))


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
    stdout, stderr = await _communicate_with_timeout(
        process, SCAN_TIMEOUT_SECONDS, "C++ scan"
    )
    if process.returncode != 0:
        raise RuntimeError(stderr.decode() or "Scanner error")
    return json.loads(stdout.decode())


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo_url: str


def _validate_repository_url(repo_url: str) -> str:
    if not isinstance(repo_url, str) or not repo_url or len(repo_url) > MAX_REPOSITORY_URL_LENGTH:
        raise RepositoryUrlError("Repository URL must be a non-empty HTTPS URL under 2048 characters.")
    try:
        parsed = urlsplit(repo_url)
        hostname = (parsed.hostname or "").rstrip(".").casefold()
        port = parsed.port
    except ValueError as exc:
        raise RepositoryUrlError("Repository URL is invalid.") from exc
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise RepositoryUrlError(
            "Repository URL must use HTTPS and may not contain credentials, query, or fragment."
        )
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise RepositoryUrlError("Repository URL may not target localhost.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise RepositoryUrlError("Repository URL may not target a private or reserved IP address.")
    return repo_url


def _validate_repository_host(hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        results = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RepositoryUrlError("Repository hostname could not be resolved.") from exc
    addresses = {
        ipaddress.ip_address(result[4][0].split("%", 1)[0])
        for result in results
    }
    if not addresses or any(not address.is_global for address in addresses):
        raise RepositoryUrlError(
            "Repository hostname must resolve exclusively to public IP addresses."
        )
    return addresses


def _directory_size(root: str | Path) -> int:
    total = 0
    pending = [Path(root)]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    try:
                        total += entry.stat(follow_symlinks=False).st_size
                    except FileNotFoundError:
                        continue
    return total


async def _clone_repository(repo_url: str, destination: str | Path) -> None:
    proc = await asyncio.create_subprocess_exec(
        "git",
        "-c",
        "http.followRedirects=false",
        "clone",
        "--depth",
        "1",
        "--no-recurse-submodules",
        repo_url,
        str(destination),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    communication = asyncio.create_task(
        _communicate_with_timeout(proc, CLONE_TIMEOUT_SECONDS, "Repository clone")
    )
    try:
        while not communication.done():
            done, _ = await asyncio.wait(
                {communication},
                timeout=CLONE_SIZE_CHECK_INTERVAL_SECONDS,
            )
            if done:
                break
            size = await asyncio.to_thread(_directory_size, destination)
            if size > MAX_CLONE_SIZE_BYTES:
                raise CloneLimitError(
                    f"Repository clone exceeded the {MAX_CLONE_SIZE_BYTES // (1024 * 1024)} MiB size limit."
                )
        _, stderr = await communication
        if proc.returncode != 0:
            _LOGGER.warning("Repository clone failed: %s", stderr.decode(errors="replace")[:2000])
            raise RuntimeError("Repository clone failed.")
        if await asyncio.to_thread(_directory_size, destination) > MAX_CLONE_SIZE_BYTES:
            raise CloneLimitError(
                f"Repository clone exceeded the {MAX_CLONE_SIZE_BYTES // (1024 * 1024)} MiB size limit."
            )
    except (TimeoutError, CloneLimitError, OSError, RuntimeError):
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        if not communication.done():
            await communication
        raise


async def _communicate_with_timeout(
    process: asyncio.subprocess.Process,
    timeout_seconds: int,
    operation: str,
) -> tuple[bytes, bytes]:
    try:
        return await asyncio.wait_for(process.communicate(), timeout_seconds)
    except asyncio.TimeoutError as exc:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()
        raise TimeoutError(f"{operation} exceeded its {timeout_seconds}-second limit.") from exc


async def trigger_scan(payload: ScanRequest) -> dict:
    repo_url = _validate_repository_url(payload.repo_url)
    async with _API_SCAN_SEMAPHORE:
        hostname = (urlsplit(repo_url).hostname or "").rstrip(".").casefold()
        try:
            await asyncio.wait_for(
                asyncio.to_thread(_validate_repository_host, hostname),
                DNS_RESOLUTION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError("Repository DNS resolution exceeded its time limit.") from exc
        with tempfile.TemporaryDirectory(prefix="protosec-api-") as tmpdir:
            await _clone_repository(repo_url, tmpdir)

            if scanner_binary_path().is_file():
                return await run_cpp_scanner(tmpdir)
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "src.main",
                "--no-cache",
                tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=PROJECT_ROOT,
            )
            stdout, stderr = await _communicate_with_timeout(
                process, SCAN_TIMEOUT_SECONDS, "Python scan"
            )
            if process.returncode != 0:
                _LOGGER.warning("Python scan failed: %s", stderr.decode(errors="replace")[:2000])
                raise RuntimeError("Python scan failed.")
            return json.loads(stdout.decode())


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
        except RepositoryUrlError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except CloneLimitError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(status_code=504, detail=str(exc)) from exc
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            _LOGGER.exception("API repository scan failed.")
            raise HTTPException(status_code=502, detail="Repository scan failed.") from exc

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ProtoSec scanner")
    parser.add_argument("--version", action="version", version="ProtoSec v1.0.0")
    parser.add_argument("repo_path", nargs="?", default=".")
    server_options = parser.add_mutually_exclusive_group()
    server_options.add_argument(
        "--serve", action="store_true", help="Run the FastAPI app if FastAPI is installed"
    )
    server_options.add_argument(
        "--mcp", action="store_true", help="Run the local MCP server over stdio"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Run a full scan without reading or updating the incremental cache",
    )
    args = parser.parse_args(argv)

    if args.mcp:
        if args.no_cache:
            parser.error("--no-cache applies only to direct project scans.")
        from src.mcp_server import main as run_mcp_server

        run_mcp_server()
        return 0

    if args.serve:
        if args.no_cache:
            parser.error("--no-cache applies only to direct project scans.")
        app = create_app()
        if app is None:
            print("FastAPI is not installed; cannot start the API server.", file=sys.stderr)
            return 1
        import uvicorn

        uvicorn.run(app, host="127.0.0.1", port=8000)
        return 0

    if args.no_cache:
        from utils.incremental_scan import scan_full_project

        report = scan_full_project(args.repo_path)
    else:
        from utils.incremental_scan import scan_incremental_project

        report = scan_incremental_project(args.repo_path)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())