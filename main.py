import argparse
import asyncio
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from pydantic import BaseModel, ConfigDict
except ImportError:  # pragma: no cover - fallback for older Pydantic
    class ConfigDict(dict):
        pass

    class BaseModel:
        model_config = ConfigDict(extra="allow")

        def __init__(self, **data):
            self.__dict__.update(data)

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "target",
    ".idea",
    ".pytest_cache",
    ".mypy_cache",
    "coverage",
    "vendor",
}

SECRET_REGEX = re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}")
PUBLIC_SECRET_PREFIX = re.compile(r"(NEXT_PUBLIC_|VITE_).*(SECRET|SERVICE_ROLE|PRIVATE_KEY)", re.IGNORECASE)
OPEN_FIREBASE_REGEX = re.compile(r"allow\s+read,\s*write:\s*if\s+true", re.IGNORECASE)


def _json_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _make_finding(rule_id: str, severity: str, title: str, file_path: str, line_number: int, snippet: str, fix_prompt: str) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "file_path": file_path,
        "line_number": line_number,
        "snippet": snippet,
        "fix_prompt": fix_prompt,
    }


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def analyze_file(file_path: Path, root_path: Path) -> list[dict]:
    findings: list[dict] = []
    try:
        rel_path = file_path.relative_to(root_path).as_posix()
    except ValueError:
        rel_path = file_path.name

    if not file_path.is_file():
        return findings

    try:
        with file_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                match = SECRET_REGEX.search(line)
                if match:
                    findings.append(
                        _make_finding(
                            "SEC-001",
                            "CRITICAL",
                            "Hardcoded API Key Detected",
                            rel_path,
                            line_number,
                            line.strip()[:80],
                            (
                                f"Remove the hardcoded secret from {rel_path} at line {line_number}, "
                                "load it via environment variables, and rotate the key immediately."
                            ),
                        )
                    )

                if PUBLIC_SECRET_PREFIX.search(line):
                    findings.append(
                        _make_finding(
                            "ENV-001",
                            "CRITICAL",
                            "Secret Exposed via Client Prefix",
                            rel_path,
                            line_number,
                            line.strip()[:80],
                            (
                                f"Move sensitive logic out of public client bundle in {rel_path} around line {line_number}."
                            ),
                        )
                    )

                if file_path.suffix.lower() == ".rules" and OPEN_FIREBASE_REGEX.search(line):
                    findings.append(
                        _make_finding(
                            "DB-002",
                            "CRITICAL",
                            "Open Firebase Security Rules",
                            rel_path,
                            line_number,
                            line.strip()[:80],
                            (
                                f"Replace 'allow read, write: if true' in {rel_path} with strict authentication checks."
                            ),
                        )
                    )
    except (OSError, UnicodeDecodeError):
        return findings

    return findings


def scan_repository(root_path: Path | str) -> dict:
    root = Path(root_path)
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root}")

    findings: list[dict] = []
    for candidate in sorted(root.rglob("*")):
        if candidate.name in {"main.py", "main.cpp", "scanner_core"}:
            continue
        if candidate.is_dir() and should_skip(candidate):
            continue
        if not candidate.is_file():
            continue
        if should_skip(candidate):
            continue

        suffix = candidate.suffix.lower()
        if suffix in {".ts", ".tsx", ".js", ".py", ".sql", ".rules"} or candidate.name == ".env":
            findings.extend(analyze_file(candidate, root))

    total_penalty = 0
    for finding in findings:
        severity = finding["severity"]
        if severity == "CRITICAL":
            total_penalty += 30
        elif severity == "HIGH":
            total_penalty += 15
        else:
            total_penalty += 5

    report = {
        "total_issues": len(findings),
        "findings": findings,
        "security_score": max(0, 100 - total_penalty),
    }
    return report


async def run_cpp_scanner(repo_path: str) -> dict:
    process = await asyncio.create_subprocess_exec(
        "./scanner_core",
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

        if Path("./scanner_core").exists():
            return await run_cpp_scanner(tmpdir)
        return scan_repository(tmpdir)


def create_app():
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError:  # pragma: no cover
        return None

    app = FastAPI(title="Vibe-Code Security Scanner API")

    @app.post("/api/scan")
    async def trigger_scan_api(payload: ScanRequest):
        try:
            return await trigger_scan(payload)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ProtoSec scanner")
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