from __future__ import annotations

import hashlib
import inspect
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path

from src.main import PROJECT_ROOT, SCANNER_SOURCE_FILES, scanner_binary_path
from src.scanner_rules import ALLOWED_EXTENSIONS, SKIP_DIRS, RULES, analyze_file
from utils.custom_rules import load_custom_rules, scan_custom_rules
from utils.cve_audit import merge_findings


_CPP_EXTRA_EXTENSIONS = {".cts", ".mts"}
_CPP_EXTRA_SKIP_DIRS = {"__tests__", "spec", "specs", "test", "tests"}
_FINGERPRINT_SOURCE_FILES = (
    PROJECT_ROOT / "src" / "scanner_rules.py",
    PROJECT_ROOT / "src" / "main.py",
    PROJECT_ROOT / "utils" / "custom_rules.py",
    PROJECT_ROOT / "utils" / "incremental_scan.py",
    PROJECT_ROOT / "core" / "include" / "rules.hpp",
    PROJECT_ROOT / "core" / "include" / "scanner.hpp",
    PROJECT_ROOT / "core" / "include" / "tree_sitter_comments.hpp",
    PROJECT_ROOT / "core" / "src" / "scanner.cpp",
    PROJECT_ROOT / "core" / "src" / "tree_sitter_comments.cpp",
)


def scan_cache_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "ProtoSec" / "scan-cache.sqlite3"


def _process_options() -> dict:
    if sys.platform != "win32":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo": startupinfo,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_and_line_count(path: Path, use_cpp: bool) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    newlines = 0
    last_byte = b""
    probe = bytearray()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            if len(probe) < 512:
                probe.extend(chunk[:512 - len(probe)])
            size += len(chunk)
            newlines += chunk.count(b"\n")
            last_byte = chunk[-1:]
    if not use_cpp:
        return digest.hexdigest(), 0
    line_count = 0 if b"\0" in probe or size == 0 else newlines + (last_byte != b"\n")
    return digest.hexdigest(), line_count


def _add_callable_fingerprint(digest, function) -> None:
    try:
        source = inspect.getsource(function).encode("utf-8")
    except (OSError, TypeError):
        source = function.__code__.co_code + repr(function.__code__.co_consts).encode("utf-8")
    digest.update(source)
    digest.update(b"\0")


def _fingerprint(root: Path, binary: Path | None) -> str:
    digest = hashlib.sha256()
    digest.update(b"ProtoSec-incremental-v1\0")
    for path in _FINGERPRINT_SOURCE_FILES:
        digest.update(str(path.name).encode("utf-8", errors="replace"))
        digest.update(b"\0")
        if path.is_file():
            digest.update(bytes.fromhex(_digest_file(path)))
        else:
            digest.update(b"not-on-disk")
        digest.update(b"\0")
    digest.update(repr(RULES).encode("utf-8", errors="replace"))
    _add_callable_fingerprint(digest, analyze_file)
    _add_callable_fingerprint(digest, load_custom_rules)
    _add_callable_fingerprint(digest, scan_custom_rules)
    if binary is not None:
        digest.update(bytes.fromhex(_digest_file(binary)))
    config = root / ".vibeguard.toml"
    if config.is_file():
        digest.update(config.read_bytes())
    return digest.hexdigest()


def _discover_files(root: Path, use_cpp: bool) -> list[tuple[str, Path]]:
    allowed_extensions = ALLOWED_EXTENSIONS | (_CPP_EXTRA_EXTENSIONS if use_cpp else set())
    skipped_directories = SKIP_DIRS | (_CPP_EXTRA_SKIP_DIRS if use_cpp else set())
    discovered = []

    def raise_walk_error(error):
        raise error

    for current_root, dirs, filenames in os.walk(root, onerror=raise_walk_error):
        current = Path(current_root)
        dirs[:] = sorted(
            name for name in dirs
            if name.lower() not in skipped_directories
            and not (current / name).is_symlink()
        )
        for filename in filenames:
            candidate = current / filename
            if candidate.is_symlink():
                continue
            if candidate.name == ".vibeguard.toml":
                continue
            if candidate.resolve() in SCANNER_SOURCE_FILES:
                continue
            if candidate.suffix.lower() not in allowed_extensions and not filename.lower().startswith(".env"):
                continue
            discovered.append((candidate.relative_to(root).as_posix(), candidate))
    return sorted(discovered, key=lambda item: item[0])


def _open_cache(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS file_cache (
            project_root TEXT NOT NULL,
            engine_fingerprint TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            line_count INTEGER NOT NULL,
            findings_json TEXT NOT NULL,
            PRIMARY KEY (project_root, engine_fingerprint, relative_path)
        )
        """
    )
    return connection


def _load_entries(
    path: Path,
    project_root: str,
    engine_fingerprint: str,
) -> dict[str, tuple[str, int, list[dict]]]:
    with closing(_open_cache(path)) as connection:
        rows = connection.execute(
            """
            SELECT relative_path, file_hash, line_count, findings_json
            FROM file_cache
            WHERE project_root = ? AND engine_fingerprint = ?
            """,
            (project_root, engine_fingerprint),
        )
        return {
            relative_path: (file_hash, line_count, json.loads(findings_json))
            for relative_path, file_hash, line_count, findings_json in rows
        }


def _store_entries(
    path: Path,
    project_root: str,
    engine_fingerprint: str,
    old_entries: dict[str, tuple[str, int, list[dict]]],
    current_paths: set[str],
    updated_entries: dict[str, tuple[str, int, list[dict]]],
) -> None:
    with closing(_open_cache(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM file_cache WHERE project_root = ? AND engine_fingerprint != ?",
            (project_root, engine_fingerprint),
        )
        for relative_path in old_entries.keys() - current_paths:
            connection.execute(
                """
                DELETE FROM file_cache
                WHERE project_root = ? AND engine_fingerprint = ? AND relative_path = ?
                """,
                (project_root, engine_fingerprint, relative_path),
            )
        connection.executemany(
            """
            INSERT INTO file_cache
                (project_root, engine_fingerprint, relative_path, file_hash, line_count, findings_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_root, engine_fingerprint, relative_path) DO UPDATE SET
                file_hash = excluded.file_hash,
                line_count = excluded.line_count,
                findings_json = excluded.findings_json
            """,
            [
                (
                    project_root,
                    engine_fingerprint,
                    relative_path,
                    file_hash,
                    line_count,
                    json.dumps(findings, separators=(",", ":"), ensure_ascii=False),
                )
                for relative_path, (file_hash, line_count, findings) in updated_entries.items()
            ],
        )
        connection.commit()


def _scan_cpp_files(
    root: Path,
    binary: Path,
    relative_paths: list[str],
    progress_callback=None,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="protosec-files-") as temporary_directory:
        list_path = Path(temporary_directory) / "changed-files.bin"
        list_path.write_bytes(
            b"".join(path.encode("utf-8") + b"\0" for path in relative_paths)
        )
        process_options = _process_options()
        process = subprocess.Popen(
            [str(binary), "--files-from", str(root), str(list_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            **process_options,
        )
        output = []
        errors = []

        def drain_stdout():
            if process.stdout is not None:
                output.append(process.stdout.read())

        def drain_stderr():
            if process.stderr is None:
                return
            for line in process.stderr:
                parts = line.rstrip("\r\n").split("\t", 3)
                if len(parts) == 4 and parts[0] == "PROGRESS" and progress_callback:
                    try:
                        progress_callback("scanning", int(parts[1]), int(parts[2]), parts[3])
                    except ValueError:
                        continue
                elif line.strip():
                    errors.append(line.strip())

        stdout_thread = threading.Thread(target=drain_stdout, daemon=True)
        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        try:
            return_code = process.wait(timeout=180)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            stdout_thread.join()
            stderr_thread.join()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            raise TimeoutError("The incremental C++ scan exceeded its 180-second limit.") from exc
        stdout_thread.join()
        stderr_thread.join()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        if return_code:
            raise RuntimeError("\n".join(errors) or "The incremental C++ scanner failed.")
        return json.loads("".join(output))


def _scan_python_files(
    root: Path,
    files: list[tuple[str, Path]],
    progress_callback=None,
) -> tuple[dict[str, tuple[int, list[dict]]], list[dict]]:
    results = {}
    for index, (relative_path, path) in enumerate(files, start=1):
        findings, line_count = analyze_file(path, root)
        results[relative_path] = (line_count, findings)
        if progress_callback:
            progress_callback("scanning", index, len(files), relative_path)
    return results


def _report(findings: list[dict], files_scanned: int, lines_scanned: int, elapsed_ms: float) -> dict:
    report = {
        "files_scanned": files_scanned,
        "lines_scanned": lines_scanned,
        "elapsed_ms": round(elapsed_ms, 2),
    }
    return merge_findings(report, findings)


def scan_full_project(root_path: str | Path, progress_callback=None) -> dict:
    root = Path(root_path).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {root}")
    started = time.perf_counter()
    binary = scanner_binary_path()
    use_cpp = binary.is_file()
    files = _discover_files(root, use_cpp)
    if use_cpp and files:
        scanned = _scan_cpp_files(
            root, binary, [relative_path for relative_path, _ in files], progress_callback
        )
        findings = scanned.get("findings", [])
        lines_scanned = scanned.get("lines_scanned", 0)
    elif files:
        results = _scan_python_files(root, files, progress_callback)
        findings = [
            finding
            for line_count, file_findings in results.values()
            for finding in file_findings
        ]
        lines_scanned = sum(line_count for line_count, _ in results.values())
    else:
        findings = []
        lines_scanned = 0
    findings.extend(scan_custom_rules(root, [path for _, path in files]))
    return _report(
        findings,
        len(files),
        lines_scanned,
        (time.perf_counter() - started) * 1000,
    )


def scan_incremental_project(
    root_path: str | Path,
    progress_callback=None,
    cache_path: str | Path | None = None,
) -> dict:
    root = Path(root_path).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {root}")
    started = time.perf_counter()
    binary = scanner_binary_path()
    use_cpp = binary.is_file()
    engine_fingerprint = _fingerprint(root, binary if use_cpp else None)
    project_key = os.path.normcase(str(root))
    cache_file = Path(cache_path) if cache_path is not None else scan_cache_path()
    files = _discover_files(root, use_cpp)
    file_hashes = {}
    for index, (relative_path, path) in enumerate(files, start=1):
        file_hashes[relative_path] = _digest_and_line_count(path, use_cpp)
        if progress_callback:
            progress_callback("hashing", index, len(files), relative_path)

    old_entries = _load_entries(cache_file, project_key, engine_fingerprint)
    changed = [
        (relative_path, path)
        for relative_path, path in files
        if relative_path not in old_entries
        or old_entries[relative_path][0] != file_hashes[relative_path][0]
    ]
    changed_paths = [relative_path for relative_path, _ in changed]
    deleted_paths = old_entries.keys() - file_hashes.keys()
    changed_results: dict[str, tuple[int, list[dict]]] = {}
    if use_cpp and changed_paths:
        report = _scan_cpp_files(root, binary, changed_paths, progress_callback)
        findings_by_file: dict[str, list[dict]] = {path: [] for path in changed_paths}
        for finding in report.get("findings", []):
            relative_path = str(finding.get("file_path", "")).replace("\\", "/")
            findings_by_file.setdefault(relative_path, []).append(finding)
        changed_results = {
            relative_path: (file_hashes[relative_path][1], findings_by_file[relative_path])
            for relative_path in changed_paths
        }
    elif changed:
        changed_results = _scan_python_files(root, changed, progress_callback)
    custom_findings = scan_custom_rules(root, [path for _, path in changed])
    for finding in custom_findings:
        changed_results.setdefault(finding["file_path"], (0, []))[1].append(finding)

    for relative_path, path in changed:
        if _digest_file(path) != file_hashes[relative_path][0]:
            raise RuntimeError(
                f"File changed during scan; rerun to avoid stale results: {relative_path}"
            )
    if set(path for path, _ in _discover_files(root, use_cpp)) != set(file_hashes):
        raise RuntimeError("Project files changed during scan; rerun for a consistent result.")

    updated_entries = {
        relative_path: (
            file_hashes[relative_path][0],
            changed_results[relative_path][0],
            changed_results[relative_path][1],
        )
        for relative_path, _ in changed
    }
    _store_entries(
        cache_file,
        project_key,
        engine_fingerprint,
        old_entries,
        set(file_hashes),
        updated_entries,
    )

    current_entries = dict(old_entries)
    current_entries.update(updated_entries)
    for relative_path in deleted_paths:
        current_entries.pop(relative_path, None)
    findings = [
        finding
        for relative_path, *_ in files
        for finding in current_entries[relative_path][2]
    ]
    report = _report(
        findings,
        len(files),
        sum(current_entries[path][1] for path in file_hashes),
        (time.perf_counter() - started) * 1000,
    )
    report["incremental"] = {
        "files_changed": len(changed),
        "files_cached": len(files) - len(changed),
        "files_removed": len(deleted_paths),
    }
    return report
