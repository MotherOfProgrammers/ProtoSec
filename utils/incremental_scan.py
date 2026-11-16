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
import warnings
from contextlib import closing
from pathlib import Path

from src.main import PROJECT_ROOT, SCANNER_SOURCE_FILES, scanner_binary_path
from src.scanner_rules import ALLOWED_EXTENSIONS, SKIP_DIRS, RULES, analyze_file
from utils.custom_rules import load_custom_rules, scan_custom_rules
from utils.cve_audit import merge_findings


_CPP_EXTRA_EXTENSIONS = {".cts", ".mts"}
_CPP_EXTRA_SKIP_DIRS = {"__tests__", "spec", "specs", "test", "tests"}
_STRUCTURAL_RULE_IDS = {
    "ENV-002", "SEC-007", "DB-004", "API-001", "API-003", "AUTH-001",
}
_FILE_CACHE_FINGERPRINT = "per-rule-v2"


def scan_cache_path() -> Path:
    configured_path = os.environ.get("PROTOSEC_CACHE_PATH")
    if configured_path:
        return Path(configured_path).expanduser()
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
    line_count = (
        0
        if size == 0 or (use_cpp and b"\0" in probe)
        else newlines + (last_byte != b"\n")
    )
    return digest.hexdigest(), line_count


def _add_callable_fingerprint(digest, function) -> None:
    try:
        source = inspect.getsource(function).encode("utf-8")
    except (OSError, TypeError):
        source = function.__code__.co_code + repr(function.__code__.co_consts).encode("utf-8")
    digest.update(source)
    digest.update(b"\0")


def _callables_fingerprint(*functions) -> str:
    digest = hashlib.sha256()
    for function in functions:
        _add_callable_fingerprint(digest, function)
    return digest.hexdigest()


def _native_rule_metadata(binary: Path) -> dict:
    process = subprocess.run(
        [str(binary), "--rule-metadata"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        shell=False,
        **_process_options(),
    )
    if process.returncode:
        raise RuntimeError(
            process.stderr.strip() or "Could not read native scanner rule metadata."
        )
    try:
        metadata = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("The native scanner returned invalid rule metadata.") from exc
    if (
        not isinstance(metadata, dict)
        or not isinstance(metadata.get("engine_version"), int)
        or not isinstance(metadata.get("rules"), list)
        or any(
            not isinstance(rule, dict) or not isinstance(rule.get("id"), str)
            for rule in metadata["rules"]
        )
    ):
        raise RuntimeError("The native scanner returned incomplete rule metadata.")
    return metadata


def _native_engine_fingerprint(engine_version: int) -> str:
    digest = hashlib.sha256(f"native-rule-engine:{engine_version}".encode("utf-8"))
    for path in (
        PROJECT_ROOT / "core" / "src" / "scanner.cpp",
        PROJECT_ROOT / "core" / "src" / "tree_sitter_comments.cpp",
        PROJECT_ROOT / "core" / "include" / "mmap_file.hpp",
        PROJECT_ROOT / "core" / "include" / "scanner.hpp",
        PROJECT_ROOT / "core" / "include" / "tree_sitter_comments.hpp",
    ):
        if path.is_file():
            digest.update(bytes.fromhex(_digest_file(path)))
    return digest.hexdigest()


def _python_engine_fingerprint() -> str:
    from src.scanner_rules import (
        calculate_entropy,
        redact_snippet,
        ENTROPY_ASSIGNMENT,
        FASTAPI_AUTH,
        FASTAPI_MUTATION,
        NEXT_AUTH,
        NEXT_MUTATION,
        PLACEHOLDER_VALUES,
        SQL_CREATE_TABLE,
    )

    digest = hashlib.sha256(b"python-rule-engine-v1")
    digest.update(
        bytes.fromhex(_callables_fingerprint(analyze_file, calculate_entropy, redact_snippet))
    )
    for pattern in (
        ENTROPY_ASSIGNMENT, FASTAPI_AUTH, FASTAPI_MUTATION, NEXT_AUTH,
        NEXT_MUTATION, SQL_CREATE_TABLE,
    ):
        digest.update(pattern.pattern.encode("utf-8"))
        digest.update(str(pattern.flags).encode("ascii"))
    digest.update(repr(PLACEHOLDER_VALUES).encode("utf-8"))
    return digest.hexdigest()


def _rule_material(rule) -> dict:
    return {
        "category": rule.category,
        "extensions": sorted(rule.extensions),
        "fix": rule.fix,
        "id": rule.rule_id,
        "pattern": rule.pattern.pattern,
        "pattern_flags": rule.pattern.flags,
        "severity": rule.severity,
        "title": rule.title,
    }


def _rule_fingerprints(
    root: Path,
    binary: Path | None,
    use_cpp: bool,
) -> dict[str, str]:
    engine = "cpp" if use_cpp else "python"
    if use_cpp and binary is not None:
        metadata = _native_rule_metadata(binary)
        engine_fingerprint = _native_engine_fingerprint(metadata["engine_version"])
        builtin_rules = {rule["id"]: rule for rule in metadata["rules"]}
    else:
        engine_fingerprint = _python_engine_fingerprint()
        builtin_rules = {rule.rule_id: _rule_material(rule) for rule in RULES}
    fingerprints = {}
    for rule_id in set(builtin_rules) | _STRUCTURAL_RULE_IDS:
        digest = hashlib.sha256(engine_fingerprint.encode("ascii"))
        digest.update(rule_id.encode("utf-8"))
        if rule_id in builtin_rules:
            digest.update(
                json.dumps(
                    builtin_rules[rule_id],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        if rule_id == "SEC-007":
            digest.update(
                json.dumps(
                    [
                        material
                        for current_id, material in builtin_rules.items()
                        if current_id.startswith("SEC-")
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        fingerprints[f"{engine}:{rule_id}"] = digest.hexdigest()

    custom_engine_fingerprint = _callables_fingerprint(load_custom_rules, scan_custom_rules)
    for rule in load_custom_rules(root):
        digest = hashlib.sha256(custom_engine_fingerprint.encode("ascii"))
        digest.update(
            json.dumps(
                {
                    "extensions": sorted(rule.extensions),
                    "id": rule.rule_id,
                    "pattern": rule.pattern.pattern,
                    "severity": rule.severity,
                    "title": rule.title,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        fingerprints[f"custom:{rule.rule_id}"] = digest.hexdigest()
    return fingerprints


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
    try:
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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS rule_cache (
                project_root TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                rule_key TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                rule_fingerprint TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                PRIMARY KEY (project_root, relative_path, rule_key)
            )
            """
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS cache_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        schema = connection.execute(
            "SELECT value FROM cache_meta WHERE key = 'schema_version'"
        ).fetchone()
        if schema is None:
            connection.execute(
                "INSERT INTO cache_meta (key, value) VALUES ('schema_version', '2')"
            )
        elif schema[0] == "1":
            connection.execute(
                "UPDATE cache_meta SET value = '2' WHERE key = 'schema_version'"
            )
        elif schema[0] != "2":
            raise RuntimeError(f"Unsupported scan cache schema version: {schema[0]}")
        connection.commit()
    except (sqlite3.DatabaseError, RuntimeError):
        connection.close()
        raise
    return connection


def _is_corrupt_database(error: sqlite3.DatabaseError) -> bool:
    message = str(error).lower()
    return "not a database" in message or "malformed" in message or "corrupt" in message


def _quarantine_corrupt_cache(path: Path) -> str:
    suffix = f".corrupt-{time.time_ns()}"
    quarantined_path = path.with_name(path.name + suffix)
    for ending in ("", "-wal", "-shm"):
        source = Path(f"{path}{ending}")
        if source.exists():
            destination = source.with_name(source.name + suffix)
            os.replace(source, destination)
    return str(quarantined_path)


def _load_entries(
    path: Path,
    project_root: str,
) -> tuple[
    dict[str, tuple[str, int]],
    dict[str, dict[str, tuple[str, str, list[dict]]]],
]:
    try:
        with closing(_open_cache(path)) as connection:
            file_entries = {
                relative_path: (file_hash, line_count)
                for relative_path, file_hash, line_count in connection.execute(
                    """
                    SELECT relative_path, file_hash, line_count
                    FROM file_cache
                    WHERE project_root = ? AND engine_fingerprint = ?
                    """,
                    (project_root, _FILE_CACHE_FINGERPRINT),
                )
            }
            rows = connection.execute(
                """
                SELECT relative_path, rule_key, file_hash, rule_fingerprint, findings_json
                FROM rule_cache
                WHERE project_root = ?
                """,
                (project_root,),
            )
            rule_entries: dict[str, dict[str, tuple[str, str, list[dict]]]] = {}
            for relative_path, rule_key, file_hash, fingerprint, findings_json in rows:
                try:
                    findings = json.loads(findings_json)
                    if not isinstance(findings, list) or not all(
                        isinstance(finding, dict) for finding in findings
                    ):
                        raise ValueError("Cached findings must be a list of objects.")
                except (json.JSONDecodeError, TypeError, ValueError):
                    warnings.warn(
                        f"Discarding invalid cached findings for {relative_path!r}; "
                        "the file will be rescanned.",
                        RuntimeWarning,
                        stacklevel=2,
                    )
                    continue
                rule_entries.setdefault(relative_path, {})[rule_key] = (
                    file_hash, fingerprint, findings
                )
            return file_entries, rule_entries
    except sqlite3.DatabaseError as exc:
        if not _is_corrupt_database(exc):
            raise
        quarantined_path = _quarantine_corrupt_cache(path)
        warnings.warn(
            f"Corrupt incremental cache was moved to {quarantined_path}; "
            "a fresh cache will be created.",
            RuntimeWarning,
            stacklevel=2,
        )
        return {}, {}


def _store_entries(
    path: Path,
    project_root: str,
    old_file_entries: dict[str, tuple[str, int]],
    current_paths: set[str],
    file_entries: dict[str, tuple[str, int]],
    active_rule_keys: set[str],
    updated_rule_entries: dict[
        tuple[str, str], tuple[str, str, list[dict]]
    ],
) -> None:
    with closing(_open_cache(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM file_cache WHERE project_root = ? AND engine_fingerprint != ?",
            (project_root, _FILE_CACHE_FINGERPRINT),
        )
        for relative_path in old_file_entries.keys() - current_paths:
            connection.execute(
                """
                DELETE FROM file_cache
                WHERE project_root = ? AND engine_fingerprint = ? AND relative_path = ?
                """,
                (project_root, _FILE_CACHE_FINGERPRINT, relative_path),
            )
        connection.executemany(
            """
            INSERT INTO file_cache
                (project_root, engine_fingerprint, relative_path, file_hash, line_count, findings_json)
            VALUES (?, ?, ?, ?, ?, '[]')
            ON CONFLICT(project_root, engine_fingerprint, relative_path) DO UPDATE SET
                file_hash = excluded.file_hash,
                line_count = excluded.line_count,
                findings_json = '[]'
            """,
            [
                (
                    project_root,
                    _FILE_CACHE_FINGERPRINT,
                    relative_path,
                    file_hash,
                    line_count,
                )
                for relative_path, (file_hash, line_count) in file_entries.items()
            ],
        )
        cached_rules = connection.execute(
            "SELECT relative_path, rule_key FROM rule_cache WHERE project_root = ?",
            (project_root,),
        ).fetchall()
        for relative_path, rule_key in cached_rules:
            if relative_path not in current_paths or rule_key not in active_rule_keys:
                connection.execute(
                    """
                    DELETE FROM rule_cache
                    WHERE project_root = ? AND relative_path = ? AND rule_key = ?
                    """,
                    (project_root, relative_path, rule_key),
                )
        connection.executemany(
            """
            INSERT INTO rule_cache
                (project_root, relative_path, rule_key, file_hash, rule_fingerprint, findings_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_root, relative_path, rule_key) DO UPDATE SET
                file_hash = excluded.file_hash,
                rule_fingerprint = excluded.rule_fingerprint,
                findings_json = excluded.findings_json
            """,
            [
                (
                    project_root,
                    relative_path,
                    rule_key,
                    file_hash,
                    fingerprint,
                    json.dumps(findings, separators=(",", ":"), ensure_ascii=False),
                )
                for (relative_path, rule_key), (
                    file_hash, fingerprint, findings
                ) in updated_rule_entries.items()
            ],
        )
        connection.commit()


def _scan_cpp_files(
    root: Path,
    binary: Path,
    relative_paths: list[str],
    progress_callback=None,
    rule_ids: list[str] | None = None,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="protosec-files-") as temporary_directory:
        list_path = Path(temporary_directory) / "changed-files.bin"
        list_path.write_bytes(
            b"".join(path.encode("utf-8") + b"\0" for path in relative_paths)
        )
        process_options = _process_options()
        command = [str(binary), "--files-from", str(root), str(list_path)]
        if rule_ids is not None:
            command.extend(["--only-rules", ",".join(rule_ids)])
        process = subprocess.Popen(
            command,
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
    rule_ids: set[str] | None = None,
) -> dict[str, tuple[int, list[dict]]]:
    results = {}
    for index, (relative_path, path) in enumerate(files, start=1):
        findings, line_count = analyze_file(path, root, rule_ids)
        results[relative_path] = (line_count, findings)
        if progress_callback:
            progress_callback("scanning", index, len(files), relative_path)
    return results


def _report(findings: list[dict], files_scanned: int, lines_scanned: int, elapsed_ms: float) -> dict:
    findings.sort(key=lambda finding: (
        finding.get("file_path", ""),
        finding.get("line_number", 0),
        finding.get("rule_id", ""),
    ))
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
    rule_fingerprints = _rule_fingerprints(root, binary if use_cpp else None, use_cpp)
    project_key = os.path.normcase(str(root))
    cache_file = Path(cache_path) if cache_path is not None else scan_cache_path()
    files = _discover_files(root, use_cpp)
    file_hashes = {}
    for index, (relative_path, path) in enumerate(files, start=1):
        file_hashes[relative_path] = _digest_and_line_count(path, use_cpp)
        if progress_callback:
            progress_callback("hashing", index, len(files), relative_path)

    old_file_entries, old_rule_entries = _load_entries(cache_file, project_key)
    changed_paths = {
        relative_path
        for relative_path, _ in files
        if relative_path not in old_file_entries
        or old_file_entries[relative_path][0] != file_hashes[relative_path][0]
    }
    deleted_paths = old_file_entries.keys() - file_hashes.keys()
    pending_rule_keys: dict[str, set[str]] = {}
    line_counts = {}
    for relative_path, _ in files:
        content_hash, discovered_line_count = file_hashes[relative_path]
        old_file_entry = old_file_entries.get(relative_path)
        line_counts[relative_path] = (
            old_file_entry[1]
            if old_file_entry is not None and old_file_entry[0] == content_hash
            else discovered_line_count
        )
        old_rules = old_rule_entries.get(relative_path, {})
        pending = {
            rule_key
            for rule_key, fingerprint in rule_fingerprints.items()
            if relative_path in changed_paths
            or rule_key not in old_rules
            or old_rules[rule_key][0] != content_hash
            or old_rules[rule_key][1] != fingerprint
        }
        if pending:
            pending_rule_keys[relative_path] = pending

    updated_rule_entries: dict[
        tuple[str, str], tuple[str, str, list[dict]]
    ] = {}
    builtin_prefix = "cpp:" if use_cpp else "python:"
    builtin_groups: dict[tuple[str, ...], list[str]] = {}
    custom_groups: dict[tuple[str, ...], list[str]] = {}
    for relative_path, pending in pending_rule_keys.items():
        builtin_ids = tuple(sorted(
            rule_key[len(builtin_prefix):]
            for rule_key in pending
            if rule_key.startswith(builtin_prefix)
        ))
        if builtin_ids:
            builtin_groups.setdefault(builtin_ids, []).append(relative_path)
        custom_ids = tuple(sorted(
            rule_key[len("custom:"):]
            for rule_key in pending
            if rule_key.startswith("custom:")
        ))
        if custom_ids:
            custom_groups.setdefault(custom_ids, []).append(relative_path)

    for rule_ids, relative_paths in builtin_groups.items():
        if use_cpp:
            report = _scan_cpp_files(
                root,
                binary,
                relative_paths,
                progress_callback,
                rule_ids=list(rule_ids),
            )
            findings_by_file: dict[str, dict[str, list[dict]]] = {
                path: {rule_id: [] for rule_id in rule_ids}
                for path in relative_paths
            }
            for finding in report.get("findings", []):
                relative_path = str(finding.get("file_path", "")).replace("\\", "/")
                rule_id = finding.get("rule_id")
                if relative_path in findings_by_file and rule_id in findings_by_file[relative_path]:
                    findings_by_file[relative_path][rule_id].append(finding)
            for relative_path in relative_paths:
                for rule_id in rule_ids:
                    rule_key = f"{builtin_prefix}{rule_id}"
                    updated_rule_entries[(relative_path, rule_key)] = (
                        file_hashes[relative_path][0],
                        rule_fingerprints[rule_key],
                        findings_by_file[relative_path][rule_id],
                    )
        else:
            selected = set(rule_ids)
            scanned = _scan_python_files(
                root,
                [(path, root / Path(path)) for path in relative_paths],
                progress_callback,
                selected,
            )
            for relative_path, (line_count, findings) in scanned.items():
                line_counts[relative_path] = line_count
                findings_by_rule = {rule_id: [] for rule_id in rule_ids}
                for finding in findings:
                    findings_by_rule[finding["rule_id"]].append(finding)
                for rule_id in rule_ids:
                    rule_key = f"{builtin_prefix}{rule_id}"
                    updated_rule_entries[(relative_path, rule_key)] = (
                        file_hashes[relative_path][0],
                        rule_fingerprints[rule_key],
                        findings_by_rule[rule_id],
                    )

    for rule_ids, relative_paths in custom_groups.items():
        findings_by_file: dict[str, dict[str, list[dict]]] = {
            path: {rule_id: [] for rule_id in rule_ids}
            for path in relative_paths
        }
        for finding in scan_custom_rules(
            root,
            [root / Path(path) for path in relative_paths],
            set(rule_ids),
        ):
            findings_by_file[finding["file_path"]][finding["rule_id"]].append(finding)
        for relative_path in relative_paths:
            for rule_id in rule_ids:
                rule_key = f"custom:{rule_id}"
                updated_rule_entries[(relative_path, rule_key)] = (
                    file_hashes[relative_path][0],
                    rule_fingerprints[rule_key],
                    findings_by_file[relative_path][rule_id],
                )

    scanned_paths = set(pending_rule_keys)
    for relative_path, path in files:
        if relative_path in scanned_paths and _digest_file(path) != file_hashes[relative_path][0]:
            raise RuntimeError(
                f"File changed during scan; rerun to avoid stale results: {relative_path}"
            )
    if set(path for path, _ in _discover_files(root, use_cpp)) != set(file_hashes):
        raise RuntimeError("Project files changed during scan; rerun for a consistent result.")

    current_file_entries = {
        relative_path: (file_hashes[relative_path][0], line_counts[relative_path])
        for relative_path, _ in files
    }
    active_rule_keys = set(rule_fingerprints)
    _store_entries(
        cache_file,
        project_key,
        old_file_entries,
        set(file_hashes),
        current_file_entries,
        active_rule_keys,
        updated_rule_entries,
    )

    current_rule_entries = {
        relative_path: dict(old_rule_entries.get(relative_path, {}))
        for relative_path, _ in files
    }
    for (relative_path, rule_key), value in updated_rule_entries.items():
        current_rule_entries[relative_path][rule_key] = value
    findings = []
    for relative_path, _ in files:
        for rule_key, fingerprint in rule_fingerprints.items():
            cached = current_rule_entries[relative_path].get(rule_key)
            if (
                cached is None
                or cached[0] != file_hashes[relative_path][0]
                or cached[1] != fingerprint
            ):
                raise RuntimeError(
                    f"Missing or stale cached rule result for {relative_path}: {rule_key}"
                )
            findings.extend(cached[2])

    report = _report(
        findings,
        len(files),
        sum(line_counts.values()),
        (time.perf_counter() - started) * 1000,
    )
    total_rule_results = len(files) * len(rule_fingerprints)
    report["incremental"] = {
        "files_changed": len(changed_paths),
        "files_cached": len(files) - len(changed_paths),
        "files_removed": len(deleted_paths),
        "rule_results_scanned": len(updated_rule_entries),
        "rule_results_cached": total_rule_results - len(updated_rule_entries),
        "rule_cache_hit_rate": (
            round((total_rule_results - len(updated_rule_entries)) / total_rule_results, 4)
            if total_rule_results
            else 0.0
        ),
    }
    return report
