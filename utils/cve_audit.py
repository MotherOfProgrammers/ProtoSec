import json
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version


OSV_ARCHIVES = {
    "npm": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    "PyPI": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
}
SKIP_DIRS = {
    ".git", ".next", ".venv", "__pycache__", "build", "dist", "node_modules",
    "target", "vendor", "venv",
}


def database_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "ProtoSec" / "osv.sqlite3"


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE advisories (
            ecosystem TEXT NOT NULL,
            package TEXT NOT NULL,
            advisory_id TEXT NOT NULL,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL,
            affected_json TEXT NOT NULL,
            PRIMARY KEY (ecosystem, package, advisory_id, affected_json)
        )
        """
    )
    connection.execute(
        "CREATE INDEX advisories_package ON advisories(ecosystem, package)"
    )
    connection.execute(
        "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )


def update_database(progress_callback=None, destination: Path | None = None) -> tuple[Path, int]:
    destination = destination or database_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="protosec-osv-", dir=destination.parent) as work_dir:
        work = Path(work_dir)
        staged_database = work / "osv.sqlite3"
        connection = sqlite3.connect(staged_database)
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            _create_schema(connection)
            inserted = 0
            for ecosystem, url in OSV_ARCHIVES.items():
                archive_path = work / f"{ecosystem}.zip"
                if progress_callback:
                    progress_callback("downloading", 0, 0, ecosystem)
                request = Request(url, headers={"User-Agent": "ProtoSec/1.0.0"})
                with urlopen(request, timeout=60) as response, archive_path.open("wb") as output:
                    total_bytes = int(response.headers.get("Content-Length", "0") or 0)
                    downloaded = 0
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback and total_bytes:
                            progress_callback("downloading", downloaded, total_bytes, ecosystem)

                with zipfile.ZipFile(archive_path) as archive:
                    json_files = [
                        info for info in archive.infolist()
                        if info.filename.lower().endswith(".json")
                    ]
                    for index, info in enumerate(json_files, start=1):
                        if info.file_size > 16 * 1024 * 1024:
                            raise ValueError(f"OSV entry is unexpectedly large: {info.filename}")
                        with archive.open(info) as entry:
                            advisory = json.load(entry)
                        advisory_id = str(advisory.get("id", ""))
                        summary = str(advisory.get("summary", "") or advisory.get("details", ""))
                        severity = _advisory_severity(advisory)
                        for affected in advisory.get("affected", []):
                            package = affected.get("package", {})
                            if package.get("ecosystem") != ecosystem or not package.get("name"):
                                continue
                            connection.execute(
                                """
                                INSERT OR IGNORE INTO advisories
                                (ecosystem, package, advisory_id, summary, severity, affected_json)
                                VALUES (?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    ecosystem,
                                    _normalize_package(ecosystem, package["name"]),
                                    advisory_id,
                                    summary[:2000],
                                    severity,
                                    json.dumps(affected, separators=(",", ":")),
                                ),
                            )
                            inserted += connection.execute("SELECT changes()").fetchone()[0]
                        if index % 500 == 0:
                            connection.commit()
                        if progress_callback:
                            progress_callback("indexing", index, len(json_files), ecosystem)
                archive_path.unlink()
            connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES ('format_version', '1')"
            )
            connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES ('updated_at', datetime('now'))"
            )
            connection.commit()
        finally:
            connection.close()
        os.replace(staged_database, destination)
    return destination, inserted


def _advisory_severity(advisory: dict) -> str:
    database_severity = str(
        advisory.get("database_specific", {}).get("severity", "")
    ).upper()
    if database_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return database_severity
    return "HIGH"


def _normalize_package(ecosystem: str, package: str) -> str:
    normalized = package.lower()
    return re.sub(r"[-_.]+", "-", normalized) if ecosystem == "PyPI" else normalized


def _parse_semver(value: str):
    match = re.fullmatch(
        r"\s*[v=]?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
        r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*",
        value,
    )
    if not match:
        raise ValueError(f"Invalid semantic version: {value}")
    major, minor, patch = (int(part or 0) for part in match.group(1, 2, 3))
    prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
    return major, minor, patch, prerelease


def _compare_versions(ecosystem: str, left: str, right: str) -> int:
    if ecosystem == "npm":
        left_version = _parse_semver(left)
        right_version = _parse_semver(right)
        if left_version[:3] != right_version[:3]:
            return (left_version[:3] > right_version[:3]) - (left_version[:3] < right_version[:3])
        left_pre, right_pre = left_version[3], right_version[3]
        if not left_pre or not right_pre:
            return (bool(left_pre) < bool(right_pre)) - (bool(left_pre) > bool(right_pre))
        for left_part, right_part in zip(left_pre, right_pre):
            if left_part == right_part:
                continue
            left_num, right_num = left_part.isdigit(), right_part.isdigit()
            if left_num and right_num:
                return (int(left_part) > int(right_part)) - (int(left_part) < int(right_part))
            if left_num != right_num:
                return -1 if left_num else 1
            return (left_part > right_part) - (left_part < right_part)
        return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))
    left_version = Version(left)
    right_version = Version(right)
    return (left_version > right_version) - (left_version < right_version)


def _range_matches(ecosystem: str, version: str, version_range: dict) -> bool:
    if version_range.get("type") not in {"SEMVER", "ECOSYSTEM"}:
        return False
    affected = False
    try:
        for event in version_range.get("events", []):
            if "introduced" in event:
                affected = _compare_versions(ecosystem, version, event["introduced"]) >= 0
            elif "fixed" in event:
                if _compare_versions(ecosystem, version, event["fixed"]) >= 0:
                    affected = False
            elif "last_affected" in event:
                affected = _compare_versions(ecosystem, version, event["last_affected"]) <= 0
            elif "limit" in event:
                if _compare_versions(ecosystem, version, event["limit"]) >= 0:
                    affected = False
    except (InvalidVersion, ValueError):
        return False
    return affected


def _is_affected(ecosystem: str, version: str, affected: dict) -> bool:
    versions = affected.get("versions", [])
    for known_version in versions:
        try:
            if _compare_versions(ecosystem, version, known_version) == 0:
                return True
        except (InvalidVersion, ValueError):
            continue
    return any(
        _range_matches(ecosystem, version, version_range)
        for version_range in affected.get("ranges", [])
    )


def _fixed_versions(ecosystem: str, affected: dict) -> list[str]:
    fixed = []
    for version_range in affected.get("ranges", []):
        if version_range.get("type") not in {"SEMVER", "ECOSYSTEM"}:
            continue
        fixed.extend(
            event["fixed"]
            for event in version_range.get("events", [])
            if event.get("fixed")
        )
    valid = []
    for version in set(fixed):
        try:
            _compare_versions(ecosystem, version, version)
            valid.append(version)
        except (InvalidVersion, ValueError):
            continue
    return sorted(
        valid,
        key=lambda item: Version(item) if ecosystem == "PyPI" else _parse_semver(item),
    )


def _dependency_manifests(root: Path):
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        if "package-lock.json" in filenames:
            yield Path(current_root) / "package-lock.json"
        for filename in filenames:
            if re.fullmatch(r"requirements(?:[-_.][A-Za-z0-9_-]+)?\.txt", filename, re.IGNORECASE):
                yield Path(current_root) / filename


def _npm_dependencies(manifest: Path) -> list[tuple[str, str]]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    dependencies = []
    for path, package in data.get("packages", {}).items():
        if not path or "node_modules/" not in path:
            continue
        package_name = package.get("name")
        if not package_name:
            package_name = path.rsplit("node_modules/", 1)[-1]
        version = package.get("version")
        if package_name and version:
            dependencies.append((package_name, str(version)))

    def collect_legacy(items):
        for name, package in items.items():
            if package.get("version"):
                dependencies.append((name, str(package["version"])))
            collect_legacy(package.get("dependencies", {}))

    if not data.get("packages"):
        collect_legacy(data.get("dependencies", {}))
    return dependencies


def _pypi_dependencies(manifest: Path) -> list[tuple[str, str]]:
    dependencies = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.match(
            r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*===?\s*([A-Za-z0-9.+!_-]+)\s*(?:;.*)?$",
            line,
        )
        if match:
            dependencies.append((match.group(1), match.group(2)))
    return dependencies


def scan_dependencies(root_path: str | Path, db_path: str | Path | None = None) -> list[dict]:
    root = Path(root_path).resolve()
    database = Path(db_path) if db_path else database_path()
    if not database.is_file():
        raise FileNotFoundError(
            "The offline OSV database is not installed. Use Tools > Update CVE database, then retry."
        )

    manifests = list(_dependency_manifests(root))
    connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
    findings = []
    seen = set()
    try:
        for manifest in manifests:
            ecosystem = "npm" if manifest.name == "package-lock.json" else "PyPI"
            dependencies = (
                _npm_dependencies(manifest) if ecosystem == "npm"
                else _pypi_dependencies(manifest)
            )
            for package, version in dependencies:
                rows = connection.execute(
                    """
                    SELECT advisory_id, summary, severity, affected_json
                    FROM advisories WHERE ecosystem = ? AND package = ?
                    """,
                    (ecosystem, _normalize_package(ecosystem, package)),
                )
                relative_path = manifest.relative_to(root).as_posix()
                for advisory_id, summary, severity, affected_json in rows:
                    affected = json.loads(affected_json)
                    if not _is_affected(ecosystem, version, affected):
                        continue
                    key = (relative_path, package, version, advisory_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    fixed = _fixed_versions(ecosystem, affected)
                    recommendation = (
                        f"Upgrade to {fixed[0]} or later."
                        if fixed else "Review the advisory for a patched release."
                    )
                    findings.append({
                        "rule_id": advisory_id,
                        "category": "Dependency CVE",
                        "severity": severity,
                        "title": f"Vulnerable dependency: {package}@{version}",
                        "file_path": relative_path,
                        "line_number": 1,
                        "snippet": f"{advisory_id}: {summary[:200]}",
                        "fix_prompt": (
                            f"Update {package} from {version}. {recommendation} "
                            f"Source: OSV advisory {advisory_id}."
                        ),
                    })
    finally:
        connection.close()
    return findings


def merge_findings(report: dict, extra_findings: list[dict]) -> dict:
    findings = list(report.get("findings", [])) + extra_findings
    summary = {
        severity.lower(): sum(item.get("severity") == severity for item in findings)
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }
    summary["total"] = len(findings)
    penalty = sum(
        {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2}.get(
            item.get("severity", "LOW"), 2
        )
        for item in findings
    )
    report["findings"] = findings
    report["summary"] = summary
    report["total_issues"] = len(findings)
    report["security_score"] = max(0, 100 - penalty)
    return report
