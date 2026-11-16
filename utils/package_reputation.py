from __future__ import annotations

import difflib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from packaging.requirements import InvalidRequirement, Requirement


MAX_PACKAGES = 25
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
REGISTRY_TIMEOUT_SECONDS = 4
SKIP_DIRS = {
    ".git", ".next", ".venv", "__pycache__", "build", "dist", "node_modules",
    "target", "vendor", "venv",
}
POPULAR_PACKAGES = {
    "npm": (
        "axios", "chalk", "commander", "dotenv", "eslint", "express", "jest",
        "lodash", "next", "prettier", "react", "react-dom", "typescript",
        "vite", "webpack", "zod",
    ),
    "PyPI": (
        "boto3", "cryptography", "django", "fastapi", "flask", "numpy",
        "pandas", "pillow", "pydantic", "pytest", "requests", "sqlalchemy",
        "urllib3",
    ),
}


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _collect_dependencies(root: Path) -> list[tuple[str, str, str]]:
    dependencies: dict[tuple[str, str], str] = {}
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        base = Path(current_root)
        if "package.json" in filenames:
            manifest = base / "package.json"
            if manifest.is_symlink():
                continue
            if manifest.stat().st_size > MAX_MANIFEST_BYTES:
                raise ValueError(f"Package manifest exceeds 2 MiB: {manifest}")
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Could not read package manifest {manifest}: {exc}") from exc
            if not isinstance(data, dict):
                raise ValueError(f"Package manifest must contain a JSON object: {manifest}")
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                values = data.get(section, {})
                if isinstance(values, dict):
                    for package, version in values.items():
                        if isinstance(package, str) and isinstance(version, str):
                            if version.startswith((
                                "file:", "link:", "workspace:", "git+", "github:", "npm:", "http"
                            )):
                                continue
                            dependencies[("npm", package)] = manifest.relative_to(root).as_posix()
        for filename in filenames:
            if not (filename == "requirements.txt" or filename.startswith("requirements") and filename.endswith(".txt")):
                continue
            manifest = base / filename
            if manifest.is_symlink():
                continue
            if manifest.stat().st_size > MAX_MANIFEST_BYTES:
                raise ValueError(f"Requirements manifest exceeds 2 MiB: {manifest}")
            try:
                lines = manifest.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                raise ValueError(f"Could not read requirements file {manifest}: {exc}") from exc
            for line in lines:
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                try:
                    package = Requirement(line).name
                except InvalidRequirement:
                    continue
                dependencies[("PyPI", package)] = manifest.relative_to(root).as_posix()
    return [
        (ecosystem, name, path)
        for (ecosystem, name), path in sorted(dependencies.items())
    ]


def _read_metadata(url: str) -> dict | None:
    request = Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "ProtoSec package reputation check",
    })
    try:
        with urlopen(request, timeout=REGISTRY_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_METADATA_BYTES + 1)
        if len(body) > MAX_METADATA_BYTES:
            raise RuntimeError("Registry metadata response exceeded the size limit.")
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("Registry returned an invalid package record.")
        return data
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise RuntimeError(f"Registry returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Registry lookup failed: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Registry returned invalid JSON metadata.") from exc


def _created_date(ecosystem: str, data: dict) -> date | None:
    if ecosystem == "npm":
        times = data.get("time", {})
        values = [times.get("created")] if isinstance(times, dict) else []
    else:
        releases = data.get("releases", {})
        values = [
            upload
            for files in releases.values()
            if isinstance(files, list)
            for item in files
            if isinstance(item, dict)
            for upload in (item.get("upload_time_iso_8601"),)
            if upload
        ] if isinstance(releases, dict) else []
    dates = []
    for value in values:
        try:
            dates.append(datetime.fromisoformat(value.replace("Z", "+00:00")).date())
        except (AttributeError, TypeError, ValueError):
            continue
    return min(dates) if dates else None


def _likely_typosquat(ecosystem: str, package: str) -> str | None:
    known = {_normalize_name(item): item for item in POPULAR_PACKAGES[ecosystem]}
    normalized = _normalize_name(package)
    if normalized in known:
        return None
    matches = difflib.get_close_matches(normalized, known, n=1, cutoff=0.8)
    return known[matches[0]] if matches else None


def _registry_metadata(dependency: tuple[str, str, str]) -> dict | None:
    ecosystem, package, _manifest = dependency
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{quote(package, safe='@')}"
    else:
        url = f"https://pypi.org/pypi/{quote(package, safe='')}/json"
    return _read_metadata(url)


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    package: str,
    manifest: str,
    detail: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "category": "Supply chain",
        "severity": severity,
        "title": title,
        "file_path": manifest,
        "line_number": 1,
        "snippet": f"{package}: {detail}",
        "fix_prompt": (
            f"Review the public-registry metadata for dependency {package!r} in {manifest}. "
            "Confirm its identity and provenance before installing or upgrading it."
        ),
    }


def audit_package_reputation(
    root_path: str | Path,
    today: date | None = None,
) -> list[dict]:
    """Opt-in registry check of package existence, age, and likely name lookalikes."""
    root = Path(root_path).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")
    dependencies = _collect_dependencies(root)
    today = today or datetime.now(timezone.utc).date()
    findings = []
    if len(dependencies) > MAX_PACKAGES:
        raise ValueError(
            f"Online package checks are limited to {MAX_PACKAGES} dependencies per scan; "
            f"found {len(dependencies)}."
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        metadata_records = list(executor.map(_registry_metadata, dependencies))

    for (ecosystem, package, manifest), data in zip(dependencies, metadata_records):
        suggestion = _likely_typosquat(ecosystem, package)
        if data is None:
            findings.append(_finding(
                "SCA-001",
                "HIGH",
                f"Dependency not found in public registry: {package}",
                package,
                manifest,
                "not found in the public registry",
            ))
            if suggestion:
                findings.append(_finding(
                    "SCA-002",
                    "MEDIUM",
                    f"Dependency name resembles {suggestion}: {package}",
                    package,
                    manifest,
                    f"similar to popular package {suggestion!r}",
                ))
            continue
        if suggestion:
            findings.append(_finding(
                "SCA-002",
                "MEDIUM",
                f"Dependency name resembles {suggestion}: {package}",
                package,
                manifest,
                f"similar to popular package {suggestion!r}",
            ))
        created = _created_date(ecosystem, data)
        age_days = (today - created).days if created else None
        if age_days is not None and 0 <= age_days < 30:
            findings.append(_finding(
                "SCA-003",
                "MEDIUM",
                f"Recently published dependency: {package}",
                package,
                manifest,
                f"public registry first-release date {created.isoformat()} ({age_days} days old)",
            ))
    return findings
