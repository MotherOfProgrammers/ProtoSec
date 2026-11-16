from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

import regex

from src.scanner_rules import ALLOWED_EXTENSIONS, SKIP_DIRS, redact_snippet

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib


MAX_RULE_FILE_BYTES = 64 * 1024
MAX_RULES = 50
MAX_RULE_SCAN_FILE_BYTES = 2 * 1024 * 1024
MAX_RULE_SCAN_FILES = 5000
MAX_RULE_SCAN_TOTAL_BYTES = 128 * 1024 * 1024
MAX_RULE_SCAN_SECONDS = 30
REGEX_TIMEOUT_SECONDS = 0.025
_RULE_ID = re.compile(r"CUSTOM-[A-Z0-9][A-Z0-9_-]{0,31}\Z")
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


@dataclass(frozen=True)
class CustomRule:
    rule_id: str
    title: str
    severity: str
    pattern: regex.Pattern
    extensions: frozenset[str]


def load_custom_rules(root_path: str | Path) -> list[CustomRule]:
    root = Path(root_path)
    config = root / ".vibeguard.toml"
    if not config.exists():
        return []
    if not config.is_file():
        raise ValueError(".vibeguard.toml must be a regular file.")
    if config.stat().st_size > MAX_RULE_FILE_BYTES:
        raise ValueError(".vibeguard.toml exceeds the 64 KiB size limit.")
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"Could not parse .vibeguard.toml: {exc}") from exc
    if not isinstance(data, dict) or set(data) - {"rules"}:
        raise ValueError(".vibeguard.toml may contain only a top-level rules array.")
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        raise ValueError(f".vibeguard.toml must contain at most {MAX_RULES} rules.")

    rules = []
    seen_ids = set()
    for index, raw in enumerate(raw_rules, start=1):
        if not isinstance(raw, dict) or set(raw) - {
            "id", "title", "severity", "pattern", "extensions"
        }:
            raise ValueError(f"Custom rule {index} contains unknown fields.")
        rule_id = raw.get("id")
        title = raw.get("title")
        severity = raw.get("severity")
        pattern = raw.get("pattern")
        extensions = raw.get("extensions", sorted(ALLOWED_EXTENSIONS))
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            raise ValueError(f"Custom rule {index} needs an id such as CUSTOM-001.")
        if rule_id in seen_ids:
            raise ValueError(f"Duplicate custom rule id: {rule_id}")
        if not isinstance(title, str) or not title.strip() or len(title) > 100:
            raise ValueError(f"Custom rule {rule_id} needs a title of 1–100 characters.")
        if not isinstance(severity, str) or severity.upper() not in _SEVERITIES:
            raise ValueError(f"Custom rule {rule_id} has an unsupported severity.")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
            raise ValueError(f"Custom rule {rule_id} needs a pattern of 1–256 characters.")
        if (
            not isinstance(extensions, list)
            or not extensions
            or len(extensions) > len(ALLOWED_EXTENSIONS)
            or any(not isinstance(item, str) or item.lower() not in ALLOWED_EXTENSIONS for item in extensions)
        ):
            raise ValueError(f"Custom rule {rule_id} has unsupported file extensions.")
        try:
            compiled = regex.compile(pattern)
        except regex.error as exc:
            raise ValueError(f"Custom rule {rule_id} has an invalid regex: {exc}") from exc
        try:
            if compiled.search("", timeout=REGEX_TIMEOUT_SECONDS):
                raise ValueError(f"Custom rule {rule_id} may not match an empty string.")
        except TimeoutError as exc:
            raise ValueError(f"Custom rule {rule_id} exceeded the regex time limit.") from exc
        seen_ids.add(rule_id)
        rules.append(CustomRule(
            rule_id=rule_id,
            title=title.strip(),
            severity=severity.upper(),
            pattern=compiled,
            extensions=frozenset(item.lower() for item in extensions),
        ))
    return rules


def scan_custom_rules(root_path: str | Path) -> list[dict]:
    root = Path(root_path).resolve(strict=True)
    rules = load_custom_rules(root)
    if not rules:
        return []
    wanted_extensions = set().union(*(rule.extensions for rule in rules))
    findings = []
    scanned_files = 0
    scanned_bytes = 0
    started = time.monotonic()
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for filename in filenames:
            path = Path(current_root) / filename
            if path == root / ".vibeguard.toml":
                continue
            if path.suffix.lower() not in wanted_extensions:
                continue
            scanned_files += 1
            if scanned_files > MAX_RULE_SCAN_FILES:
                raise RuntimeError(
                    f"Custom rules are limited to {MAX_RULE_SCAN_FILES} files per scan."
                )
            file_size = path.stat().st_size
            if file_size > MAX_RULE_SCAN_FILE_BYTES:
                raise RuntimeError(
                    f"Custom-rule scan file exceeds 2 MiB: {path.relative_to(root).as_posix()}"
                )
            scanned_bytes += file_size
            if scanned_bytes > MAX_RULE_SCAN_TOTAL_BYTES:
                raise RuntimeError("Custom-rule scan exceeded its 128 MiB total input limit.")
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                raise OSError(f"Could not read custom-rule scan file {path}: {exc}") from exc
            relative = path.relative_to(root).as_posix()
            applicable = [rule for rule in rules if path.suffix.lower() in rule.extensions]
            for line_number, line in enumerate(lines, start=1):
                for rule in applicable:
                    if time.monotonic() - started > MAX_RULE_SCAN_SECONDS:
                        raise RuntimeError("Custom-rule scan exceeded its 30-second time limit.")
                    try:
                        match = rule.pattern.search(line, timeout=REGEX_TIMEOUT_SECONDS)
                    except TimeoutError as exc:
                        raise RuntimeError(
                            f"Custom rule {rule.rule_id} exceeded the 25 ms per-line regex limit."
                        ) from exc
                    if not match:
                        continue
                    matched_text = match.group(0)
                    findings.append({
                        "rule_id": rule.rule_id,
                        "category": "Custom policy",
                        "severity": rule.severity,
                        "title": rule.title,
                        "file_path": relative,
                        "line_number": line_number,
                        "snippet": redact_snippet(line, matched_text),
                        "fix_prompt": (
                            f"Review custom policy {rule.rule_id} ({rule.title}) at "
                            f"{relative}:{line_number}."
                        ),
                    })
    return findings
