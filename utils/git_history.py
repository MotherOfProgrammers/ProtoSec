from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from src.scanner_rules import ALLOWED_EXTENSIONS, ENTROPY_ASSIGNMENT, RULES, redact_snippet


MAX_COMMITS = 100
MAX_DIFF_BYTES = 32 * 1024 * 1024
_COMMIT_MARKER = "__PROTOSEC_COMMIT__"
_HUNK_START = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_SECRET_RULES = tuple(rule for rule in RULES if rule.category == "Secrets")


def _process_options() -> dict:
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo": startupinfo,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }


def _source_path(path: str) -> bool:
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        return False
    return relative.suffix.lower() in ALLOWED_EXTENSIONS or relative.name.lower().startswith(".env")


def _matches_for_line(line: str):
    for rule in _SECRET_RULES:
        match = rule.pattern.search(line)
        if match:
            yield rule, match.group(0)
    entropy_match = ENTROPY_ASSIGNMENT.search(line)
    if entropy_match:
        yield None, entropy_match.group(2)


def scan_git_history(root_path: str | Path) -> list[dict]:
    """Scan added text lines in recent local Git history; secret values stay redacted."""
    root = Path(root_path).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {root}")
    git_root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
        **_process_options(),
    )
    if git_root.returncode:
        detail = git_root.stderr.strip()
        raise RuntimeError(
            "The selected folder is not a Git worktree."
            + (f" {detail}" if detail else "")
        )

    command = [
        "git", "log", "--all", f"--max-count={MAX_COMMITS}", "-p", "-U0",
        "--no-color", "--no-ext-diff", "--no-textconv",
        f"--format={_COMMIT_MARKER}%H", "--",
    ]
    process = subprocess.Popen(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        **_process_options(),
    )
    findings = []
    seen = set()
    current_commit = ""
    current_path = ""
    current_line = 0
    bytes_read = 0
    if process.stdout is None:
        raise RuntimeError("Could not read Git history output.")
    for text_line in process.stdout:
        bytes_read += len(text_line.encode("utf-8", errors="replace"))
        if bytes_read > MAX_DIFF_BYTES:
            process.kill()
            process.wait()
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            raise RuntimeError(
                f"Git history output exceeded the {MAX_DIFF_BYTES // (1024 * 1024)} MB scan limit."
            )
        line = text_line.rstrip("\r\n")
        if line.startswith(_COMMIT_MARKER):
            current_commit = line[len(_COMMIT_MARKER):]
            current_path = ""
            current_line = 0
            continue
        if line.startswith("+++ b/"):
            current_path = line[6:]
            if not _source_path(current_path):
                current_path = ""
            continue
        hunk = _HUNK_START.match(line)
        if hunk:
            current_line = int(hunk.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++") and current_path:
            added_line = line[1:]
            for rule, secret in _matches_for_line(added_line):
                rule_id = rule.rule_id if rule else "SEC-000"
                key = (current_commit, current_path, current_line, rule_id)
                if key in seen:
                    continue
                seen.add(key)
                title = rule.title if rule else "High-entropy secret assignment"
                severity = rule.severity if rule else "HIGH"
                findings.append({
                    "rule_id": rule_id,
                    "category": "Secrets",
                    "severity": severity,
                    "title": f"Historical secret: {title}",
                    "file_path": current_path,
                    "line_number": current_line,
                    "commit_hash": current_commit,
                    "snippet": redact_snippet(added_line, secret),
                    "fix_prompt": (
                        f"Rotate this credential, remove the historical exposure from commit "
                        f"{current_commit}, and review all references to {current_path}."
                    ),
                })
            current_line += 1
        elif line.startswith(" "):
            current_line += 1

    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()
    if return_code:
        raise RuntimeError(stderr.strip() or "Git history scan failed.")
    return findings
