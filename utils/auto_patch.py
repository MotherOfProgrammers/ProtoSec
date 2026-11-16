import difflib
import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


_PUBLIC_SECRET_PREFIX = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)(?=[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|DATABASE_URL))",
    re.IGNORECASE,
)
_CREATE_TABLE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_.\"]+)",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*\Z")


@dataclass(frozen=True)
class PatchFile:
    relative_path: str
    before: bytes
    after: bytes
    expected_hash: str | None


@dataclass(frozen=True)
class PatchPlan:
    files: tuple[PatchFile, ...]
    unified_diff: str
    skipped: tuple[str, ...]


def _resolve_target(root: Path, relative_path: str, allow_missing: bool = False) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Unsafe patch path: {relative_path}")
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"Patch path escapes the selected project: {relative_path}")
    if not allow_missing and not candidate.is_file():
        raise FileNotFoundError(f"Patch target no longer exists: {relative_path}")
    return candidate


def _load_text(root: Path, relative_path: str, changes: dict) -> tuple[Path, str, str]:
    path = _resolve_target(root, relative_path)
    if path in changes:
        before, text = changes[path]
        return path, before, text
    before = path.read_bytes()
    return path, before, before.decode("utf-8")


def create_patch_plan(root_path: str | Path, findings: list[dict]) -> PatchPlan:
    root = Path(root_path).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Patch root is not a directory: {root}")

    changes: dict[Path, tuple[bytes, str]] = {}
    skipped = []
    for finding in findings:
        rule_id = finding.get("rule_id")
        relative_path = str(finding.get("file_path", ""))
        if rule_id not in {"DB-004", "ENV-001"} or not relative_path:
            continue
        try:
            path, before, text = _load_text(root, relative_path, changes)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            skipped.append(f"{relative_path}: {exc}")
            continue
        updated_text = text

        if rule_id == "DB-004" and path.suffix.lower() == ".sql":
            match = _CREATE_TABLE.search(str(finding.get("snippet", "")))
            if not match:
                skipped.append(f"{relative_path}: could not safely identify the SQL table.")
                continue
            parts = [part.strip('"') for part in match.group(1).split(".")]
            if not parts or any(not _IDENTIFIER.fullmatch(part) for part in parts):
                skipped.append(f"{relative_path}: table identifier requires manual review.")
                continue
            table = ".".join(f'"{part}"' for part in parts)
            newline = "\r\n" if "\r\n" in updated_text else "\n"
            statement = f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
            if statement.lower() not in updated_text.lower():
                if updated_text and not updated_text.endswith(("\n", "\r")):
                    updated_text += newline
                updated_text += statement + newline

        elif rule_id == "ENV-001":
            if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"}:
                skipped.append(f"{relative_path}: unsupported file type for prefix removal.")
                continue
            line_number = int(finding.get("line_number", 0))
            lines = updated_text.splitlines(keepends=True)
            if line_number < 1 or line_number > len(lines):
                skipped.append(f"{relative_path}: reported line is no longer available.")
                continue
            preceding = "\n".join(lines[:line_number - 1])
            in_block_comment = preceding.count("/*") > preceding.count("*/")
            line = lines[line_number - 1]
            stripped = line.lstrip()
            prefix_match = _PUBLIC_SECRET_PREFIX.search(line)
            comment_before_match = (
                line.find("//") >= 0
                and prefix_match is not None
                and line.find("//") < prefix_match.start()
            )
            if (
                in_block_comment
                or stripped.startswith(("//", "#", "/*", "*"))
                or comment_before_match
            ):
                skipped.append(f"{relative_path}:{line_number}: match is inside a comment.")
                continue
            lines[line_number - 1], count = _PUBLIC_SECRET_PREFIX.subn("", line, count=1)
            updated_text = "".join(lines)
            if not count:
                skipped.append(f"{relative_path}: no sensitive public prefix remains to remove.")
                continue

        if updated_text != text:
            changes[path] = (before, updated_text)

    env_findings = [
        item for item in findings
        if item.get("rule_id") == "ENV-002"
    ]
    if env_findings:
        gitignore_path = _resolve_target(root, ".gitignore", allow_missing=True)
        before = gitignore_path.read_bytes() if gitignore_path.is_file() else b""
        try:
            text = before.decode("utf-8")
        except UnicodeDecodeError:
            skipped.append(".gitignore: file is not valid UTF-8.")
        else:
            newline = "\r\n" if "\r\n" in text else "\n"
            entries = {line.strip() for line in text.splitlines()}
            additions = [
                entry for entry in (".env", ".env.*", "!.env.example", "!.env.sample", "!.env.template")
                if entry not in entries
            ]
            if additions:
                if text and not text.endswith(("\n", "\r")):
                    text += newline
                text += newline.join(additions) + newline
                changes[gitignore_path] = (before, text)

    patch_files = []
    diff_chunks = []
    for path, (before, after) in sorted(changes.items(), key=lambda item: item[0].as_posix().casefold()):
        relative = path.relative_to(root).as_posix()
        after_bytes = after.encode("utf-8")
        expected_hash = hashlib.sha256(before).hexdigest() if path.exists() else None
        patch_files.append(PatchFile(relative, before, after_bytes, expected_hash))
        old_lines = before.decode("utf-8").splitlines(keepends=True)
        new_lines = after.splitlines(keepends=True)
        diff_chunks.extend(difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{relative}" if before else "/dev/null",
            tofile=f"b/{relative}",
        ))

    return PatchPlan(tuple(patch_files), "".join(diff_chunks), tuple(skipped))


def apply_patch_plan(root_path: str | Path, plan: PatchPlan) -> list[str]:
    root = Path(root_path).resolve()
    prepared = []
    applied = []
    try:
        for patch_file in plan.files:
            target = _resolve_target(root, patch_file.relative_path, allow_missing=True)
            exists = target.is_file()
            current = target.read_bytes() if exists else b""
            current_hash = hashlib.sha256(current).hexdigest() if exists else None
            if current_hash != patch_file.expected_hash:
                raise RuntimeError(
                    f"{patch_file.relative_path} changed since preview; regenerate the patch."
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".protosec-", suffix=".tmp",
                dir=target.parent, delete=False,
            ) as staged:
                staged.write(patch_file.after)
                staged.flush()
                os.fsync(staged.fileno())
                staged_path = Path(staged.name)
            os.chmod(staged_path, stat.S_IMODE(target.stat().st_mode) if exists else 0o644)
            backup_path = None
            if exists:
                with tempfile.NamedTemporaryFile(
                    mode="wb", prefix=".protosec-backup-", suffix=".tmp",
                    dir=target.parent, delete=False,
                ) as backup:
                    backup.write(current)
                    backup.flush()
                    os.fsync(backup.fileno())
                    backup_path = Path(backup.name)
            prepared.append((target, staged_path, backup_path, exists))

        for target, staged_path, backup_path, existed in prepared:
            os.replace(staged_path, target)
            applied.append((target, backup_path, existed))
        return [patch_file.relative_path for patch_file in plan.files]
    except OSError as exc:
        rollback_errors = []
        for target, backup_path, existed in reversed(applied):
            try:
                if existed and backup_path:
                    os.replace(backup_path, target)
                else:
                    target.unlink(missing_ok=True)
            except OSError as rollback_error:
                rollback_errors.append(f"{target}: {rollback_error}")
        details = f"Could not apply patch set: {exc}"
        if rollback_errors:
            details += "\nRollback errors: " + "; ".join(rollback_errors)
        raise OSError(details) from exc
    finally:
        for _target, staged_path, backup_path, _existed in prepared:
            for temporary in (staged_path, backup_path):
                if temporary and temporary.exists():
                    temporary.unlink()
