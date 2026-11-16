from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


_HOOK_TEMPLATE = r'''#!/usr/bin/env python3
import ntpath
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_SCANNER = Path(__PROTOSEC_SCANNER_PATH__)


def _git(root, arguments):
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(detail or "Git command failed")
    return completed.stdout


def _safe_parts(path_bytes):
    if not path_bytes or path_bytes.startswith(b"/") or b"\\" in path_bytes:
        raise RuntimeError("Unsafe staged path rejected")
    parts = path_bytes.split(b"/")
    if any(part in (b"", b".", b"..") for part in parts):
        raise RuntimeError("Unsafe staged path rejected")
    path = os.fsdecode(path_bytes)
    if ntpath.splitdrive(path)[0] or any(
        ":" in part or part.endswith((" ", ".")) or any(ord(char) < 32 for char in part)
        for part in path.split("/")
    ):
        raise RuntimeError("Unsafe staged path rejected")
    reserved = {"CON", "PRN", "AUX", "NUL"}
    for part in path.split("/"):
        stem = part.split(".", 1)[0].upper()
        if stem in reserved or (
            len(stem) == 4 and stem[:3] in ("COM", "LPT") and stem[3] in "123456789"
        ):
            raise RuntimeError("Unsafe staged path rejected")
    return path.split("/")


def _create_snapshot(root, snapshot):
    changed = {
        path for path in _git(
            root,
            ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT", "--"],
        ).split(b"\0")
        if path
    }
    if not changed:
        return

    entries = {}
    for record in _git(root, ["ls-files", "--stage", "-z"]).split(b"\0"):
        if not record:
            continue
        try:
            metadata, path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.split()
        except ValueError as error:
            raise RuntimeError("Git returned an invalid index entry") from error
        if stage == b"0":
            entries[path] = (mode, object_id)

    snapshot_root = snapshot.resolve()
    for path in changed:
        entry = entries.get(path)
        if entry is None:
            continue
        mode, object_id = entry
        if mode not in (b"100644", b"100755"):
            continue
        if len(object_id) not in (40, 64) or any(
            character not in b"0123456789abcdefABCDEF" for character in object_id
        ):
            raise RuntimeError("Git returned an invalid staged object id")
        parts = _safe_parts(path)
        target = snapshot.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = target.parent.resolve()
        if os.path.commonpath((str(snapshot_root), str(resolved_parent))) != str(snapshot_root):
            raise RuntimeError("Unsafe staged path rejected")
        for parent in (target.parent, *target.parent.parents):
            if parent == snapshot:
                break
            if parent.is_symlink():
                raise RuntimeError("Unsafe staged path rejected")
        content = _git(root, ["cat-file", "blob", object_id.decode("ascii")])
        with target.open("xb") as staged_file:
            staged_file.write(content)


def main():
    try:
        start = Path.cwd()
        root_bytes = _git(start, ["rev-parse", "--show-toplevel"]).rstrip(b"\r\n")
        root = Path(os.fsdecode(root_bytes)).resolve()
        with tempfile.TemporaryDirectory(prefix="protosec-staged-") as directory:
            snapshot = Path(directory) / "snapshot"
            snapshot.mkdir()
            _create_snapshot(root, snapshot)
            result = subprocess.run(
                [str(_SCANNER), "--staged-only", str(snapshot)],
                cwd=root,
                shell=False,
            )
            return result.returncode
    except (OSError, RuntimeError) as error:
        print("ProtoSec pre-commit scan failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _git_output(repository_root: Path, arguments: list[str]) -> bytes:
    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(detail or "Git command failed")
    return completed.stdout


def install_precommit_hook(repository_root: Path, scanner_binary: Path) -> Path:
    """Install a hook that scans only changed, staged Git blob contents."""
    root = Path(repository_root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    scanner = Path(scanner_binary).expanduser().resolve(strict=True)
    if not scanner.is_file():
        raise FileNotFoundError(f"Scanner binary is not a file: {scanner}")

    git_root = Path(
        os.fsdecode(_git_output(root, ["rev-parse", "--show-toplevel"]).rstrip(b"\r\n"))
    ).resolve()
    if git_root != root:
        raise ValueError(f"repository_root must be the Git worktree root: {git_root}")

    hooks_path = Path(
        os.fsdecode(_git_output(root, ["rev-parse", "--git-path", "hooks"]).rstrip(b"\r\n"))
    )
    if not hooks_path.is_absolute():
        hooks_path = root / hooks_path
    hooks_directory = hooks_path.resolve()
    hooks_directory.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_directory / "pre-commit"
    if hook_path.exists() or hook_path.is_symlink():
        raise FileExistsError(
            f"Refusing to overwrite existing Git pre-commit hook: {hook_path}"
        )

    hook_source = _HOOK_TEMPLATE.replace(
        "__PROTOSEC_SCANNER_PATH__", repr(str(scanner))
    )
    created = False
    try:
        with hook_path.open("x", encoding="utf-8", newline="\n") as hook_file:
            created = True
            hook_file.write(hook_source)
        if os.name != "nt":
            hook_path.chmod(
                hook_path.stat().st_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )
    except FileExistsError as error:
        raise FileExistsError(
            f"Refusing to overwrite existing Git pre-commit hook: {hook_path}"
        ) from error
    except OSError:
        if created:
            hook_path.unlink(missing_ok=True)
        raise
    return hook_path
