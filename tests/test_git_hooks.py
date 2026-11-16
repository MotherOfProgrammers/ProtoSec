import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from utils.git_hooks import install_precommit_hook


class GitHookTests(unittest.TestCase):
    def test_hook_passes_only_changed_index_blob_contents_to_scanner(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            scanner = root / "scanner"
            scanner.write_text("fake scanner", encoding="utf-8")
            hook_source = self._hook_source(scanner)
            git_root = os.fsencode(root)
            staged = b"src/staged.txt"
            unchanged = b"src/unchanged.txt"
            calls = []

            def fake_run(arguments, **kwargs):
                calls.append((arguments, kwargs))
                self.assertIsInstance(arguments, list)
                self.assertIs(kwargs["shell"], False)
                if arguments[:3] == ["git", "rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, git_root + b"\n", b"")
                if arguments[1:3] == ["diff", "--cached"]:
                    return subprocess.CompletedProcess(arguments, 0, staged + b"\0", b"")
                if arguments[1:3] == ["ls-files", "--stage"]:
                    entries = (
                        b"100644 " + b"a" * 40 + b" 0\t" + staged + b"\0"
                        + b"100644 " + b"b" * 40 + b" 0\t" + unchanged + b"\0"
                    )
                    return subprocess.CompletedProcess(arguments, 0, entries, b"")
                if arguments[1:3] == ["cat-file", "blob"]:
                    self.assertEqual(arguments[3], "a" * 40)
                    return subprocess.CompletedProcess(
                        arguments, 0, b"staged blob, not working-tree data", b""
                    )
                if arguments[0] == str(scanner):
                    self.assertEqual(arguments[1], "--staged-only")
                    snapshot = Path(arguments[2])
                    self.assertEqual(
                        (snapshot / "src" / "staged.txt").read_bytes(),
                        b"staged blob, not working-tree data",
                    )
                    self.assertFalse((snapshot / "src" / "unchanged.txt").exists())
                    return subprocess.CompletedProcess(arguments, 0)
                self.fail(f"Unexpected subprocess command: {arguments!r}")

            with mock.patch("subprocess.run", side_effect=fake_run):
                with self.assertRaises(SystemExit) as result:
                    exec(
                        compile(hook_source, "pre-commit", "exec"),
                        {"__name__": "__main__"},
                    )
            self.assertEqual(result.exception.code, 0)

            self.assertTrue(any(call[0][1:3] == ["cat-file", "blob"] for call in calls))
            self.assertTrue(any(call[0][1:3] == ["diff", "--cached"] for call in calls))

    def test_hook_rejects_traversal_paths_before_scanner_execution(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            scanner = root / "scanner"
            scanner.write_text("fake scanner", encoding="utf-8")
            hook_source = self._hook_source(scanner)
            outside = root.parent / f"{root.name}-escape.txt"
            calls = []

            def fake_run(arguments, **kwargs):
                calls.append(arguments)
                if arguments[:3] == ["git", "rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, os.fsencode(root) + b"\n", b"")
                if arguments[1:3] == ["diff", "--cached"]:
                    return subprocess.CompletedProcess(
                        arguments, 0, f"../{outside.name}".encode() + b"\0", b""
                    )
                if arguments[1:3] == ["ls-files", "--stage"]:
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        b"100644 " + b"a" * 40 + b" 0\t"
                        + f"../{outside.name}".encode()
                        + b"\0",
                        b"",
                    )
                if arguments[1:3] == ["cat-file", "blob"]:
                    return subprocess.CompletedProcess(arguments, 0, b"must not be written", b"")
                self.fail(f"Scanner must not run for traversal path: {arguments!r}")

            with mock.patch("subprocess.run", side_effect=fake_run):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as result:
                        exec(compile(hook_source, "pre-commit", "exec"), {"__name__": "__main__"})

            self.assertEqual(result.exception.code, 1)
            self.assertIn("Unsafe staged path rejected", stderr.getvalue())
            self.assertFalse(outside.exists())
            self.assertFalse(any(args[0] == str(scanner) for args in calls))

    def test_existing_hook_is_not_overwritten_and_worktree_git_path_is_used(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            (root / ".git").write_text("gitdir: worktree-admin\n", encoding="utf-8")
            scanner = root / "scanner"
            scanner.write_text("fake scanner", encoding="utf-8")
            hooks = root / "worktree-admin" / "hooks"
            hooks.mkdir(parents=True)
            hook = hooks / "pre-commit"
            original = b"existing hook contents"
            hook.write_bytes(original)

            def fake_run(arguments, **kwargs):
                self.assertIsInstance(arguments, list)
                self.assertIs(kwargs["shell"], False)
                if arguments[1:] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, os.fsencode(root) + b"\n", b"")
                if arguments[1:] == ["rev-parse", "--git-path", "hooks"]:
                    return subprocess.CompletedProcess(
                        arguments, 0, os.fsencode(hooks) + b"\n", b""
                    )
                self.fail(f"Unexpected Git command: {arguments!r}")

            with mock.patch("subprocess.run", side_effect=fake_run):
                with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite"):
                    install_precommit_hook(root, scanner)

            self.assertEqual(hook.read_bytes(), original)

    def test_installs_hook_at_git_reported_path(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            scanner = root / "scanner"
            scanner.write_text("fake scanner", encoding="utf-8")
            hooks = root / ".git" / "hooks"

            def fake_run(arguments, **kwargs):
                self.assertIsInstance(arguments, list)
                self.assertIs(kwargs["shell"], False)
                if arguments[1:] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(arguments, 0, os.fsencode(root) + b"\n", b"")
                if arguments[1:] == ["rev-parse", "--git-path", "hooks"]:
                    return subprocess.CompletedProcess(arguments, 0, b".git/hooks\n", b"")
                self.fail(f"Unexpected Git command: {arguments!r}")

            with mock.patch("subprocess.run", side_effect=fake_run):
                installed = install_precommit_hook(root, scanner)

            self.assertEqual(installed, hooks / "pre-commit")
            self.assertIn("--staged-only", installed.read_text(encoding="utf-8"))
            self.assertIn(repr(str(scanner)), installed.read_text(encoding="utf-8"))
            if os.name != "nt":
                self.assertTrue(installed.stat().st_mode & 0o111)

    @staticmethod
    def _hook_source(scanner):
        from utils.git_hooks import _HOOK_TEMPLATE

        return _HOOK_TEMPLATE.replace(
            "__PROTOSEC_SCANNER_PATH__", repr(str(scanner))
        )


if __name__ == "__main__":
    unittest.main()
