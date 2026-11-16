import subprocess
import tempfile
import unittest
from pathlib import Path

from utils.git_history import scan_git_history


class GitHistoryTests(unittest.TestCase):
    def test_finds_removed_secret_in_history_without_returning_the_value(self):
        secret = "sk-" + "a" * 40
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._git(root, "init", "-q")
            source = root / "settings.py"
            source.write_text(f"API_KEY = '{secret}'\n", encoding="utf-8")
            self._git(root, "add", "settings.py")
            self._commit(root, "add key")
            source.write_text("API_KEY = ''\n", encoding="utf-8")
            self._git(root, "add", "settings.py")
            self._commit(root, "remove key")

            findings = scan_git_history(root)

        self.assertTrue(any(finding["rule_id"] == "SEC-001" for finding in findings))
        finding = next(finding for finding in findings if finding["rule_id"] == "SEC-001")
        self.assertEqual(len(finding["commit_hash"]), 40)
        self.assertNotIn(secret, repr(findings))
        self.assertIn("…", finding["snippet"])

    def test_requires_a_git_repository(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with self.assertRaisesRegex(RuntimeError, "not a Git worktree"):
                scan_git_history(temporary_directory)

    @staticmethod
    def _git(root, *arguments):
        subprocess.run(["git", *arguments], cwd=root, check=True, shell=False)

    @classmethod
    def _commit(cls, root, message):
        cls._git(
            root,
            "-c", "user.name=ProtoSec Test",
            "-c", "user.email=protosec@example.invalid",
            "commit", "-q", "-m", message,
        )


if __name__ == "__main__":
    unittest.main()
