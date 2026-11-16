import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from utils.incremental_scan import (
    scan_cache_path,
    scan_full_project,
    scan_incremental_project,
)


class IncrementalScanTests(unittest.TestCase):
    def test_reuses_unchanged_files_and_invalidates_changed_or_deleted_files(self):
        secret = "sk-" + "a" * 40
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            app = root / "app.py"
            safe = root / "safe.js"
            app.write_text(f"token = '{secret}'\n", encoding="utf-8")
            safe.write_text("const ready = true;\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"

            first = scan_incremental_project(root, cache_path=cache)
            second = scan_incremental_project(root, cache_path=cache)
            app.write_text("token = ''\n", encoding="utf-8")
            safe.unlink()
            third = scan_incremental_project(root, cache_path=cache)

            connection = sqlite3.connect(cache)
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(file_cache)")
            }
            stored = connection.execute(
                "SELECT findings_json FROM file_cache"
            ).fetchall()
            connection.close()

        self.assertEqual(first["incremental"]["files_changed"], 2)
        self.assertEqual(second["incremental"]["files_changed"], 0)
        self.assertEqual(second["incremental"]["files_cached"], 2)
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual(third["incremental"]["files_changed"], 1)
        self.assertEqual(third["incremental"]["files_removed"], 1)
        self.assertEqual(third["findings"], [])
        self.assertIn("file_hash", columns)
        self.assertNotIn("source_contents", columns)
        self.assertNotIn(secret, json.dumps(stored))

    def test_rule_configuration_changes_invalidate_cached_file_results(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            source = root / "app.py"
            source.write_text("value = 'INTERNAL_ONLY'\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"

            initial = scan_incremental_project(root, cache_path=cache)
            (root / ".vibeguard.toml").write_text(
                '[[rules]]\nid = "CUSTOM-010"\ntitle = "Internal marker"\n'
                'severity = "LOW"\npattern = "INTERNAL_ONLY"\nextensions = [".py"]\n',
                encoding="utf-8",
            )
            updated = scan_incremental_project(root, cache_path=cache)

        self.assertEqual(initial["findings"], [])
        self.assertIn("CUSTOM-010", {finding["rule_id"] for finding in updated["findings"]})
        self.assertEqual(updated["incremental"]["files_changed"], 1)

    def test_incremental_and_full_scans_have_same_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text(
                "query = f'SELECT * FROM users WHERE id={user_id}'\n",
                encoding="utf-8",
            )
            cache = Path(temporary_directory) / "scan-cache.sqlite3"

            incremental = scan_incremental_project(root, cache_path=cache)
            full = scan_full_project(root)

        self.assertEqual(incremental["findings"], full["findings"])
        self.assertEqual(incremental["summary"], full["summary"])

    def test_default_cache_is_per_user_not_inside_project(self):
        cache = scan_cache_path()
        self.assertEqual(cache.name, "scan-cache.sqlite3")
        self.assertEqual(cache.parent.name, "ProtoSec")

    def test_cpp_engine_uses_file_list_when_available(self):
        from src.main import scanner_binary_path

        if not scanner_binary_path().is_file():
            self.skipTest("C++ scanner is not built in this environment.")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text(
                "token = 'sk-" + "b" * 40 + "'\n",
                encoding="utf-8",
            )
            (root / "safe.ts").write_text("const ready = true;\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"

            first = scan_incremental_project(root, cache_path=cache)
            second = scan_incremental_project(root, cache_path=cache)

        self.assertEqual(first["incremental"]["files_changed"], 2)
        self.assertEqual(second["incremental"]["files_cached"], 2)
        self.assertEqual(first["findings"], second["findings"])
        self.assertTrue(any(finding["rule_id"] == "SEC-001" for finding in first["findings"]))


if __name__ == "__main__":
    unittest.main()
