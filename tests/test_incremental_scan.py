import json
import os
import re
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest import mock

import utils.incremental_scan as incremental_scan_module
from src.scanner_rules import analyze_file
from utils.incremental_scan import (
    _scan_cpp_files,
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
                "SELECT findings_json FROM rule_cache"
            ).fetchall()
            connection.close()

        self.assertEqual(first["incremental"]["files_changed"], 2)
        self.assertEqual(second["incremental"]["files_changed"], 0)
        self.assertEqual(second["incremental"]["files_cached"], 2)
        self.assertEqual(first["incremental"]["files_hashed"], 2)
        self.assertTrue(first["incremental"]["full_hash_verification"])
        self.assertEqual(second["incremental"]["files_hashed"], 0)
        self.assertEqual(second["incremental"]["files_metadata_cached"], 2)
        self.assertEqual(second["incremental"]["bytes_hashed"], 0)
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual(third["incremental"]["files_changed"], 1)
        self.assertEqual(third["incremental"]["files_removed"], 1)
        self.assertEqual(third["incremental"]["files_hashed"], 1)
        self.assertEqual(
            third["incremental"]["rule_results_scanned"],
            first["incremental"]["rule_results_scanned"] // 2,
        )
        self.assertEqual(third["findings"], [])
        self.assertIn("file_hash", columns)
        self.assertNotIn("source_contents", columns)
        self.assertNotIn(secret, json.dumps(stored))

    def test_rule_configuration_changes_invalidate_cached_file_results(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            source = root / "app.py"
            source.write_text(
                "value = 'INTERNAL_ONLY'\nother = 'SAFE_ONLY'\n",
                encoding="utf-8",
            )
            config = root / ".vibeguard.toml"
            config.write_text(
                '[[rules]]\nid = "CUSTOM-010"\ntitle = "Internal marker"\n'
                'severity = "LOW"\npattern = "INTERNAL_ONLY"\nextensions = [".py"]\n'
                '[[rules]]\nid = "CUSTOM-011"\ntitle = "Safe marker"\n'
                'severity = "LOW"\npattern = "SAFE_ONLY"\nextensions = [".py"]\n',
                encoding="utf-8",
            )
            cache = Path(temporary_directory) / "scan-cache.sqlite3"

            initial = scan_incremental_project(root, cache_path=cache)
            config.write_text(
                '[[rules]]\nid = "CUSTOM-010"\ntitle = "Internal marker"\n'
                'severity = "HIGH"\npattern = "INTERNAL_ONLY"\nextensions = [".py"]\n'
                '[[rules]]\nid = "CUSTOM-011"\ntitle = "Safe marker"\n'
                'severity = "LOW"\npattern = "SAFE_ONLY"\nextensions = [".py"]\n',
                encoding="utf-8",
            )
            updated = scan_incremental_project(root, cache_path=cache)

        self.assertEqual(
            {finding["rule_id"] for finding in initial["findings"]},
            {"CUSTOM-010", "CUSTOM-011"},
        )
        updated_findings = {finding["rule_id"]: finding for finding in updated["findings"]}
        self.assertEqual(updated_findings["CUSTOM-010"]["severity"], "HIGH")
        self.assertIn("CUSTOM-011", updated_findings)
        self.assertEqual(updated["incremental"]["files_changed"], 0)
        self.assertEqual(updated["incremental"]["rule_results_scanned"], 1)

    def test_changed_rule_fingerprint_rescans_only_its_results(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"
            missing_scanner = Path(temporary_directory) / "missing-scanner.exe"

            with (
                mock.patch(
                    "utils.incremental_scan.scanner_binary_path",
                    return_value=missing_scanner,
                ),
                mock.patch(
                    "utils.incremental_scan._rule_fingerprints",
                    side_effect=[
                        {
                            "python:SEC-001": "secret-v1",
                            "python:INJ-002": "injection-v1",
                        },
                        {
                            "python:SEC-001": "secret-v2",
                            "python:INJ-002": "injection-v1",
                        },
                    ],
                ),
                mock.patch(
                    "utils.incremental_scan.analyze_file",
                    wraps=analyze_file,
                ) as analyzer,
            ):
                initial = scan_incremental_project(root, cache_path=cache)
                updated = scan_incremental_project(root, cache_path=cache)
                scanned_rule_sets = [
                    call.args[2] for call in analyzer.call_args_list
                ]

            with closing(sqlite3.connect(cache)) as connection:
                cached_results = connection.execute(
                    "SELECT rule_key, rule_fingerprint FROM rule_cache"
                ).fetchall()

        self.assertEqual(initial["incremental"]["files_changed"], 1)
        self.assertEqual(updated["incremental"]["files_changed"], 0)
        self.assertEqual(updated["incremental"]["rule_results_scanned"], 1)
        self.assertEqual(updated["incremental"]["rule_results_cached"], 1)
        self.assertEqual(
            scanned_rule_sets,
            [{"SEC-001", "INJ-002"}, {"SEC-001"}],
        )
        self.assertEqual(
            set(cached_results),
            {("python:SEC-001", "secret-v2"), ("python:INJ-002", "injection-v1")},
        )

    def test_secret_rule_change_invalidates_only_that_rule_and_entropy_dependency(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            original_fingerprints = incremental_scan_module._rule_fingerprints(
                root, None, False
            )
            changed_rules = tuple(
                replace(rule, pattern=re.compile("different-secret-pattern", rule.pattern.flags))
                if rule.rule_id == "SEC-001"
                else rule
                for rule in incremental_scan_module.RULES
            )
            with mock.patch("utils.incremental_scan.RULES", changed_rules):
                changed_fingerprints = incremental_scan_module._rule_fingerprints(
                    root, None, False
                )

        invalidated = {
            rule_key
            for rule_key, fingerprint in original_fingerprints.items()
            if changed_fingerprints[rule_key] != fingerprint
        }
        self.assertEqual(invalidated, {"python:SEC-001", "python:SEC-007"})

    def test_corrupt_cached_findings_warn_and_rescan_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            source = root / "app.py"
            source.write_text("first = 1\nsecond = 2\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"
            missing_scanner = Path(temporary_directory) / "missing-scanner.exe"

            with mock.patch(
                "utils.incremental_scan.scanner_binary_path",
                return_value=missing_scanner,
            ):
                scan_incremental_project(root, cache_path=cache)
                with closing(sqlite3.connect(cache)) as connection:
                    connection.execute(
                        "UPDATE rule_cache SET findings_json = ? WHERE rule_key = ?",
                        ("{invalid-json", "python:SEC-001"),
                    )
                    connection.commit()

                with self.assertWarnsRegex(RuntimeWarning, "Discarding invalid cached findings"):
                    recovered = scan_incremental_project(root, cache_path=cache)

            with closing(sqlite3.connect(cache)) as connection:
                stored = connection.execute(
                    "SELECT findings_json FROM rule_cache WHERE rule_key = ?",
                    ("python:SEC-001",),
                ).fetchone()[0]

        self.assertEqual(recovered["incremental"]["files_changed"], 0)
        self.assertEqual(recovered["incremental"]["rule_results_scanned"], 1)
        self.assertEqual(json.loads(stored), [])

    def test_corrupt_sqlite_cache_is_quarantined_and_rebuilt(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"
            cache.write_bytes(b"not a sqlite database")
            missing_scanner = Path(temporary_directory) / "missing-scanner.exe"

            with mock.patch(
                "utils.incremental_scan.scanner_binary_path",
                return_value=missing_scanner,
            ):
                with self.assertWarnsRegex(RuntimeWarning, "Corrupt incremental cache"):
                    report = scan_incremental_project(root, cache_path=cache)

            quarantined = list(Path(temporary_directory).glob("scan-cache.sqlite3.corrupt-*"))
            with closing(sqlite3.connect(cache)) as connection:
                row_count = connection.execute(
                    "SELECT COUNT(*) FROM file_cache"
                ).fetchone()[0]

        self.assertEqual(report["incremental"]["files_changed"], 1)
        self.assertEqual(row_count, 1)
        self.assertEqual(len(quarantined), 1)

    def test_python_fallback_preserves_line_counts_on_unchanged_scans(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text(
                "first = 1\nsecond = 2\nthird = 3\n",
                encoding="utf-8",
            )
            cache = Path(temporary_directory) / "scan-cache.sqlite3"
            missing_scanner = Path(temporary_directory) / "missing-scanner.exe"

            with mock.patch(
                "utils.incremental_scan.scanner_binary_path",
                return_value=missing_scanner,
            ):
                first = scan_incremental_project(root, cache_path=cache)
                second = scan_incremental_project(root, cache_path=cache)
                full = scan_full_project(root)

        self.assertEqual(first["lines_scanned"], 3)
        self.assertEqual(second["lines_scanned"], 3)
        self.assertEqual(full["lines_scanned"], 3)
        self.assertEqual(second["incremental"]["files_changed"], 0)

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

    def test_python_and_cpp_engines_agree_on_shared_rules(self):
        from src.main import scanner_binary_path

        if not scanner_binary_path().is_file():
            self.skipTest("C++ scanner is not built in this environment.")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text(
                "token = 'sk-" + "d" * 40 + "'\n"
                "result = eval(user_input)\n",
                encoding="utf-8",
            )
            cpp_report = scan_incremental_project(
                root,
                cache_path=Path(temporary_directory) / "cpp-cache.sqlite3",
            )
            with mock.patch(
                "utils.incremental_scan.scanner_binary_path",
                return_value=Path(temporary_directory) / "missing-scanner.exe",
            ):
                python_report = scan_incremental_project(
                    root,
                    cache_path=Path(temporary_directory) / "python-cache.sqlite3",
                )

        shared_findings = lambda report: {
            (finding["rule_id"], finding["file_path"], finding["line_number"])
            for finding in report["findings"]
        }
        self.assertEqual(shared_findings(cpp_report), shared_findings(python_report))

    def test_default_cache_is_per_user_not_inside_project(self):
        with mock.patch.dict(os.environ, {"PROTOSEC_CACHE_PATH": ""}):
            cache = scan_cache_path()
        self.assertEqual(cache.name, "scan-cache.sqlite3")
        self.assertEqual(cache.parent.name, "ProtoSec")

    def test_cache_path_can_be_configured_with_environment_variable(self):
        configured = Path("custom-cache.sqlite3")
        with mock.patch.dict(
            os.environ, {"PROTOSEC_CACHE_PATH": str(configured)}
        ):
            self.assertEqual(scan_cache_path(), configured)

    def test_legacy_cache_schema_migrates_to_per_rule_entries(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"
            with closing(sqlite3.connect(cache)) as connection:
                connection.execute(
                    """
                    CREATE TABLE file_cache (
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
                    "CREATE TABLE cache_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO cache_meta VALUES ('schema_version', '1')"
                )

            missing_scanner = Path(temporary_directory) / "missing-scanner.exe"
            with mock.patch(
                "utils.incremental_scan.scanner_binary_path",
                return_value=missing_scanner,
            ):
                report = scan_incremental_project(root, cache_path=cache)

            with closing(sqlite3.connect(cache)) as connection:
                schema = connection.execute(
                    "SELECT value FROM cache_meta WHERE key = 'schema_version'"
                ).fetchone()[0]
                file_fingerprints = connection.execute(
                    "SELECT DISTINCT engine_fingerprint FROM file_cache"
                ).fetchall()
                rule_count = connection.execute(
                    "SELECT COUNT(*) FROM rule_cache"
                ).fetchone()[0]

        self.assertEqual(schema, "3")
        self.assertEqual(file_fingerprints, [("per-rule-v2",)])
        self.assertGreater(rule_count, 0)
        self.assertEqual(report["incremental"]["files_changed"], 1)

    def test_forced_hash_and_periodic_hash_verification(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            source = root / "app.py"
            source.write_text("value = 1\n", encoding="utf-8")
            cache = Path(temporary_directory) / "scan-cache.sqlite3"
            missing_scanner = Path(temporary_directory) / "missing-scanner.exe"

            with mock.patch(
                "utils.incremental_scan.scanner_binary_path",
                return_value=missing_scanner,
            ):
                initial = scan_incremental_project(root, cache_path=cache)
                forced = scan_incremental_project(
                    root,
                    cache_path=cache,
                    force_hash_paths={source},
                )
                with closing(sqlite3.connect(cache)) as connection:
                    old_metadata = connection.execute(
                        """
                        SELECT file_size, mtime_ns, ctime_ns, device, inode
                        FROM file_cache
                        """
                    ).fetchone()
                    connection.execute(
                        "UPDATE project_scan_state SET last_full_hash_ns = 1"
                    )
                    connection.commit()

                source.write_text("value = 2\n", encoding="utf-8")
                with mock.patch(
                    "utils.incremental_scan._file_metadata",
                    return_value=old_metadata,
                ):
                    verified = scan_incremental_project(root, cache_path=cache)

        self.assertTrue(initial["incremental"]["full_hash_verification"])
        self.assertFalse(forced["incremental"]["full_hash_verification"])
        self.assertEqual(forced["incremental"]["files_hashed"], 1)
        self.assertTrue(verified["incremental"]["full_hash_verification"])
        self.assertEqual(verified["incremental"]["files_changed"], 1)
        self.assertEqual(verified["incremental"]["files_hashed"], 1)

    def test_concurrent_scans_keep_the_cache_consistent(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text(
                "token = 'sk-" + "c" * 40 + "'\n",
                encoding="utf-8",
            )
            cache = Path(temporary_directory) / "scan-cache.sqlite3"

            def scan(_):
                return scan_incremental_project(root, cache_path=cache)

            with ThreadPoolExecutor(max_workers=2) as executor:
                reports = list(executor.map(scan, range(2)))

            with closing(sqlite3.connect(cache)) as connection:
                file_count = connection.execute(
                    "SELECT COUNT(*) FROM file_cache"
                ).fetchone()[0]
                rule_count = connection.execute(
                    "SELECT COUNT(*) FROM rule_cache"
                ).fetchone()[0]

        self.assertEqual(reports[0]["findings"], reports[1]["findings"])
        self.assertEqual(file_count, 1)
        self.assertEqual(
            rule_count,
            reports[0]["incremental"]["rule_results_scanned"]
            + reports[0]["incremental"]["rule_results_cached"],
        )

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

    def test_cpp_rule_change_rescans_only_the_changed_rule(self):
        from src.main import scanner_binary_path

        if not scanner_binary_path().is_file():
            self.skipTest("C++ scanner is not built in this environment.")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "project"
            root.mkdir()
            (root / "app.py").write_text(
                'token = "sk-' + "x" * 40 + '"\nvalue = eval(user_input)\n',
                encoding="utf-8",
            )
            cache = Path(temporary_directory) / "scan-cache.sqlite3"

            with (
                mock.patch(
                    "utils.incremental_scan._rule_fingerprints",
                    side_effect=[
                        {
                            "cpp:SEC-001": "secret-v1",
                            "cpp:INJ-002": "injection-v1",
                        },
                        {
                            "cpp:SEC-001": "secret-v2",
                            "cpp:INJ-002": "injection-v1",
                        },
                    ],
                ),
                mock.patch(
                    "utils.incremental_scan._scan_cpp_files",
                    wraps=_scan_cpp_files,
                ) as native_scan,
            ):
                first = scan_incremental_project(root, cache_path=cache)
                second = scan_incremental_project(root, cache_path=cache)
                selected_rules = [
                    call.kwargs["rule_ids"] for call in native_scan.call_args_list
                ]

        self.assertEqual(first["incremental"]["rule_results_scanned"], 2)
        self.assertEqual(second["incremental"]["rule_results_scanned"], 1)
        self.assertEqual(second["incremental"]["rule_results_cached"], 1)
        self.assertEqual(selected_rules, [["INJ-002", "SEC-001"], ["SEC-001"]])


if __name__ == "__main__":
    unittest.main()
