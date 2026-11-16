import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from utils.cve_audit import (
    _compare_versions,
    _create_schema,
    merge_findings,
    scan_dependencies,
)


class CveAuditTests(unittest.TestCase):
    def test_scans_pinned_npm_and_python_dependencies_offline(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "package-lock.json").write_text(
                json.dumps({
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "sample"},
                        "node_modules/left-pad": {"version": "1.2.0"},
                    },
                }),
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("Django==2.2.0\n", encoding="utf-8")
            database = root / "osv.sqlite3"
            connection = sqlite3.connect(database)
            _create_schema(connection)
            affected = {
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "1.3.0"}],
                }]
            }
            pypi_affected = {
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.2.1"}],
                }]
            }
            connection.executemany(
                """
                INSERT INTO advisories
                (ecosystem, package, advisory_id, summary, severity, affected_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    ("npm", "left-pad", "OSV-NPM-1", "Test npm issue", "HIGH", json.dumps(affected)),
                    ("PyPI", "django", "OSV-PYPI-1", "Test Python issue", "CRITICAL", json.dumps(pypi_affected)),
                ],
            )
            connection.commit()
            connection.close()

            findings = scan_dependencies(root, database)

            self.assertEqual({item["rule_id"] for item in findings}, {"OSV-NPM-1", "OSV-PYPI-1"})
            self.assertTrue(any("Upgrade to 1.3.0" in item["fix_prompt"] for item in findings))

    def test_version_ranges_handle_npm_prereleases_and_fixed_boundary(self):
        self.assertLess(_compare_versions("npm", "1.0.0-beta.2", "1.0.0-beta.10"), 0)
        self.assertGreater(_compare_versions("npm", "1.0.0", "1.0.0-rc.1"), 0)

    def test_scan_requires_a_local_database(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with self.assertRaises(FileNotFoundError):
                scan_dependencies(root, root / "missing.sqlite3")

    def test_merging_findings_recalculates_report_summary_and_score(self):
        report = {"findings": [], "summary": {"total": 0}, "security_score": 100}
        merged = merge_findings(report, [{
            "rule_id": "OSV-TEST",
            "severity": "CRITICAL",
        }])
        self.assertEqual(merged["summary"]["critical"], 1)
        self.assertEqual(merged["summary"]["total"], 1)
        self.assertEqual(merged["security_score"], 75)


if __name__ == "__main__":
    unittest.main()
