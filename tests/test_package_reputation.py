import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from utils.package_reputation import audit_package_reputation


class PackageReputationTests(unittest.TestCase):
    def test_reports_unknown_lookalike_and_recent_packages(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "package.json").write_text(
                json.dumps({
                    "dependencies": {
                        "recat": "^1.0.0",
                        "fresh-lib": "^1.0.0",
                        "known-lib": "^1.0.0",
                    },
                }),
                encoding="utf-8",
            )
            metadata = {
                "recat": None,
                "fresh-lib": {"time": {"created": "2026-11-01T00:00:00.000Z"}},
                "known-lib": {"time": {"created": "2020-01-01T00:00:00.000Z"}},
            }
            with mock.patch(
                "utils.package_reputation._read_metadata",
                side_effect=lambda url: metadata[
                    "recat" if "recat" in url else
                    "fresh-lib" if "fresh-lib" in url else "known-lib"
                ],
            ):
                findings = audit_package_reputation(root, today=date(2026, 11, 16))

        by_rule = {
            (item["rule_id"], item["title"])
            for item in findings
        }
        self.assertIn(("SCA-001", "Dependency not found in public registry: recat"), by_rule)
        self.assertIn(("SCA-002", "Dependency name resembles react: recat"), by_rule)
        self.assertIn(("SCA-003", "Recently published dependency: fresh-lib"), by_rule)
        self.assertFalse(any("known-lib" in title for _, title in by_rule))

    def test_online_check_is_limited_before_registry_requests(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            deps = {f"package-{index}": "1.0.0" for index in range(26)}
            (root / "package.json").write_text(
                json.dumps({"dependencies": deps}),
                encoding="utf-8",
            )
            with mock.patch("utils.package_reputation._read_metadata") as lookup:
                with self.assertRaisesRegex(ValueError, "limited to 25"):
                    audit_package_reputation(root)
            lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
