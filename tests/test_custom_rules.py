import tempfile
import unittest
from pathlib import Path

from src.main import scan_repository
from utils.custom_rules import load_custom_rules, scan_custom_rules


class CustomRuleTests(unittest.TestCase):
    def test_scans_matching_local_rule_and_redacts_the_match(self):
        secret = "PRIVATE-" + "x" * 24
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".vibeguard.toml").write_text(
                '[[rules]]\n'
                'id = "CUSTOM-001"\n'
                'title = "Internal credential"\n'
                'severity = "high"\n'
                'pattern = "PRIVATE-[A-Za-z0-9]{24}"\n'
                'extensions = [".py"]\n',
                encoding="utf-8",
            )
            (root / "app.py").write_text(f"token = '{secret}'\n", encoding="utf-8")

            findings = scan_custom_rules(root)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "CUSTOM-001")
        self.assertNotIn(secret, findings[0]["snippet"])
        self.assertIn("…", findings[0]["snippet"])

    def test_python_scan_includes_project_policy_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".vibeguard.toml").write_text(
                '[[rules]]\nid = "CUSTOM-010"\ntitle = "Forbidden marker"\n'
                'severity = "LOW"\npattern = "INTERNAL_ONLY"\nextensions = [".py"]\n',
                encoding="utf-8",
            )
            (root / "app.py").write_text("mode = 'INTERNAL_ONLY'\n", encoding="utf-8")

            report = scan_repository(root)

        self.assertIn("CUSTOM-010", {item["rule_id"] for item in report["findings"]})

    def test_rejects_duplicate_ids_and_empty_match_patterns(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = root / ".vibeguard.toml"
            config.write_text(
                '[[rules]]\nid = "CUSTOM-001"\ntitle = "Empty"\nseverity = "LOW"\npattern = ".*"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "empty string"):
                load_custom_rules(root)

    def test_invalid_configuration_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".vibeguard.toml").write_text(
                '[[rules]]\nid = "bad-id"\ntitle = "Bad"\nseverity = "HIGH"\npattern = "x"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "id such as CUSTOM"):
                load_custom_rules(root)


if __name__ == "__main__":
    unittest.main()
