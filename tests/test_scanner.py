import tempfile
import unittest
from pathlib import Path

from src.main import scan_repository
from src.scanner_rules import RULES


class ScanRepositoryTests(unittest.TestCase):
    def test_rulebook_has_at_least_twenty_line_rules(self):
        self.assertGreaterEqual(len(RULES), 20)

    def test_scans_security_rules_reports_progress_and_skips_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "app" / "api").mkdir(parents=True)
            (root / "node_modules").mkdir()
            (root / ".git").mkdir()
            (root / "src.py").write_text(
                'token = "sk-' + "x" * 40 + '"\n'
                'secret = "AbCdEf1234567890GhIjKlMnOpQrStUvWx"\n'
                "@app.post('/records')\n"
                "data = pickle.loads(blob)\n",
                encoding="utf-8",
            )
            (root / "firestore.rules").write_text(
                "allow read, write: if true;\n",
                encoding="utf-8",
            )
            (root / "schema.sql").write_text(
                "CREATE TABLE public.accounts (id integer);\n"
                "GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC;\n",
                encoding="utf-8",
            )
            (root / "app" / "api" / "route.ts").write_text(
                "export async function POST(request) { return Response.json({}); }\n",
                encoding="utf-8",
            )
            (root / ".env.local").write_text("API_TOKEN=example-only\n", encoding="utf-8")
            (root / "node_modules" / "ignored.js").write_text(
                'token = "sk-' + "y" * 40 + '"\n',
                encoding="utf-8",
            )
            (root / ".git" / "ignored.py").write_text(
                'token = "sk-' + "z" * 40 + '"\n',
                encoding="utf-8",
            )
            progress = []

            report = scan_repository(root, progress_callback=lambda *item: progress.append(item))

            rule_ids = {finding["rule_id"] for finding in report["findings"]}
            self.assertTrue({
                "SEC-001", "DB-001", "DB-003", "DB-004", "INJ-004",
                "API-001", "API-003", "ENV-002", "SEC-007",
            }.issubset(rule_ids))
            self.assertEqual(report["total_issues"], report["summary"]["total"])
            self.assertEqual(report["files_scanned"], 5)
            self.assertTrue(any(event[0] == "scanning" for event in progress))
            self.assertNotIn("x" * 40, " ".join(
                finding["snippet"] for finding in report["findings"]
            ))

    def test_rejects_non_directory_scan_target(self):
        with tempfile.NamedTemporaryFile() as target:
            with self.assertRaises(NotADirectoryError):
                scan_repository(target.name)


if __name__ == "__main__":
    unittest.main()
