import json
import tempfile
import unittest
from pathlib import Path

from utils.report_exporter import export_html_report, export_json_report


class ReportExporterTests(unittest.TestCase):
    def test_exports_json_and_escapes_untrusted_html_fields(self):
        report = {
            "security_score": 82,
            "total_issues": 1,
            "findings": [{
                "rule_id": "TEST-001",
                "severity": "HIGH",
                "title": "<script>alert(1)</script>",
                "file_path": "src/<unsafe>.py",
                "line_number": 3,
                "snippet": "<img src=x>",
                "fix_prompt": "Fix & review",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            json_path = Path(temporary_directory) / "report.json"
            html_path = Path(temporary_directory) / "report.html"
            export_json_report(report, json_path)
            export_html_report(report, "<project>", html_path)

            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), report)
            document = html_path.read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", document)
            self.assertNotIn("<script>alert(1)</script>", document)
            self.assertIn("&lt;project&gt;", document)


if __name__ == "__main__":
    unittest.main()
