import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.mcp_server import scan_project, verify_fix


class McpServerTests(unittest.TestCase):
    def test_scan_project_and_verify_fix_use_local_scan_results(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "app.py"
            source.write_text("value = 1\n", encoding="utf-8")
            clean_report = scan_project(str(root))
            self.assertEqual(clean_report["total_issues"], 0)
            self.assertTrue(verify_fix(str(root))["verified"])

            source.write_text("api_key = 'sk-" + "a" * 40 + "'\n", encoding="utf-8")
            result = verify_fix(str(root))

        self.assertFalse(result["verified"])
        self.assertTrue(result["remaining_findings"])

    def test_stdio_protocol_exposes_only_the_two_local_tools(self):
        process = subprocess.Popen(
            [sys.executable, "-m", "src.main", "--mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            shell=False,
        )
        try:
            self._send(process, {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "ProtoSec test", "version": "1"},
                },
            })
            initialized = json.loads(process.stdout.readline())
            self.assertEqual(initialized["result"]["serverInfo"]["name"], "ProtoSec")
            self._send(process, {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            })
            self._send(process, {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            })
            listed = json.loads(process.stdout.readline())
            self.assertEqual(
                {tool["name"] for tool in listed["result"]["tools"]},
                {"scan_project", "verify_fix"},
            )
        finally:
            if process.stdin:
                process.stdin.close()
            process.wait(timeout=10)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    @staticmethod
    def _send(process, message):
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()


if __name__ == "__main__":
    unittest.main()
