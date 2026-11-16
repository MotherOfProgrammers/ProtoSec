import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from utils.passive_probe import probe_security_headers


class PassiveProbeTests(unittest.TestCase):
    def test_uses_one_head_request_without_fetching_a_body(self):
        state = {"heads": 0, "gets": 0}

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                state["heads"] += 1
                self.send_response(200)
                self.send_header("Content-Security-Policy", "default-src 'self'")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("RateLimit-Limit", "60")
                self.end_headers()

            def do_GET(self):
                state["gets"] += 1
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"must not be fetched")

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = probe_security_headers(f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertEqual(state, {"heads": 1, "gets": 0})
        self.assertFalse(result["body_fetched"])
        self.assertEqual(result["rate_limit_headers"]["RateLimit-Limit"], "60")
        csp = next(item for item in result["checks"] if item["header"] == "Content-Security-Policy")
        self.assertTrue(csp["present"])
        self.assertFalse(result["rate_limit_enforcement_tested"])

    def test_external_host_requires_explicit_authorization(self):
        with self.assertRaises(PermissionError):
            probe_security_headers("https://example.test")

    def test_rejects_paths_and_query_strings(self):
        with self.assertRaises(ValueError):
            probe_security_headers("http://localhost:3000/api?table=users")


if __name__ == "__main__":
    unittest.main()
