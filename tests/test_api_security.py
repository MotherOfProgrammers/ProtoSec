import asyncio
import ipaddress
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from src.main import (
    CloneLimitError,
    MAX_CLONE_SIZE_BYTES,
    RepositoryUrlError,
    ScanRequest,
    _clone_repository,
    _communicate_with_timeout,
    _directory_size,
    _validate_repository_url,
    _validate_repository_host,
    main,
    trigger_scan,
)


class ApiSecurityTests(unittest.TestCase):
    def test_only_accepts_public_https_repository_urls(self):
        self.assertEqual(
            _validate_repository_url("https://github.com/example/project.git"),
            "https://github.com/example/project.git",
        )
        for value in (
            "http://github.com/example/project.git",
            "file:///C:/Users/example/private",
            "https://user:password@github.com/example/project.git",
            "https://github.com/example/project.git?token=secret",
            "https://localhost/repo.git",
            "https://127.0.0.1/repo.git",
            "https://example.com:8443/repo.git",
        ):
            with self.subTest(value=value), self.assertRaises(RepositoryUrlError):
                _validate_repository_url(value)

    def test_rejects_invalid_url_before_starting_a_clone(self):
        async def run():
            with mock.patch("src.main.asyncio.create_subprocess_exec") as create_process:
                with self.assertRaises(RepositoryUrlError):
                    await trigger_scan(ScanRequest(repo_url="file:///private"))
            create_process.assert_not_called()

        asyncio.run(run())

    def test_repository_host_must_resolve_only_to_public_addresses(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))
        with mock.patch("src.main.socket.getaddrinfo", return_value=[public]):
            self.assertEqual(
                _validate_repository_host("example.com"),
                {ipaddress.ip_address("93.184.216.34")},
            )
        for results in ([private], [public, private], []):
            with (
                self.subTest(results=results),
                mock.patch("src.main.socket.getaddrinfo", return_value=results),
                self.assertRaises(RepositoryUrlError),
            ):
                _validate_repository_host("example.com")

    def test_private_dns_resolution_is_rejected_before_clone(self):
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))

        async def run():
            with (
                mock.patch("src.main.socket.getaddrinfo", return_value=[private]),
                mock.patch("src.main.asyncio.create_subprocess_exec") as create_process,
                self.assertRaises(RepositoryUrlError),
            ):
                await trigger_scan(ScanRequest(repo_url="https://repo.example/project.git"))
            create_process.assert_not_called()

        asyncio.run(run())

    def test_dns_resolution_timeout_happens_before_clone(self):
        async def run():
            with (
                mock.patch(
                    "src.main.asyncio.to_thread",
                    new=mock.AsyncMock(side_effect=asyncio.TimeoutError),
                ),
                mock.patch("src.main.asyncio.create_subprocess_exec") as create_process,
                self.assertRaisesRegex(TimeoutError, "DNS resolution"),
            ):
                await trigger_scan(ScanRequest(repo_url="https://repo.example/project.git"))
            create_process.assert_not_called()

        asyncio.run(run())

    def test_clone_disables_redirects_and_enforces_directory_size_limit(self):
        class FakeProcess:
            def __init__(self, complete_immediately=False):
                self.returncode = 0 if complete_immediately else None
                self.killed = False
                self.finished = asyncio.Event()
                if complete_immediately:
                    self.finished.set()

            async def communicate(self):
                await self.finished.wait()
                return b"", b""

            def kill(self):
                self.killed = True
                self.returncode = -9
                self.finished.set()

            async def wait(self):
                return self.returncode

        async def run():
            with tempfile.TemporaryDirectory() as destination:
                complete = FakeProcess(complete_immediately=True)
                with (
                    mock.patch(
                        "src.main.asyncio.create_subprocess_exec",
                        new=mock.AsyncMock(return_value=complete),
                    ) as create_process,
                    mock.patch("src.main._directory_size", return_value=0),
                ):
                    await _clone_repository(
                        "https://example.com/repo.git",
                        destination,
                    )
                self.assertEqual(create_process.call_args.args[:3], (
                    "git",
                    "-c",
                    "http.followRedirects=false",
                ))

            with tempfile.TemporaryDirectory() as destination:
                oversized = FakeProcess()
                with (
                    mock.patch(
                        "src.main.asyncio.create_subprocess_exec",
                        new=mock.AsyncMock(return_value=oversized),
                    ),
                    mock.patch("src.main._directory_size", return_value=MAX_CLONE_SIZE_BYTES + 1),
                    mock.patch("src.main.CLONE_SIZE_CHECK_INTERVAL_SECONDS", 0.01),
                ):
                    with self.assertRaises(CloneLimitError):
                        await _clone_repository(
                            "https://example.com/repo.git",
                            destination,
                        )
                self.assertTrue(oversized.killed)

        asyncio.run(run())

    def test_directory_size_ignores_symlink_targets(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "payload.bin").write_bytes(b"0123456789")
            target = root / "outside.bin"
            target.write_bytes(b"x" * 100)
            try:
                (root / "linked.bin").symlink_to(target)
            except OSError:
                self.skipTest("Symlinks are unavailable for this account.")

            self.assertEqual(_directory_size(root), 110)

    def test_api_server_binds_to_loopback_by_default(self):
        uvicorn = types.SimpleNamespace(run=mock.Mock())
        app = object()
        with (
            mock.patch("src.main.create_app", return_value=app),
            mock.patch.dict(sys.modules, {"uvicorn": uvicorn}),
        ):
            self.assertEqual(main(["--serve"]), 0)

        uvicorn.run.assert_called_once_with(app, host="127.0.0.1", port=8000)

    def test_timeout_terminates_the_child_process(self):
        class FakeProcess:
            killed = False
            returncode = None

            async def communicate(self):
                await asyncio.Event().wait()

            def kill(self):
                self.killed = True
                self.returncode = -9

            async def wait(self):
                return self.returncode

        async def run():
            process = FakeProcess()
            with self.assertRaisesRegex(TimeoutError, "exceeded its 0-second limit"):
                await _communicate_with_timeout(process, 0, "Clone")
            return process

        process = asyncio.run(run())
        self.assertTrue(process.killed)


if __name__ == "__main__":
    unittest.main()
