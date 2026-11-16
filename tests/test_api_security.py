import asyncio
import sys
import types
import unittest
from unittest import mock

from src.main import (
    RepositoryUrlError,
    ScanRequest,
    _communicate_with_timeout,
    _validate_repository_url,
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
