import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QBoxLayout
from PyQt6.QtTest import QTest

from src.gui import ProtoSecWindow, asset_path


class GuiResponsiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_narrow_window_reflows_and_scrolls_content(self):
        window = ProtoSecWindow()
        window.show()
        for width, sidebar_visible in ((800, False), (1024, True), (1320, True)):
            with self.subTest(width=width):
                window.resize(width, 600)
                self.application.processEvents()

                self.assertEqual(not window.sidebar.isHidden(), sidebar_visible)
                self.assertGreater(window.main_scroll_area.viewport().height(), 0)
                self.assertGreater(window.path_input.width(), 200)
                if width == 800:
                    self.assertGreater(window.main_scroll_area.verticalScrollBar().maximum(), 0)
                expected_direction = (
                    QBoxLayout.Direction.TopToBottom
                    if width < 1180
                    else QBoxLayout.Direction.LeftToRight
                )
                self.assertEqual(window.topbar_layout.direction(), expected_direction)
                self.assertEqual(
                    window.findings_header_layout.direction(),
                    QBoxLayout.Direction.TopToBottom
                    if width < 1100
                    else QBoxLayout.Direction.LeftToRight,
                )
                for layout in (window.topbar_layout, window.findings_header_layout):
                    first = layout.itemAt(0).geometry()
                    second = layout.itemAt(1).geometry()
                    self.assertFalse(first.intersects(second))

        window.close()

    def test_asset_path_resolves_bundled_and_adjacent_assets(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            bundle = root / "_MEIPASS"
            bundled_asset = bundle / "assets" / "shield-check.svg"
            bundled_asset.parent.mkdir(parents=True)
            bundled_asset.write_text("bundled", encoding="utf-8")
            executable_dir = root / "dist"
            adjacent_asset = executable_dir / "assets" / "shield-check.svg"
            adjacent_asset.parent.mkdir(parents=True)
            adjacent_asset.write_text("adjacent", encoding="utf-8")
            with (
                mock.patch.object(sys, "_MEIPASS", str(bundle), create=True),
                mock.patch.object(sys, "frozen", True, create=True),
                mock.patch.object(sys, "executable", str(executable_dir / "ProtoSec.exe")),
            ):
                self.assertEqual(asset_path("shield-check.svg"), bundled_asset)
                bundled_asset.unlink()
                self.assertEqual(asset_path("shield-check.svg"), adjacent_asset)

    def test_optional_scan_and_live_guard_controls_start_disabled(self):
        window = ProtoSecWindow()
        self.assertFalse(window.scan_cve_checkbox.isChecked())
        self.assertFalse(window.live_guard_checkbox.isChecked())
        self.assertFalse(window.live_guard_action.isChecked())
        self.assertFalse(window.package_reputation_action.isChecked())
        self.assertFalse(window.history_scan_action.isChecked())
        self.assertIn("pre-commit", window.install_hook_action.text())
        self.assertIn("headers", window.probe_headers_action.text().lower())

        window.live_guard_checkbox.setChecked(True)
        self.application.processEvents()
        self.assertFalse(window.live_guard_checkbox.isChecked())
        self.assertFalse(window.live_guard_action.isChecked())
        window.close()

    def test_live_guard_watches_project_sources_and_stops_cleanly(self):
        with tempfile.TemporaryDirectory() as project:
            source_file = Path(project) / "app.py"
            requirements_file = Path(project) / "requirements.txt"
            source_file.write_text("print('hello')\n", encoding="utf-8")
            requirements_file.write_text("requests==2.31.0\n", encoding="utf-8")
            window = ProtoSecWindow()
            window._set_target_folder(Path(project))
            window.live_guard_checkbox.setChecked(True)
            for _ in range(100):
                self.application.processEvents()
                if str(source_file) in window.file_watcher.files():
                    break
                QTest.qWait(20)

            self.assertIn(str(source_file), window.file_watcher.files())
            self.assertIn(str(requirements_file), window.file_watcher.files())
            self.assertIn(project, window.file_watcher.directories())

            window.live_guard_checkbox.setChecked(False)
            self.assertEqual(window.file_watcher.files(), [])
            self.assertEqual(window.file_watcher.directories(), [])
            window.close()

    def test_live_guard_copies_a_finding_prompt_to_the_clipboard(self):
        window = ProtoSecWindow()
        window.tray_icon.setVisible(False)
        window.findings = [{"fix_prompt": "Use a parameterized query."}]
        window._live_scan_in_progress = True

        window._notify_live_findings()

        self.assertEqual(
            self.application.clipboard().text(),
            "Use a parameterized query.",
        )
        self.assertFalse(window._live_scan_in_progress)
        window.close()


if __name__ == "__main__":
    unittest.main()
