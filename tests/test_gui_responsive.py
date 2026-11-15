import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QBoxLayout

from src.gui import ProtoSecWindow


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


if __name__ == "__main__":
    unittest.main()
