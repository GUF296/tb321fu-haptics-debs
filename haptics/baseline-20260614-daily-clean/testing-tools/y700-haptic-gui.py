#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import os
import subprocess
import sys

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSlider,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


HELPER = "/usr/local/bin/y700-haptic-test"


class HapticWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Y700 Haptics")
        self.setMinimumSize(600, 420)
        self.process = None

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("Y700 Haptics")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Sans Serif", 18, QFont.Bold))
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        layout.addWidget(tabs, 1)

        short_page, short_layout = self.make_scroll_page()
        tabs.addTab(short_page, "Short Clicks")
        preset_grid = QGridLayout()
        preset_grid.setSpacing(10)
        short_layout.addLayout(preset_grid)

        presets = [
            ("Light", ["both", "10", "42000", "4", "60"]),
            ("Key Tap", ["both", "13", "65535", "5", "65"]),
            ("Confirm", ["both", "24", "60000", "2", "90"]),
            ("Notify", ["both", "45", "62000", "3", "120"]),
            ("Left", ["left", "30", "60000", "2", "120"]),
            ("Right", ["right", "30", "60000", "2", "120"]),
            ("Soft", ["both", "13", "32000", "4", "65"]),
            ("Strong", ["both", "13", "65535", "4", "65"]),
        ]
        for index, (label, args) in enumerate(presets):
            button = self.make_button(label)
            button.clicked.connect(lambda checked=False, a=args: self.run_helper(a))
            preset_grid.addWidget(button, index // 2, index % 2)
        short_layout.addStretch(1)

        hold_page, hold_layout = self.make_scroll_page()
        tabs.addTab(hold_page, "Long Hold")
        hold_grid = QGridLayout()
        hold_grid.setSpacing(10)
        hold_layout.addLayout(hold_grid)

        hold_presets = [
            ("Rumble 1s", ["both", "1000", "65535", "1", "65"]),
            ("Rumble 5s", ["both", "5000", "65535", "1", "65"]),
            ("Constant 1s", ["constant", "1000", "65535", "1", "65"]),
            ("Constant 5s", ["constant", "5000", "65535", "1", "65"]),
            ("Periodic 1s", ["periodic", "1000", "65535", "6", "1", "65"]),
            ("Periodic 5s", ["periodic", "5000", "65535", "6", "1", "65"]),
        ]
        for index, (label, args) in enumerate(hold_presets):
            button = self.make_button(label)
            button.clicked.connect(lambda checked=False, a=args: self.run_helper(a))
            hold_grid.addWidget(button, index // 2, index % 2)
        hold_layout.addStretch(1)

        custom_page, custom_layout = self.make_scroll_page()
        tabs.addTab(custom_page, "Custom")

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        custom_layout.addWidget(line)

        custom = QGridLayout()
        custom.setHorizontalSpacing(12)
        custom.setVerticalSpacing(10)
        custom_layout.addLayout(custom)

        self.target_group = QButtonGroup(self)
        row = QHBoxLayout()
        for text, value, checked in [
            ("Both", "both", True),
            ("Left", "left", False),
            ("Right", "right", False),
        ]:
            rb = QRadioButton(text)
            rb.setProperty("value", value)
            rb.setChecked(checked)
            rb.setMinimumHeight(42)
            self.target_group.addButton(rb)
            row.addWidget(rb)
        custom.addWidget(QLabel("Target"), 0, 0)
        custom.addLayout(row, 0, 1, 1, 3)

        self.duration = self.add_slider(custom, 1, "Duration ms", 5, 10000, 13)
        self.magnitude = self.add_slider(custom, 2, "Magnitude", 1000, 65535, 65535)

        self.repeats = QSpinBox()
        self.repeats.setRange(1, 20)
        self.repeats.setValue(5)
        self.repeats.setMinimumHeight(42)
        custom.addWidget(QLabel("Repeats"), 3, 0)
        custom.addWidget(self.repeats, 3, 1)

        self.gap = QSpinBox()
        self.gap.setRange(20, 1000)
        self.gap.setValue(65)
        self.gap.setSuffix(" ms")
        self.gap.setMinimumHeight(42)
        custom.addWidget(QLabel("Gap"), 3, 2)
        custom.addWidget(self.gap, 3, 3)

        custom_button = self.make_button("Custom Test")
        custom_button.clicked.connect(self.run_custom)
        custom_layout.addWidget(custom_button)
        custom_layout.addStretch(1)

        self.status = QLabel("Ready")
        self.status.setAlignment(Qt.AlignCenter)
        self.status.setMinimumHeight(34)
        layout.addWidget(self.status)

        self.setCentralWidget(root)

        if not os.path.exists(HELPER):
            QTimer.singleShot(200, self.show_missing_helper)

    def make_scroll_page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(4, 8, 4, 8)
        page_layout.setSpacing(12)
        scroll.setWidget(page)
        return scroll, page_layout

    def make_button(self, label):
        button = QPushButton(label)
        button.setMinimumHeight(56)
        button.setFont(QFont("Sans Serif", 14, QFont.Bold))
        return button

    def add_slider(self, layout, row, label, minimum, maximum, value):
        slider = QSlider(Qt.Horizontal)
        slider.setRange(minimum, maximum)
        slider.setValue(value)
        slider.setMinimumHeight(42)

        value_label = QLabel(str(value))
        value_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        value_label.setMinimumWidth(70)
        slider.valueChanged.connect(lambda v: value_label.setText(str(v)))

        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(slider, row, 1, 1, 2)
        layout.addWidget(value_label, row, 3)
        return slider

    def show_missing_helper(self):
        QMessageBox.critical(self, "Y700 Haptic Test", f"Missing helper: {HELPER}")

    def run_custom(self):
        checked = self.target_group.checkedButton()
        target = checked.property("value") if checked else "both"
        self.run_helper([
            target,
            str(self.duration.value()),
            str(self.magnitude.value()),
            str(self.repeats.value()),
            str(self.gap.value()),
        ])

    def run_helper(self, args):
        if self.process and self.process.poll() is None:
            self.status.setText("Busy")
            return

        command = [HELPER] + args
        self.status.setText("Running: " + " ".join(args))
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            self.status.setText("Error")
            QMessageBox.critical(self, "Y700 Haptic Test", str(exc))
            return

        QTimer.singleShot(80, self.poll_process)

    def poll_process(self):
        if not self.process:
            return
        rc = self.process.poll()
        if rc is None:
            QTimer.singleShot(80, self.poll_process)
            return

        stdout, stderr = self.process.communicate()
        self.process = None
        if rc == 0:
            self.status.setText("Done")
            return

        self.status.setText(f"Failed ({rc})")
        QMessageBox.critical(self, "Y700 Haptic Test", (stderr or stdout or "Unknown error").strip())


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(
        """
        QWidget { font-size: 15px; }
        QPushButton {
            border: 1px solid #8a8f98;
            border-radius: 8px;
            padding: 8px 12px;
            background: #f4f6f8;
        }
        QPushButton:pressed { background: #dfe7ef; }
        QLabel { color: #20242a; }
        QRadioButton { font-size: 16px; }
        """
    )
    win = HapticWindow()
    win.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
