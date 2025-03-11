#!/usr/bin/env python3

import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QFileDialog, QTabWidget
)
from PySide6.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MachO Analyzer")
        self.setMinimumSize(800, 600)
        
        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Основной layout
        layout = QVBoxLayout(central_widget)
        
        # Панель инструментов
        toolbar = QHBoxLayout()
        self.open_button = QPushButton("Open File")
        self.open_button.clicked.connect(self.open_file)
        toolbar.addWidget(self.open_button)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        # Вкладки для разных видов анализа
        self.tabs = QTabWidget()
        self.tabs.addTab(QWidget(), "Headers")
        self.tabs.addTab(QWidget(), "Segments")
        self.tabs.addTab(QWidget(), "Imports/Exports")
        self.tabs.addTab(QWidget(), "Security")
        self.tabs.addTab(QWidget(), "Patterns")
        layout.addWidget(self.tabs)
        
    def open_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Open MachO File",
            "",
            "MachO Files (*.dylib *.bundle *.o);;All Files (*)"
        )
        if file_name:
            # TODO: Implement file analysis
            pass

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main() 