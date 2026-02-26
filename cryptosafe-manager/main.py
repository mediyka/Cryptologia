#!/usr/bin/env python3
"""
Точка входа в приложение CryptoSafe Manager.
"""
from src.gui.main_window import MainWindow


def main():
    """Запускает приложение."""
    app = MainWindow()
    app.run()


if __name__ == "__main__":
    main()
