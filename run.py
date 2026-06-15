import os
import sys


def main():
    """Запустить CryptoSafe Manager из исходного кода."""
    project_root = os.path.abspath(os.path.dirname(__file__))
    src_path = os.path.join(project_root, "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from core.config import ConfigManager
    from gui.main_window import MainWindow

    app = MainWindow(config=ConfigManager())
    app.mainloop()


if __name__ == "__main__":
    main()
