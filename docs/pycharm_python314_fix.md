# PyCharm / Python 3.14 package fix

If PyCharm shows an error like:

```text
ERROR: No matching distribution found for pyinstaller==6.0.0
Interpreter path: ... Python314\python.exe
```

then PyCharm is trying to install an old pinned PyInstaller version (`6.0.0`).
That version declares incompatible Python ranges for very new Python versions.

For running the app, PyInstaller is not required. Use:

```bat
INSTALL_WINDOWS.bat
```

For building an `.exe`, use:

```bat
INSTALL_BUILD_WINDOWS.bat
python build.py
```

Do not install `pyinstaller==6.0.0` manually. Install the latest compatible version:

```bat
python -m pip install --upgrade pyinstaller
```
