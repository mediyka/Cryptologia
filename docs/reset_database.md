# Resetting the local database

Use `RESET_DATABASE.bat` on Windows to reset the local CryptoSafeManager vault.

What it resets:

- vault entries;
- master password data stored in SQLite;
- audit log;
- import/export history;
- SQLite settings stored inside the vault database.

The script does not delete source code or the virtual environment. It moves existing database files to:

```text
%USERPROFILE%\.cryptosafe\reset_backups\<timestamp>\
```

After reset, run `RUN_WINDOWS.bat` or `python run.py`. The app should open the first-run setup wizard so you can create a new master password and vault.
