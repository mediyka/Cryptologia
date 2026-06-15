# Windows install fix

If Windows shows this error:

```text
Building wheel for argon2 ...
Microsoft Visual C++ 14.0 or greater is required
```

it means the old PyPI package named `argon2` is being built from source. The
project uses `argon2-cffi`, but on very new Python versions pip/user commands can
still end up attempting the wrong package.

Use `INSTALL_WINDOWS.bat` first. It installs only runtime dependencies and skips
Argon2 installation. CryptoSafeManager will still run and will use a PBKDF2
password-verification fallback. Vault encryption remains PBKDF2-derived
AES-256-GCM.

For full Sprint 2 Argon2id compliance, install Python 3.12 x64 and run
`INSTALL_FULL_SECURITY_WINDOWS.bat`.
