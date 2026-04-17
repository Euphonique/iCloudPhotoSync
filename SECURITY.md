# Security

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately rather than opening a public issue. Email the maintainer directly with a description of the issue, steps to reproduce, and any relevant files or line numbers.

## Architecture Overview

iCloudPhotoSync is a Synology DSM package consisting of:

- **Python 3 CGI backend** (`ui/api.cgi`, `webapi/iCloudPhotoSync.cgi`) serving JSON responses
- **Apple iCloud authentication** via vendored SRP + pyicloud libraries (`lib/vendor/`)
- **SQLite manifest database** for sync state tracking (`lib/sync_manifest.py`)
- **Background subprocess runners** for sync/move operations (`bin/`)
- **File-based config and credential storage** under `/var/packages/iCloudPhotoSync/var/`

The package runs as an unprivileged Synology system user (`iCloudPhotoSync`), not root.

---

## Security Controls

### Authorization & Access Control

Every API handler that accepts an `account_id` parameter verifies ownership via `lib/handlers/authz.py`:

- The DSM username of the requesting user is resolved from environment variables or the session cookie.
- The first DSM user to create or authenticate an account is recorded as its **owner**.
- Subsequent requests from a different DSM user are rejected with HTTP 403.
- The account list endpoint filters results to only show accounts owned by the requesting user.
- Legacy accounts (created before the ownership system) are auto-stamped to the first user who accesses them.

### Credential Handling

| Credential | Storage | Protection |
|---|---|---|
| Apple ID password (during 2FA) | Encrypted file in per-account directory | HMAC-SHA256 stream cipher with per-installation secret key; file permissions `0600` |
| iCloud session tokens | JSON files in per-account directory | Directory permissions `0700`; per-installation secret stored separately at `$PKG_VAR/.install_secret` |
| DSM session ID | Environment variable (CGI) | Never written to disk by this package; resolved server-side via localhost API |

**Pending password lifecycle:**

1. User submits Apple ID + password → password encrypted with a 16-byte random nonce and HMAC-SHA256 derived keystream, then written to `.pending_pw`
2. User completes 2FA verification → `.pending_pw` deleted immediately
3. If 2FA is abandoned, the encrypted file persists until the account is removed

The per-installation encryption key (`$PKG_VAR/.install_secret`, 32 bytes, `0600`) is generated on first use and stored outside per-account directories so compromising an account directory alone does not reveal the password.

### Account Identifiers

New account IDs use full UUID4 values (128-bit entropy). Legacy 8-character hex IDs from earlier versions are still accepted but not generated. Both formats are validated by `config_manager.validate_account_id()` which rejects any value containing path separators or traversal sequences.

### Input Validation

**CGI parameters:**
- All `account_id`, `action`, and configuration parameters are stripped and validated before use.
- `account_id` is regex-validated against UUID4 or legacy hex format before being used in any filesystem path, preventing path traversal.
- Log and album pagination parameters (`start`, `limit`, `offset`) are bounded: offset ≥ 0, limit clamped to 1–500. Invalid/non-integer values fall back to safe defaults.

**SQL:**
- All queries in `lib/sync_manifest.py` use parameterized statements (`?` placeholders). No string interpolation in SQL.

**Filenames:**
- `_safe_filename()` in `ui/api.cgi` strips NUL bytes, control characters (`\x00–\x1f`, `\x7f–\x9f`), path separators, and shell metacharacters (`` ;|&$`*?!<>'"(){}[] ``).
- Filenames are truncated to 255 UTF-8 bytes (ext4/btrfs filesystem limit).

**URLs (SSRF prevention):**
- Proxy and download endpoints validate URLs via `urlparse()`, requiring `scheme` to be `http` or `https` and `hostname` to end with `.icloud-content.com` or `.icloud.com`. Substring-based checks are not used.

### File System Security

**Symlink protection:**
- `sync_engine._download_file()` resolves destinations via `os.path.realpath()` before writing and rejects paths that escape the target directory.
- `move_engine.run_move()` resolves both old and new directories via `os.path.realpath()` before iterating files.

**Path traversal:**
- `config_manager.validate_account_id()` rejects account IDs that aren't UUID/hex, preventing `../../` injection into `os.path.join(ACCOUNTS_DIR, account_id)`.
- `config_manager.get_account_dir()` calls `validate_account_id()` and raises `ValueError` on invalid input.
- Move operations validate that source paths start with the expected old directory prefix after realpath resolution.

**Atomic writes:**
- Config and progress files use temp-file + `fsync()` + `os.replace()` to prevent corruption from concurrent reads.
- Photo downloads write to `.part` files, then rename on completion.

### Subprocess Execution

All subprocess calls use **list-style arguments** (never `shell=True`):

```python
subprocess.Popen([sys.executable, runner, account_id], ...)
subprocess.run([convert_bin, heic_path, "-quality", str(quality), jpg_path], ...)
```

`stdin` is set to `subprocess.DEVNULL` on background runners. No user input is interpolated into command strings.

### Error Handling

- CGI entrypoints (`api.cgi`, `iCloudPhotoSync.cgi`) return generic `"Internal server error"` messages to clients on unhandled exceptions.
- All handler-level `except` blocks return fixed error strings (e.g. `"Failed to list albums"`); `str(e)` is never sent to the client.
- Detailed exception information is logged server-side only.
- Internal path references (e.g., unresolved home directories) are not exposed in API responses.

### Concurrency

- File-based locking (`fcntl.flock`) + thread locks prevent concurrent config corruption.
- Per-account sync locks prevent parallel sync runs for the same account.
- SQLite uses WAL mode with timeouts for concurrent access.

---

## Known Limitations

| Area | Limitation | Mitigation |
|---|---|---|
| Session tokens at rest | Stored as JSON, not encrypted | Protected by directory permissions (`0700`) and OS-level access controls |
| CSRF protection | No anti-CSRF tokens in API handlers | DSM's own session management provides some protection; app is internal-network-only by design |
| Rate limiting | No brute-force protection on login endpoint | DSM's built-in auto-block feature covers this at the network layer |
| Log isolation | Sync logs are shared across all accounts on the same NAS | Log entries do not contain credentials; access requires DSM authentication |
| Vendored dependencies | SRP and pyicloud_ipd are bundled, not updated via pip | Manual updates required; track upstream security advisories |

---

## Dependency Inventory

| Dependency | Version | Source | Notes |
|---|---|---|---|
| `pyicloud_ipd` | Vendored (based on icloudpd v1.32.2) | `lib/vendor/pyicloud_ipd/` | iCloud API client with SRP auth |
| `srp` | Vendored | `lib/vendor/srp/` | Secure Remote Password protocol |
| `six` | Vendored | `lib/vendor/six.py` | Python 2/3 compatibility (SRP dependency) |
| `requests` | System/pip | `requirements.txt` | HTTP client for iCloud API |
| `keyring` | System/pip | `requirements.txt` | Listed but not currently used |

---

## File Permissions Summary

| Path | Permissions | Contents |
|---|---|---|
| `$PKG_VAR/.install_secret` | `0600` | 32-byte encryption key |
| `$PKG_VAR/accounts/<id>/` | `0700` | Session tokens, config, progress |
| `$PKG_VAR/accounts/<id>/.pending_pw` | `0600` | Encrypted pending password |
| `$PKG_VAR/config.json` | `0644` | Global config (no secrets) |
| Sync target directories | `0755` | Downloaded photos |
| Downloaded photo files | `0644` | User photo data |
