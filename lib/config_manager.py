"""
Config Manager — reads/writes JSON config for iCloud Photo Sync.

Config is stored at /var/packages/iCloudPhotoSync/var/config.json
Per-account data is in /var/packages/iCloudPhotoSync/var/accounts/{account_id}/
"""
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import uuid

try:
    import fcntl
except ImportError:  # Windows dev boxes
    fcntl = None

# Regex for valid account IDs (full UUID4, lowercase hex + hyphens)
_ACCOUNT_ID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
# Also accept legacy 8-char truncated IDs from before this hardening
_LEGACY_ACCOUNT_ID_RE = re.compile(r'^[0-9a-f]{8}$')


def validate_account_id(account_id):
    """Return True if account_id is a safe, valid identifier.

    Prevents path traversal by rejecting anything that isn't a UUID or
    legacy 8-char hex string.
    """
    if not account_id or not isinstance(account_id, str):
        return False
    return bool(_ACCOUNT_ID_RE.match(account_id) or _LEGACY_ACCOUNT_ID_RE.match(account_id))

_config_tlock = threading.Lock()

PKG_VAR = os.environ.get(
    "SYNOPKG_PKGVAR",
    "/var/packages/iCloudPhotoSync/var"
)

CONFIG_FILE = os.path.join(PKG_VAR, "config.json")
ACCOUNTS_DIR = os.path.join(PKG_VAR, "accounts")


def _ensure_dirs():
    os.makedirs(PKG_VAR, exist_ok=True)
    os.makedirs(ACCOUNTS_DIR, exist_ok=True)


def atomic_write_json(path, data, indent=None):
    """Write JSON to path atomically: temp file + fsync + rename.

    Multiple CGI handlers and the scheduler can hit the same JSON file
    concurrently. A direct overwrite leaves a window where another reader
    sees a truncated or empty file. os.replace is atomic on POSIX.
    """
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        if indent is not None:
            json.dump(data, f, indent=indent)
        else:
            json.dump(data, f)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


@contextlib.contextmanager
def _locked(lock_path):
    """Serialise read-modify-write cycles across threads AND processes.

    Two accounts updating different fields of config.json concurrently would
    otherwise produce lost updates: both read the same base, each writes back
    its own change, second writer wins. The threading.Lock covers in-process
    parallel scheduler threads; fcntl.flock covers CGI handlers running in
    sibling processes.
    """
    _ensure_dirs()
    _config_tlock.acquire()
    fd = None
    try:
        if fcntl is not None:
            try:
                fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    fd = None
        yield
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass
        _config_tlock.release()


def load_config():
    _ensure_dirs()
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            # Corrupted (e.g. concurrent write before atomic_write_json
            # was introduced). Fall back to defaults rather than crash.
            pass
    return {"accounts": [], "log_level": "INFO"}


def save_config(config):
    _ensure_dirs()
    atomic_write_json(CONFIG_FILE, config, indent=2)


def get_accounts():
    config = load_config()
    return config.get("accounts", [])


def get_account(account_id):
    for acc in get_accounts():
        if acc["id"] == account_id:
            return acc
    return None


def add_account(apple_id):
    with _locked(CONFIG_FILE + ".lock"):
        config = load_config()
        account_id = str(uuid.uuid4())
        account = {
            "id": account_id,
            "apple_id": apple_id,
            "status": "pending_2fa",
            "photo_count": 0,
            "added": None,
        }
        config.setdefault("accounts", []).append(account)
        save_config(config)

    # Create per-account directory for session data
    account_dir = os.path.join(ACCOUNTS_DIR, account_id)
    os.makedirs(account_dir, mode=0o700, exist_ok=True)

    return account


def update_account(account_id, updates):
    with _locked(CONFIG_FILE + ".lock"):
        config = load_config()
        for acc in config.get("accounts", []):
            if acc["id"] == account_id:
                acc.update(updates)
                save_config(config)
                return acc
    return None


def remove_account(account_id):
    with _locked(CONFIG_FILE + ".lock"):
        config = load_config()
        accounts = config.get("accounts", [])
        config["accounts"] = [a for a in accounts if a["id"] != account_id]
        save_config(config)

    # Clean up per-account directory
    import shutil
    account_dir = os.path.join(ACCOUNTS_DIR, account_id)
    if os.path.isdir(account_dir):
        shutil.rmtree(account_dir, ignore_errors=True)


def get_account_dir(account_id):
    if not validate_account_id(account_id):
        raise ValueError("Invalid account_id: %r" % account_id)
    return os.path.join(ACCOUNTS_DIR, account_id)


# --- Temporary password storage for pending 2FA ---
# Stored in the per-account directory, cleared after successful auth.

# --- Per-installation secret for encrypting transient credentials ---

def _secret_path():
    return os.path.join(PKG_VAR, ".install_secret")


def _get_install_secret():
    """Return or create a 32-byte per-installation secret.

    Stored outside per-account directories so compromising account data
    alone does not reveal the encryption key.
    """
    path = _secret_path()
    _ensure_dirs()
    if os.path.isfile(path):
        with open(path, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def _encrypt_password(password):
    """Encrypt with HMAC-SHA256 derived XOR stream.

    Not a full AES cipher, but sufficient for short-lived transient
    storage (password is deleted after 2FA completes). The nonce
    ensures repeated encryptions produce different ciphertexts.
    """
    key = _get_install_secret()
    nonce = secrets.token_bytes(16)
    pw_bytes = password.encode("utf-8")
    # Derive a keystream long enough to cover the password
    stream = b""
    counter = 0
    while len(stream) < len(pw_bytes):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        stream += block
        counter += 1
    encrypted = bytes(a ^ b for a, b in zip(pw_bytes, stream[:len(pw_bytes)]))
    # Format: nonce (16) + encrypted_password
    return nonce + encrypted


def _decrypt_password(data):
    """Decrypt a password encrypted by _encrypt_password."""
    if not data or len(data) < 17:
        return None
    key = _get_install_secret()
    nonce = data[:16]
    encrypted = data[16:]
    stream = b""
    counter = 0
    while len(stream) < len(encrypted):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        stream += block
        counter += 1
    pw_bytes = bytes(a ^ b for a, b in zip(encrypted, stream[:len(encrypted)]))
    try:
        return pw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # Decrypted bytes aren't valid UTF-8 — the file was likely written
        # before encryption was added (plaintext legacy) and the XOR
        # produced garbage. Return None so the caller falls back.
        return None


def save_pending_password(account_id, password):
    """Encrypt and store password temporarily while waiting for 2FA."""
    acc_dir = get_account_dir(account_id)
    pw_file = os.path.join(acc_dir, ".pending_pw")
    os.makedirs(acc_dir, mode=0o700, exist_ok=True)
    encrypted = _encrypt_password(password)
    fd = os.open(pw_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, encrypted)
        os.fsync(fd)
    finally:
        os.close(fd)


def get_pending_password(account_id):
    """Retrieve and decrypt temporarily stored password, or None."""
    acc_dir = get_account_dir(account_id)
    pw_file = os.path.join(acc_dir, ".pending_pw")
    if not os.path.isfile(pw_file):
        return None
    with open(pw_file, "rb") as f:
        data = f.read()
    # Support legacy plaintext files from before encryption was added.
    # _decrypt_password returns None if decryption produces invalid UTF-8
    # (i.e. the file wasn't actually encrypted).
    result = _decrypt_password(data)
    if result is not None:
        return result
    # Fallback: treat as plaintext (legacy)
    return data.decode("utf-8", errors="replace")


def clear_pending_password(account_id):
    """Remove temporarily stored password."""
    acc_dir = get_account_dir(account_id)
    pw_file = os.path.join(acc_dir, ".pending_pw")
    try:
        os.remove(pw_file)
    except FileNotFoundError:
        pass


# --- Per-account sync configuration ---

def _sync_config_path(account_id):
    return os.path.join(ACCOUNTS_DIR, account_id, "sync_config.json")


def get_sync_config(account_id):
    """Get sync configuration for an account."""
    path = _sync_config_path(account_id)
    defaults = {
        "target_dir": "/volume1/iCloudPhotos",
        "photostream": {
            "enabled": True,
            "folder_structure": "year_month",  # year_month_day, year_month, year, flat
        },
        "albums": {
            "enabled": True,
            "folder_structure": "flat",  # year_month_day, year_month, year, flat
            "selected": {},  # album_name -> True/False
            "deduplicate_hardlinks": True,  # hardlink instead of re-downloading duplicates
        },
        "filenames": "original",  # original, date_based
        "conflict": "skip",  # skip, overwrite, rename
        "formats": "original",  # original, jpg_only, both
        "format_folders": False,  # separate HEIC/JPG subfolders
        "parallel_downloads": 4,  # 1, 2, 4, 8
        "sync_interval_hours": 6,
    }

    try:
        with open(path, "r") as f:
            saved = json.load(f)
        # Merge saved over defaults (keeps new defaults for missing keys)
        for k, v in saved.items():
            if isinstance(v, dict) and isinstance(defaults.get(k), dict):
                defaults[k].update(v)
            else:
                defaults[k] = v
        return defaults
    except (FileNotFoundError, json.JSONDecodeError):
        return defaults


def save_sync_config(account_id, config):
    """Save sync configuration for an account."""
    os.makedirs(os.path.join(ACCOUNTS_DIR, account_id), exist_ok=True)
    path = _sync_config_path(account_id)
    atomic_write_json(path, config, indent=2)


def set_album_sync(account_id, album_name, enabled):
    """Toggle sync for a specific album."""
    with _locked(_sync_config_path(account_id) + ".lock"):
        config = get_sync_config(account_id)
        config["albums"]["selected"][album_name] = enabled
        save_sync_config(account_id, config)
    return config
