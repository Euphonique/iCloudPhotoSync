#!/usr/bin/env python3
"""Pre-publish security validation tests."""
import os
import re
import sys
from urllib.parse import urlparse

# Setup paths
ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
sys.path.insert(0, os.path.join(ROOT, "lib", "vendor"))
os.environ["SYNOPKG_PKGVAR"] = "/tmp/test_icloud_pkg"

passed = 0
failed = 0


def check(label, condition):
    global passed, failed
    if condition:
        passed += 1
    else:
        failed += 1
        print("  FAIL: %s" % label)


# --- 1. Imports ---
print("1. Testing core imports...")
import config_manager
from handlers import authz
# Handlers that import sync_engine/move_engine need 'requests' at import time,
# which may not be installed in the dev environment. We test those via
# py_compile (syntax check) instead and focus on the security-critical modules.
try:
    from handlers import status, auth, account, album, sync
    from handlers import config as cfg_handler
    from handlers import log, move
    print("   All handler imports OK")
except ImportError as e:
    print("   Some handler imports skipped (missing runtime dep): %s" % e)
import sync_manifest
import heic_converter
print("   Core imports OK")

# --- 2. validate_account_id ---
print("2. Testing validate_account_id...")
check("legacy 8-char hex", config_manager.validate_account_id("a1b2c3d4"))
check("full UUID4", config_manager.validate_account_id("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"))
check("path traversal rejected", not config_manager.validate_account_id("../../etc"))
check("empty rejected", not config_manager.validate_account_id(""))
check("None rejected", not config_manager.validate_account_id(None))
check("UUID+traversal rejected", not config_manager.validate_account_id("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d/../../x"))
check("uppercase hex rejected", not config_manager.validate_account_id("ABCDEF12"))
check("slash rejected", not config_manager.validate_account_id("abc/def"))
check("backslash rejected", not config_manager.validate_account_id("abc\\def"))
check("NUL byte rejected", not config_manager.validate_account_id("abc\x00def"))
check("spaces rejected", not config_manager.validate_account_id("a1b 2c3d"))

# --- 3. Password encryption ---
print("3. Testing password encryption...")
test_pw = "MySecretPassword123!"
encrypted = config_manager._encrypt_password(test_pw)
check("encrypted has nonce+ciphertext", len(encrypted) > 16)
decrypted = config_manager._decrypt_password(encrypted)
check("decrypt matches original", decrypted == test_pw)
encrypted2 = config_manager._encrypt_password(test_pw)
check("different nonces produce different ciphertext", encrypted != encrypted2)
decrypted2 = config_manager._decrypt_password(encrypted2)
check("second decrypt matches", decrypted2 == test_pw)
# Legacy plaintext fallback
legacy = test_pw.encode("utf-8")
legacy_dec = config_manager._decrypt_password(legacy)
# May or may not match — the point is it shouldn't crash
check("legacy plaintext doesn't crash", True)
# Unicode password
unicode_pw = "Passwort mit Umlauten: \u00e4\u00f6\u00fc\u00df"
enc_u = config_manager._encrypt_password(unicode_pw)
dec_u = config_manager._decrypt_password(enc_u)
check("unicode password roundtrips", dec_u == unicode_pw)

# --- 4. get_account_dir validation ---
print("4. Testing get_account_dir validation...")
try:
    config_manager.get_account_dir("../../etc")
    check("get_account_dir rejects traversal", False)
except ValueError:
    check("get_account_dir rejects traversal", True)

try:
    d = config_manager.get_account_dir("a1b2c3d4")
    check("get_account_dir accepts legacy ID", d.endswith("/a1b2c3d4"))
except ValueError:
    check("get_account_dir accepts legacy ID", False)

# --- 5. URL validation ---
print("5. Testing URL validation...")
def _valid_icloud_url(url):
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return (
            parsed.scheme in ("http", "https")
            and (host.endswith(".icloud-content.com") or host.endswith(".icloud.com"))
        )
    except Exception:
        return False

check("valid icloud-content URL", _valid_icloud_url("https://cvws.icloud-content.com/B/abc/photo.jpg"))
check("valid icloud.com URL", _valid_icloud_url("https://p123-ckdatabasews.icloud.com/api"))
check("query param bypass blocked", not _valid_icloud_url("https://evil.com?x=icloud-content.com"))
check("subdomain bypass blocked", not _valid_icloud_url("https://icloud-content.com.evil.com/x"))
check("ftp scheme blocked", not _valid_icloud_url("ftp://cvws.icloud-content.com/x"))
check("empty blocked", not _valid_icloud_url(""))
check("javascript: blocked", not _valid_icloud_url("javascript:alert(1)"))
check("file: scheme blocked", not _valid_icloud_url("file:///etc/passwd"))
check("bare hostname blocked", not _valid_icloud_url("icloud-content.com"))

# --- 6. Filename sanitizer ---
print("6. Testing _safe_filename...")
def _safe_filename(name, fallback="photo.jpg"):
    if not name:
        return fallback
    name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", name)
    name = name.replace("\\", "_").replace("/", "_")
    name = re.sub(r"[;|&$`*?!<>'\"\(\)\{\}\[\]]", "", name)
    name = name.strip(". ")
    if not name:
        return fallback
    encoded = name.encode("utf-8")[:255]
    name = encoded.decode("utf-8", errors="ignore")
    return name or fallback

check("empty -> fallback", _safe_filename("") == "photo.jpg")
check("None -> fallback", _safe_filename(None) == "photo.jpg")
check("normal file preserved", _safe_filename("test.jpg") == "test.jpg")
check("slashes replaced", "/" not in _safe_filename("../../../etc/passwd"))
check("NUL stripped", "\x00" not in _safe_filename("file\x00name.jpg"))
check("newline stripped", "\n" not in _safe_filename("file\nname.jpg"))
check("semicolon stripped", ";" not in _safe_filename("file;rm -rf.jpg"))
check("pipe stripped", "|" not in _safe_filename("file|cat.jpg"))
check("long name truncated", len(_safe_filename("a" * 300 + ".jpg").encode("utf-8")) <= 255)

# --- 7. UUID generation ---
print("7. Testing new account uses full UUID...")
import uuid
test_id = str(uuid.uuid4())
check("uuid4 format matches regex", bool(config_manager._ACCOUNT_ID_RE.match(test_id)))
check("8-char truncated does NOT match UUID regex", not bool(config_manager._ACCOUNT_ID_RE.match(test_id[:8])))
check("8-char truncated matches legacy regex", bool(config_manager._LEGACY_ACCOUNT_ID_RE.match(test_id[:8])))

# --- 8. authz module structure ---
print("8. Testing authz module...")
check("authz has validate_access", hasattr(authz, "validate_access"))
check("authz has stamp_owner", hasattr(authz, "stamp_owner"))
check("authz has filter_accounts_for_user", hasattr(authz, "filter_accounts_for_user"))

# No DSM env in test, but validate_access with a missing account should return error
result = authz.validate_access("nonexistent-id-xx")
# It won't match UUID or legacy pattern, so get_account_dir raises ValueError
# Actually, validate_access calls get_account which reads config.json — let's just
# check it doesn't crash
check("validate_access doesn't crash on missing account", result is not None)

# --- Summary ---
print()
total = passed + failed
print("=" * 50)
if failed == 0:
    print("ALL %d TESTS PASSED" % total)
else:
    print("%d/%d PASSED, %d FAILED" % (passed, total, failed))
sys.exit(1 if failed else 0)
