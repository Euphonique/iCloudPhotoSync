"""
Authorization — per-account ownership enforcement.

Every handler that accepts an account_id should call validate_access()
before performing any action.  The first DSM user to create or
authenticate an account is recorded as its owner; requests from other
DSM users are rejected.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import config_manager


def _get_dsm_username():
    """Resolve the DSM username of the current CGI request."""
    user = os.environ.get("REMOTE_USER", "") or os.environ.get("HTTP_X_SYNO_USER", "")
    if user:
        return user

    cookie_str = os.environ.get("HTTP_COOKIE", "")
    sid = ""
    for part in cookie_str.split(";"):
        part = part.strip()
        if part.startswith("id="):
            sid = part[3:]
            break
    if not sid:
        return ""

    try:
        import json
        import urllib.request
        url = (
            "http://localhost:5000/webapi/entry.cgi"
            "?api=SYNO.Core.CurrentConnection&version=1&method=list&_sid=%s" % sid
        )
        resp = urllib.request.urlopen(url, timeout=5)
        result = json.loads(resp.read().decode("utf-8"))
        if result.get("success") and result.get("data"):
            items = result["data"].get("items", [])
            remote_ip = os.environ.get("REMOTE_ADDR", "")
            for item in items:
                if item.get("from") == remote_ip:
                    return item.get("who", "")
            if items:
                return items[0].get("who", "")
    except Exception:
        pass
    return ""


def stamp_owner(account_id):
    """Record the current DSM user as the account owner if not set yet."""
    dsm_user = _get_dsm_username()
    if not dsm_user:
        return
    account = config_manager.get_account(account_id)
    if not account:
        return
    if not account.get("owner"):
        config_manager.update_account(account_id, {"owner": dsm_user})


def validate_access(account_id):
    """Check that the requesting DSM user owns the account.

    Returns None on success, or an error dict suitable for returning
    from a handler if access is denied.
    """
    if not account_id:
        return {"success": False, "error": {"code": 403, "message": "account_id required"}}

    account = config_manager.get_account(account_id)
    if not account:
        return {"success": False, "error": {"code": 404, "message": "Account not found"}}

    owner = account.get("owner", "")
    dsm_user = _get_dsm_username()

    # Legacy accounts without an owner: stamp the first user who touches them
    if not owner:
        if dsm_user:
            config_manager.update_account(account_id, {"owner": dsm_user})
        return None

    if not dsm_user:
        # Cannot determine caller identity — allow (DSM auth already gates
        # access to the CGI). This keeps the package working when synoscgi
        # doesn't expose user info (e.g. scheduler daemon calling directly).
        return None

    if dsm_user != owner:
        return {"success": False, "error": {"code": 403, "message": "Access denied"}}

    return None


def filter_accounts_for_user(accounts):
    """Filter an account list to only those owned by (or unowned for) the
    current DSM user."""
    dsm_user = _get_dsm_username()
    if not dsm_user:
        return accounts
    return [
        acc for acc in accounts
        if not acc.get("owner") or acc.get("owner") == dsm_user
    ]
