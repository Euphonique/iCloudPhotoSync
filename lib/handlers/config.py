"""
Config Handler — get/set sync configuration per account.

Actions:
  get         — Get sync config for an account
  set         — Update sync config fields
  set_album   — Toggle sync for a specific album
"""
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import config_manager
from handlers import authz
from sync_engine import SyncProgress, heal_stale_progress


def _sync_running(account_id):
    """Block config writes while a sync is active.

    Calls heal_stale_progress() so a crashed runner doesn't block writes
    even when the UI hasn't polled status yet.
    """
    try:
        p = SyncProgress.load(account_id)
        heal_stale_progress(p)
        return p.status in ("syncing", "starting")
    except Exception:
        return False


def handle(params):
    action = params.getvalue("action", "")

    if action == "get":
        return _get_config(params)
    if action == "set":
        return _set_config(params)
    if action == "set_album":
        return _set_album(params)

    return {"success": False, "error": {"code": 101, "message": "Unknown action"}}


def _get_config(params):
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return {"success": False, "error": {"code": 301, "message": "account_id required"}}

    denied = authz.validate_access(account_id)
    if denied:
        return denied

    config = config_manager.get_sync_config(account_id)
    return {"success": True, "data": config}


def _get_dsm_username():
    """Get the logged-in DSM username from the session cookie.

    synoscgi doesn't set REMOTE_USER, so we extract the session ID
    from the HTTP_COOKIE and query the Synology Auth API internally.
    """
    # Try direct env vars first
    user = os.environ.get("REMOTE_USER", "") or os.environ.get("HTTP_X_SYNO_USER", "")
    if user:
        return user

    # Extract session ID from cookie
    cookie_str = os.environ.get("HTTP_COOKIE", "")
    sid = ""
    for part in cookie_str.split(";"):
        part = part.strip()
        if part.startswith("id="):
            sid = part[3:]
            break

    if not sid:
        return ""

    # Query Synology Auth API to get username from session
    try:
        import urllib.request
        url = "http://localhost:5000/webapi/entry.cgi?api=SYNO.Core.CurrentConnection&version=1&method=list&_sid=%s" % sid
        resp = urllib.request.urlopen(url, timeout=5)
        result = json.loads(resp.read().decode("utf-8"))
        if result.get("success") and result.get("data"):
            items = result["data"].get("items", [])
            # Find the connection matching the request IP
            remote_ip = os.environ.get("REMOTE_ADDR", "")
            for item in items:
                if item.get("from") == remote_ip:
                    return item.get("who", "")
            # Fallback: return first connection's user
            if items:
                return items[0].get("who", "")
    except Exception:
        pass

    return ""


def _resolve_home_path(path, dsm_user=""):
    """Resolve FileChooser /home/... paths to real filesystem paths.

    FileChooser returns virtual paths:
      /home/Test        → /volume1/homes/<username>/Test
      /photo/iCloud     → unchanged (resolved by sync engine)
      /volume1/...      → unchanged (already absolute)

    Note: FileChooser "home" share maps to "homes" directory (plural).
    """
    if not path or (not path.startswith("/home/") and path != "/home"):
        return path
    if not dsm_user:
        dsm_user = _get_dsm_username()
    sub = path[5:].lstrip("/")
    if dsm_user:
        return os.path.join("/volume1/homes", dsm_user, sub)
    return path


def _set_config(params):
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return {"success": False, "error": {"code": 301, "message": "account_id required"}}

    denied = authz.validate_access(account_id)
    if denied:
        return denied

    if _sync_running(account_id):
        return {"success": False, "error": {"code": 305,
            "message": "Einstellungen k\u00f6nnen nicht ge\u00e4ndert werden, solange eine Synchronisation l\u00e4uft. Bitte stoppe den Sync zuerst."}}

    config_json = params.getvalue("config", "").strip()
    if not config_json:
        return {"success": False, "error": {"code": 302, "message": "config required"}}

    try:
        updates = json.loads(config_json)
    except json.JSONDecodeError:
        return {"success": False, "error": {"code": 303, "message": "Invalid JSON"}}

    # Frontend passes the logged-in DSM username explicitly because synoscgi
    # doesn't reliably expose it via env vars. Persist it on the account so
    # the background scheduler can resolve /home/... paths too.
    dsm_user = params.getvalue("dsm_user", "").strip()
    if dsm_user:
        config_manager.update_account(account_id, {"dsm_user": dsm_user})
    else:
        acc = config_manager.get_account(account_id) or {}
        dsm_user = acc.get("dsm_user", "")

    # Resolve /home/... paths at save time using the DSM user
    if "target_dir" in updates:
        resolved = _resolve_home_path(updates["target_dir"], dsm_user)
        if resolved.startswith("/home/") or resolved == "/home":
            return {"success": False, "error": {"code": 304,
                "message": "Cannot resolve home path — DSM username unknown. Pick a shared folder or reopen the app."}}
        updates["target_dir"] = resolved

    current = config_manager.get_sync_config(account_id)

    # Target dir change policy is decided by the UI and passed via
    # `target_action`: "clear" (re-download everything, original behavior),
    # "move" (keep manifest — caller will launch /move handler after save),
    # or empty (no existing data, plain save).
    if "target_dir" in updates and updates["target_dir"] != current.get("target_dir"):
        target_action = params.getvalue("target_action", "").strip()
        import sync_manifest
        if target_action == "clear":
            sync_manifest.clear_all(account_id)
        elif target_action == "move":
            pass  # files will be relocated by move_runner; manifest gets updated per file
        else:
            try:
                stats = sync_manifest.get_stats(account_id)
            except Exception:
                stats = {"total_synced": 0}
            if stats.get("total_synced", 0) > 0:
                return {"success": False, "error": {"code": 306,
                    "message": "target_action required",
                    "target_dir_changed": True,
                    "old_target_dir": current.get("target_dir", ""),
                    "new_target_dir": updates["target_dir"],
                    "manifest_total": stats.get("total_synced", 0)}}
            # Empty manifest: nothing to move; just save.

    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(current.get(k), dict):
            current[k].update(v)
        else:
            current[k] = v
    config_manager.save_sync_config(account_id, current)
    return {"success": True, "data": current}


def _set_album(params):
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return {"success": False, "error": {"code": 301, "message": "account_id required"}}

    denied = authz.validate_access(account_id)
    if denied:
        return denied

    if _sync_running(account_id):
        return {"success": False, "error": {"code": 305,
            "message": "Albenauswahl kann nicht ge\u00e4ndert werden, solange eine Synchronisation l\u00e4uft. Bitte stoppe den Sync zuerst."}}

    album_name = params.getvalue("album", "").strip()
    if not album_name:
        return {"success": False, "error": {"code": 311, "message": "album required"}}

    enabled = params.getvalue("enabled", "true").strip().lower() in ("true", "1", "yes")

    config = config_manager.set_album_sync(account_id, album_name, enabled)
    return {"success": True, "data": {"album": album_name, "enabled": enabled}}
