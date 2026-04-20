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
    if action == "validate_path":
        return _validate_path(params)

    return {"success": False, "error": {"code": 101, "message": "Unknown action"}}


def _get_config(params):
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return {"success": False, "error": {"code": 301, "message": "account_id required"}}

    config = config_manager.get_sync_config(account_id)

    # Include cached shared library availability so the UI can disable the toggle
    cache_path = os.path.join(config_manager.get_account_dir(account_id), "album_cache.json")
    try:
        with open(cache_path, "r") as f:
            cache = json.load(f)
        config["has_shared_library"] = cache.get("has_shared_library", False)
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        config["has_shared_library"] = False

    return {"success": True, "data": config}


def _validate_path(params):
    """Check if target path is writable and return filesystem diagnostics."""
    path = params.getvalue("path", "").strip()
    if not path:
        return {"success": False, "error": {"code": 301, "message": "path required"}}

    from sync_engine import _writable, _get_mount_info

    writable = _writable(path)
    mp, fstype, opts = _get_mount_info(path)

    result = {
        "writable": writable,
        "mountpoint": mp,
        "fstype": fstype,
    }

    if not writable and fstype:
        no_acl = fstype.lower() in ("vfat", "exfat", "ntfs", "fuseblk", "msdos")
        result["no_acl_fs"] = no_acl

    return {"success": True, "data": result}


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


def _resolve_share_path(path):
    """Resolve FileChooser share-relative paths to real filesystem paths.

    FileChooser returns virtual paths without volume prefix:
      /photo/iCloud     → /volume2/photo/iCloud  (if share "photo" is on volume2)
      /volume1/...      → unchanged (already absolute)
      /home/...         → handled separately by _resolve_home_path()

    Uses synoshare to look up which volume a shared folder lives on.
    """
    if not path or path.startswith("/volume"):
        return path
    if path.startswith("/home"):
        return path

    parts = path.strip("/").split("/", 1)
    share_name = parts[0]
    sub_path = parts[1] if len(parts) > 1 else ""

    try:
        import subprocess
        result = subprocess.run(
            ["/usr/syno/sbin/synoshare", "--get", share_name],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Path"):
                real_share = line.split("[", 1)[-1].rstrip("]").strip()
                if real_share:
                    return os.path.join(real_share, sub_path) if sub_path else real_share
    except Exception:
        pass

    import glob
    for vol_path in sorted(glob.glob("/volume*/{}".format(share_name))):
        if os.path.isdir(vol_path):
            return os.path.join(vol_path, sub_path) if sub_path else vol_path

    return path


def _resolve_home_path(path, dsm_user=""):
    """Resolve FileChooser /home/... paths to real filesystem paths.

    Note: FileChooser "home" share maps to "homes" directory (plural).
    """
    if not path or (not path.startswith("/home/") and path != "/home"):
        return path
    if not dsm_user:
        dsm_user = _get_dsm_username()
    sub = path[5:].lstrip("/")
    if dsm_user:
        return os.path.join(config_manager.DEFAULT_VOLUME, "homes", dsm_user, sub)
    return path


def _set_config(params):
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return {"success": False, "error": {"code": 301, "message": "account_id required"}}

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

    # Resolve FileChooser share-relative paths and /home/... paths at save time
    if "target_dir" in updates:
        updates["target_dir"] = _resolve_share_path(updates["target_dir"])
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

    if _sync_running(account_id):
        return {"success": False, "error": {"code": 305,
            "message": "Albenauswahl kann nicht ge\u00e4ndert werden, solange eine Synchronisation l\u00e4uft. Bitte stoppe den Sync zuerst."}}

    album_name = params.getvalue("album", "").strip()
    if not album_name:
        return {"success": False, "error": {"code": 311, "message": "album required"}}

    enabled = params.getvalue("enabled", "true").strip().lower() in ("true", "1", "yes")
    album_type = params.getvalue("album_type", "user").strip()

    if album_type == "shared":
        config = config_manager.set_shared_album_sync(account_id, album_name, enabled)
    else:
        config = config_manager.set_album_sync(account_id, album_name, enabled)
    return {"success": True, "data": {"album": album_name, "enabled": enabled}}
