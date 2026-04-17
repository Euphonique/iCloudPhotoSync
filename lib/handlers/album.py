"""
Album Handler — list albums, get photos, thumbnails.

Actions:
  list    — Get all albums (names + cached counts)
  count   — Get photo count for a single album (+ update cache)
  photos  — Get photos in an album (paginated)
"""
import json
import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import config_manager
import icloud_client
from handlers import authz


def _cache_path(account_id):
    return os.path.join(config_manager.get_account_dir(account_id), "album_cache.json")


def _load_cache(account_id):
    try:
        with open(_cache_path(account_id), "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"counts": {}, "updated": 0}


def _save_cache(account_id, cache):
    cache["updated"] = int(time.time())
    try:
        with open(_cache_path(account_id), "w") as f:
            json.dump(cache, f)
    except Exception:
        pass


def handle(params):
    action = params.getvalue("action", "")

    if action == "list":
        return _list_albums(params)
    if action == "count":
        return _album_count(params)
    if action == "photos":
        return _list_photos(params)
    if action == "cached":
        return _cached_albums(params)

    return {"success": False, "error": {"code": 101, "message": "Unknown action"}}


def _cached_albums(params):
    """Return album data from local cache only — no Apple API calls."""
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return {"success": False, "error": {"code": 301, "message": "account_id required"}}

    denied = authz.validate_access(account_id)
    if denied:
        return denied

    cache = _load_cache(account_id)
    counts = cache.get("counts", {})
    if not counts:
        return {"success": True, "data": {"albums": [], "from_cache": True, "cache_age": -1}}

    album_list = []
    for name, count in counts.items():
        if name in ("All Photos",):
            atype = "all"
        elif any(name == s for s in ("Favorites", "Videos", "Screenshots", "Live",
                                      "Panoramas", "Time-lapse", "Slo-mo", "Bursts")):
            atype = "smart"
        else:
            atype = "user"
        album_list.append({"name": name, "type": atype, "photo_count": count})

    type_order = {"all": 0, "user": 1, "smart": 2}
    album_list.sort(key=lambda a: (type_order.get(a["type"], 9), a["name"]))

    cache_age = int(time.time()) - cache.get("updated", 0)
    return {"success": True, "data": {"albums": album_list, "from_cache": True, "cache_age": cache_age}}


def _get_authenticated_client(params):
    """Helper: get an authenticated icloud client from account_id param."""
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return None, {"success": False, "error": {"code": 301, "message": "account_id required"}}

    denied = authz.validate_access(account_id)
    if denied:
        return None, denied

    account = config_manager.get_account(account_id)
    if not account:
        return None, {"success": False, "error": {"code": 302, "message": "Account not found"}}

    client = icloud_client.get_client(account_id, account["apple_id"])
    if not client.restore_session():
        return None, {"success": False, "error": {"code": 303, "message": "Not authenticated"}}

    return client, None


def _list_albums(params):
    client, err = _get_authenticated_client(params)
    if err:
        return err

    account_id = params.getvalue("account_id", "").strip()
    cache = _load_cache(account_id)
    cached_counts = cache.get("counts", {})

    try:
        photos_svc = client.api.photos
        albums = photos_svc.albums

        album_list = []
        for name, album in albums.items():
            album_list.append({
                "name": name,
                "type": album.album_type,
                "photo_count": cached_counts.get(name, -1),
            })

        # Sort: "All Photos" first, then user albums, then smart folders
        type_order = {"all": 0, "user": 1, "smart": 2}
        album_list.sort(key=lambda a: (type_order.get(a["type"], 9), a["name"]))

        cache_age = int(time.time()) - cache.get("updated", 0)
        return {"success": True, "data": {
            "albums": album_list,
            "cache_age": cache_age,
        }}

    except Exception as e:
        import logging
        logging.getLogger("album").exception("list_albums error")
        return {"success": False, "error": {"code": 310, "message": "Failed to list albums"}}


def _album_count(params):
    client, err = _get_authenticated_client(params)
    if err:
        return err

    account_id = params.getvalue("account_id", "").strip()
    album_name = params.getvalue("album", "").strip()
    if not album_name:
        return {"success": False, "error": {"code": 311, "message": "album required"}}

    try:
        photos_svc = client.api.photos
        album = photos_svc.albums.get(album_name)
        if not album:
            return {"success": False, "error": {"code": 311, "message": "Album not found"}}

        count = album.photo_count

        # Update cache
        cache = _load_cache(account_id)
        cache.setdefault("counts", {})[album_name] = count
        _save_cache(account_id, cache)

        return {"success": True, "data": {"album": album_name, "photo_count": count}}

    except Exception as e:
        import logging
        logging.getLogger("album").exception("album_count error")
        return {"success": False, "error": {"code": 312, "message": "Failed to get album count"}}


def _list_photos(params):
    client, err = _get_authenticated_client(params)
    if err:
        return err

    album_name = params.getvalue("album", "All Photos").strip()
    try:
        limit = max(1, min(500, int(params.getvalue("limit", "50"))))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(params.getvalue("offset", "0")))
    except (TypeError, ValueError):
        offset = 0
    direction = params.getvalue("direction", "ASCENDING").strip().upper()
    if direction not in ("ASCENDING", "DESCENDING"):
        direction = "ASCENDING"

    try:
        photos_svc = client.api.photos
        albums = photos_svc.albums
        album = albums.get(album_name)

        if not album:
            return {"success": False, "error": {"code": 311, "message": "Album not found"}}

        photos = album.photos(limit=limit, offset=offset, direction=direction)
        photo_list = [p.to_dict() for p in photos]

        return {
            "success": True,
            "data": {
                "album": album_name,
                "photos": photo_list,
                "offset": offset,
                "direction": direction,
                "count": len(photo_list),
                "total": album.photo_count or 0,
            }
        }

    except Exception as e:
        import logging
        logging.getLogger("album").exception("list_photos error")
        return {"success": False, "error": {"code": 312, "message": "Failed to list photos"}}
