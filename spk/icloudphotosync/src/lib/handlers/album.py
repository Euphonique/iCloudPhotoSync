"""
Album Handler — list albums, get photos, thumbnails.

Actions:
  list    — Get all albums (names + cached counts)
  count   — Get photo count for a single album (+ update cache)
  photos  — Get photos in an album (paginated)
"""
import json
import logging
import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import config_manager
import icloud_client
import log_utils
import sync_engine

logger = logging.getLogger(__name__)

# CGI processes have no logging configured — attach a file handler so
# album (and pyicloud) log messages are captured for debugging.
if not logging.root.handlers:
    logging.root.addHandler(log_utils.file_handler("album.log"))
    logging.root.setLevel(log_utils.configured_level())

ADP_ERROR_CODE = 320

_TYPE_ORDER = {"all": 0, "folder": 1, "user": 1, "smart": 2, "shared": 3}


def _album_sort_key(a):
    """Sort: All Photos first, then user+folder albums grouped with
    proper tree ordering (parent before children at every depth),
    then smart folders, then shared."""
    t = _TYPE_ORDER.get(a["type"], 9)
    parent = a.get("parent_folder") or ""
    if parent:
        full_path = parent + "/" + a["name"]
    else:
        full_path = a["name"]
    return (t, full_path.lower())


def _maybe_adp_error(exc, fallback_code, account_id=None):
    """Return an ADP-specific error response when appropriate."""
    from pyicloud_ipd.exceptions import (
        PyiCloudADPProtectionException,
        PyiCloudServiceNotActivatedException,
        PyiCloudSessionExpiredException,
    )
    if isinstance(exc, PyiCloudSessionExpiredException):
        # Surface the re-login button instead of a "connected" account
        # whose every Photos request fails (#87).
        if account_id:
            config_manager.update_account(account_id, {"status": "re_auth_needed"})
        return {"success": False, "error": {"code": 303, "message": str(exc)}}
    if isinstance(exc, PyiCloudADPProtectionException):
        return {"success": False, "error": {"code": ADP_ERROR_CODE, "message": str(exc)}}
    if isinstance(exc, PyiCloudServiceNotActivatedException):
        return {"success": False, "error": {"code": ADP_ERROR_CODE, "message":
            "iCloud Photos is not available for this account. "
            "Make sure iCloud Photos is enabled in the Apple ID settings."}}
    return {"success": False, "error": {"code": fallback_code, "message": str(exc)}}


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

    cache = _load_cache(account_id)
    counts = cache.get("counts", {})
    if not counts:
        return {"success": True, "data": {"albums": [], "libraries": [], "from_cache": True, "cache_age": -1}}

    album_types = cache.get("types", {})
    cached_parents = cache.get("parents", {})
    cached_names = cache.get("names", {})

    personal_list = []
    shared_library_list = []

    for name, count in counts.items():
        is_sl = name.startswith("sl:")
        key = name[3:] if is_sl else name
        display_name = cached_names.get(name, key)

        cached_type = album_types.get(name)
        if cached_type:
            atype = cached_type
        elif display_name in ("All Photos",):
            atype = "all"
        elif any(display_name == s for s in ("Favorites", "Videos", "Screenshots", "Live",
                                              "Panoramas", "Time-lapse", "Slo-mo", "Bursts")):
            atype = "smart"
        else:
            atype = "user"

        if atype == "shared":
            continue

        entry = {
            "key": key, "name": display_name, "type": atype, "photo_count": count,
            "parent_folder": cached_parents.get(name),
        }

        if is_sl:
            if display_name != "All Photos" and count == 0:
                continue
            entry["library"] = "shared"
            shared_library_list.append(entry)
        else:
            personal_list.append(entry)

    personal_list.sort(key=_album_sort_key)
    shared_library_list.sort(key=_album_sort_key)

    cache_age = int(time.time()) - cache.get("updated", 0)
    libraries = [{"id": "personal", "name": "My Library", "albums": personal_list}]
    if cache.get("has_shared_library") and shared_library_list:
        libraries.append({"id": "shared", "name": "Shared Library", "albums": shared_library_list})

    return {"success": True, "data": {
        "libraries": libraries,
        "albums": personal_list,
        "from_cache": True,
        "cache_age": cache_age,
        "has_shared_library": cache.get("has_shared_library", False),
    }}


def _get_authenticated_client(params):
    """Helper: get an authenticated icloud client from account_id param."""
    account_id = params.getvalue("account_id", "").strip()
    if not account_id:
        return None, {"success": False, "error": {"code": 301, "message": "account_id required"}}

    account = config_manager.get_account(account_id)
    if not account:
        return None, {"success": False, "error": {"code": 302, "message": "Account not found"}}

    client = icloud_client.get_client(account_id, account["apple_id"])
    if not client.restore_session():
        if client.transient_error:
            return None, {"success": False, "error": {"code": 313, "message":
                "Could not reach Apple's iCloud servers. Check the NAS "
                "network connection and try again."}}
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
        photos_svc.refresh_albums()
        albums = photos_svc.albums

        # Personal library albums
        # Albums are keyed by folder path since #81; rewrite selections
        # still stored under a bare display name before the UI reads them.
        migrated = bool(sync_engine.migrate_album_keys(
            account_id, photos_svc.legacy_album_keys))

        album_list = []
        cached_parents = {}
        cached_names = {}
        for key, album in albums.items():
            parent = getattr(album, "parent_folder", None)
            if parent:
                cached_parents[key] = parent
            if album.name != key:
                cached_names[key] = album.name
            album_list.append({
                "key": key,
                "name": album.name,
                "type": album.album_type,
                "photo_count": cached_counts.get(key, -1),
                "parent_folder": parent,
            })
        album_list.sort(key=_album_sort_key)

        # Shared Library albums (iOS 16+ family sharing)
        shared_library_list = []
        has_shared_library = False
        sl_albums = {}
        sl_failed = False
        try:
            has_shared_library = photos_svc.has_shared_library
            if has_shared_library:
                sl_albums = photos_svc.shared_library_albums
                if sync_engine.migrate_album_keys(
                        account_id,
                        photos_svc.legacy_shared_library_album_keys,
                        library="shared"):
                    migrated = True
                for key, album in sl_albums.items():
                    count = cached_counts.get("sl:" + key, -1)
                    if key != "All Photos" and count == 0:
                        continue
                    parent = getattr(album, "parent_folder", None)
                    if parent:
                        cached_parents["sl:" + key] = parent
                    if album.name != key:
                        cached_names["sl:" + key] = album.name
                    shared_library_list.append({
                        "key": key,
                        "name": album.name,
                        "type": album.album_type,
                        "photo_count": count,
                        "parent_folder": parent,
                        "library": "shared",
                    })
                shared_library_list.sort(key=_album_sort_key)
        except Exception as exc:
            logger.error("Failed to list shared library albums: %s", exc, exc_info=True)
            sl_failed = True

        # Persist parent relationships, types, and shared library status in cache
        cache["has_shared_library"] = has_shared_library
        if sl_failed:
            # Keep the last known shared library tree
            for field, fresh in (("parents", cached_parents), ("names", cached_names)):
                for k, v in cache.get(field, {}).items():
                    if k.startswith("sl:"):
                        fresh.setdefault(k, v)
        cache["parents"] = cached_parents
        cache["names"] = cached_names
        album_types = cache.setdefault("types", {})
        counts = cache.setdefault("counts", {})
        # Every album gets a cache row (-1 = count not loaded yet, rendered
        # as "…"). Rows used to appear only once a count had loaded, so a
        # timed-out count pass left the cached tree permanently incomplete
        # (#81).
        live_keys = set()
        for a in album_list:
            live_keys.add(a["key"])
            album_types[a["key"]] = a["type"]
            counts.setdefault(a["key"], 0 if a["type"] == "folder" else -1)
        for a in shared_library_list:
            live_keys.add("sl:" + a["key"])
            album_types["sl:" + a["key"]] = a["type"]
            counts.setdefault("sl:" + a["key"], 0 if a["type"] == "folder" else -1)
        # Drop rows of albums that no longer exist — including the old
        # name-keyed rows of nested albums, which would otherwise show up
        # twice in the cached tree. Shared library rows hidden for having
        # 0 photos are kept so their count isn't re-fetched.
        for key in list(counts):
            if key in live_keys:
                continue
            if key.startswith("sl:") and (sl_failed or key[3:] in sl_albums):
                continue
            counts.pop(key, None)
            album_types.pop(key, None)
        _save_cache(account_id, cache)

        cache_age = int(time.time()) - cache.get("updated", 0)
        result = {
            "libraries": [
                {"id": "personal", "name": "My Library", "albums": album_list},
            ],
            "albums": album_list,
            "cache_age": cache_age,
            "has_shared_library": has_shared_library,
            # Selections were rewritten — the UI must reload the config
            "selection_migrated": migrated,
        }
        if has_shared_library:
            result["libraries"].append({
                "id": "shared",
                "name": "Shared Library",
                "albums": shared_library_list,
            })
        return {"success": True, "data": result}

    except Exception as e:
        return _maybe_adp_error(e, 310, account_id)


def _find_album(photos_svc, album_name, library="personal"):
    """Find an album by name and library."""
    if library == "shared":
        return photos_svc.shared_library_albums.get(album_name)
    album = photos_svc.albums.get(album_name)
    if album:
        return album
    if photos_svc.has_shared_library:
        album = photos_svc.shared_library_albums.get(album_name)
        if album:
            return album
    return None


def _album_count(params):
    client, err = _get_authenticated_client(params)
    if err:
        return err

    account_id = params.getvalue("account_id", "").strip()
    album_name = params.getvalue("album", "").strip()
    library = params.getvalue("library", "personal").strip()
    if not album_name:
        return {"success": False, "error": {"code": 311, "message": "album required"}}

    try:
        photos_svc = client.api.photos
        album = _find_album(photos_svc, album_name, library)
        if not album:
            return {"success": False, "error": {"code": 311, "message": "Album not found"}}

        if album.album_type == "folder":
            count = 0
        else:
            count = album.photo_count

        # Update cache
        cache = _load_cache(account_id)
        cache_key = ("sl:" + album_name) if library == "shared" else album_name
        cache.setdefault("counts", {})[cache_key] = count
        cache.setdefault("types", {})[cache_key] = album.album_type
        _save_cache(account_id, cache)

        return {"success": True, "data": {"album": album_name, "photo_count": count}}

    except Exception as e:
        return _maybe_adp_error(e, 312, account_id)


def _list_photos(params):
    client, err = _get_authenticated_client(params)
    if err:
        return err

    album_name = params.getvalue("album", "All Photos").strip()
    limit = int(params.getvalue("limit", "50"))
    offset = int(params.getvalue("offset", "0"))
    library = params.getvalue("library", "personal").strip()
    direction = params.getvalue("direction", "ASCENDING").strip().upper()
    if direction not in ("ASCENDING", "DESCENDING"):
        direction = "ASCENDING"

    try:
        photos_svc = client.api.photos
        album = _find_album(photos_svc, album_name, library)

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
        return {"success": False, "error": {"code": 312, "message": str(e)}}
