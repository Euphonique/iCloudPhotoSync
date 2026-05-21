"""PhotosService — iCloud Photos via CloudKit API."""
import base64
import json
import logging
import time
import unicodedata

from requests import Session as _RawSession

LOGGER = logging.getLogger(__name__)

# Smart album filter values: (query_filter for photos, count_key for HyperionIndexCountLookup)
# Apple uses UPPERCASE for photo queries but mixed-case for count queries
SMART_FOLDERS = {
    "Favorites": ("FAVORITE", "Favorite"),
    "Videos": ("VIDEO", "Video"),
    "Screenshots": ("SCREENSHOT", "Screenshot"),
    "Live": ("LIVE", "Live"),
    "Panoramas": ("PANORAMA", "Panorama"),
    "Time-lapse": ("TIMELAPSE", "Time-lapse"),
    "Slo-mo": ("SLOMO", "Slo-mo"),
}


def _decode_b64_name(raw):
    """Decode a base64-encoded name from CloudKit, handling missing padding
    and non-UTF-8 data. Returns the decoded string or the raw value."""
    if not raw:
        return ""
    try:
        padded = raw + "=" * (-len(raw) % 4)
        name = base64.b64decode(padded).decode("utf-8")
        return unicodedata.normalize("NFC", name)
    except Exception:
        return raw


class PhotoAlbum:
    """Represents an iCloud Photos album."""

    def __init__(self, service, name, record_name=None, album_type="user",
                 smart_filter=None, smart_count_key=None,
                 list_type=None, obj_type=None, zone_id=None,
                 parent_folder=None):
        self.service = service
        self.name = name
        self.record_name = record_name
        self.album_type = album_type  # "all", "user", "smart", "shared", "folder"
        self.smart_filter = smart_filter
        self._photo_count = None
        self.zone_id = zone_id
        self.parent_folder = parent_folder

        if album_type == "all":
            self.list_type = "CPLAssetAndMasterByAssetDateWithoutHiddenOrDeleted"
            self.obj_type = "CPLAssetByAssetDateWithoutHiddenOrDeleted"
        elif album_type == "smart":
            self.list_type = "CPLAssetAndMasterInSmartAlbumByAssetDate"
            self.obj_type = "CPLAssetInSmartAlbumByAssetDate:%s" % (smart_count_key or smart_filter)
        elif album_type == "burst":
            self.list_type = "CPLBurstStackAssetAndMasterByAssetDate"
            self.obj_type = "CPLAssetBurstStackAssetByAssetDate"
        elif album_type == "user":
            self.list_type = "CPLContainerRelationLiveByAssetDate"
            self.obj_type = "CPLContainerRelationNotDeletedByAssetDate:%s" % record_name
        elif album_type == "shared":
            self.list_type = "CPLAssetAndMasterByAssetDate"
            self.obj_type = "CPLAssetByAssetDate"
        else:
            self.list_type = list_type
            self.obj_type = obj_type

    @property
    def _is_shared_library(self):
        return (self.zone_id or {}).get("zoneName", "").startswith("SharedSync-")

    @property
    def _uses_shared_db(self):
        return self._is_shared_library and getattr(self.service, '_shared_library_uses_shared_db', False)

    @property
    def photo_count(self):
        if self._photo_count is None:
            if self.album_type == "folder":
                self._photo_count = 0
            elif self.album_type == "shared" or self._uses_shared_db:
                self._photo_count = self.service._get_shared_album_count(self)
            else:
                self._photo_count = self.service._get_album_count(self.obj_type, zone_id=self.zone_id)
        return self._photo_count

    def photos(self, limit=200, offset=0, direction="ASCENDING"):
        """Fetch photos in this album."""
        if self.album_type == "shared" or self._uses_shared_db:
            return self.service._get_shared_album_photos(self, limit=limit, offset=offset, direction=direction)
        return self.service._get_album_photos(self, limit=limit, offset=offset, direction=direction)

    def __repr__(self):
        return "<PhotoAlbum: %s>" % self.name


class PhotoAsset:
    """Represents a single photo/video asset."""

    def __init__(self, master_record, asset_record=None):
        self._master = master_record
        self._asset = asset_record
        self._parse()

    def _parse(self):
        m = self._master.get("fields", {})
        a = self._asset.get("fields", {}) if self._asset else {}

        # Filename
        raw = m.get("filenameEnc", {}).get("value", "")
        self.filename = _decode_b64_name(raw) or raw

        # Dates
        self.created = a.get("assetDate", {}).get("value", 0)
        self.added = a.get("addedDate", {}).get("value", 0)

        # Type
        self.item_type = m.get("itemType", {}).get("value", "public.jpeg")
        self.is_video = "movie" in self.item_type or "video" in self.item_type

        # Dimensions
        self.width = m.get("resOriginalWidth", {}).get("value", 0)
        self.height = m.get("resOriginalHeight", {}).get("value", 0)

        # Size and checksum from original resource
        res = m.get("resOriginalRes", {}).get("value", {})
        self.size = res.get("size", 0)
        self.checksum = res.get("fileChecksum", "")

        # Record name for identification
        self.id = self._master.get("recordName", "")

    @staticmethod
    def _fix_url(url):
        """Replace ${f} placeholder in iCloud download URLs."""
        if url and "${f}" in url:
            return url.replace("${f}", "image.jpg")
        return url

    @property
    def thumb_url(self):
        """URL for JPEG thumbnail."""
        m = self._master.get("fields", {})
        thumb = m.get("resJPEGThumbRes", {}).get("value", {})
        return self._fix_url(thumb.get("downloadURL"))

    @property
    def medium_url(self):
        """URL for medium JPEG."""
        m = self._master.get("fields", {})
        med = m.get("resJPEGMedRes", {}).get("value", {})
        return self._fix_url(med.get("downloadURL"))

    @property
    def original_url(self):
        """URL for original file."""
        m = self._master.get("fields", {})
        orig = m.get("resOriginalRes", {}).get("value", {})
        return self._fix_url(orig.get("downloadURL"))

    def to_dict(self):
        """Serializable dict for JSON responses."""
        return {
            "id": self.id,
            "filename": self.filename,
            "created": self.created,
            "item_type": self.item_type,
            "is_video": self.is_video,
            "width": self.width,
            "height": self.height,
            "size": self.size,
            "checksum": self.checksum,
            "thumb_url": self.thumb_url,
            "medium_url": self.medium_url,
            "original_url": self.original_url,
        }

    def __repr__(self):
        return "<PhotoAsset: %s>" % self.filename


class PhotosService:
    """iCloud Photos service via CloudKit API."""

    ZONE_ID = {"zoneName": "PrimarySync"}

    def __init__(self, service_root, session, params):
        self.session = session
        self.params = dict(params)
        self.params.update({
            "remapEnums": "true",
            "getCurrentSyncToken": "true",
        })
        self._service_root = service_root
        self._service_endpoint = (
            "%s/database/1/com.apple.photos.cloud/production/private"
            % service_root
        )
        self._shared_endpoint = (
            "%s/database/1/com.apple.photos.cloud/production/shared"
            % service_root
        )
        self._albums = None
        self._shared_albums = None
        self._shared_albums_error = None
        self._shared_library = None
        self._shared_library_zone = None
        self._shared_library_albums = None

    def _query(self, payload):
        """Execute a CloudKit records query."""
        url = "%s/records/query" % self._service_endpoint
        response = self.session.post(
            url,
            params=self.params,
            data=json.dumps(payload),
            headers={"Content-Type": "text/plain"},
        )
        data = response.json()
        self._check_cloudkit_adp(data)
        return data

    def _lookup_records(self, record_names, zone_id=None):
        """Fetch records by recordName via CloudKit records/lookup."""
        url = "%s/records/lookup" % self._service_endpoint
        zid = dict(zone_id or self.ZONE_ID)
        if "ownerRecordName" not in zid:
            zid["ownerRecordName"] = "_defaultOwner"
        payload = {
            "records": [{"recordName": rn} for rn in record_names],
            "zoneID": zid,
        }
        # Don't send getCurrentSyncToken for lookups — Apple rejects it
        # with "syncToken operations supported only in SyncZone" when the
        # session's sync token state is stale (e.g. after re-auth).
        params = {k: v for k, v in self.params.items()
                  if k != "getCurrentSyncToken"}
        response = self.session.post(
            url,
            params=params,
            data=json.dumps(payload),
            headers={"Content-Type": "text/plain"},
        )
        data = response.json()
        self._check_cloudkit_adp(data)
        return data

    def refresh_photo_url(self, photo, zone_id=None):
        """Re-fetch a photo's master record to get fresh download URLs.

        Retries with exponential backoff for transient/server errors.
        Returns a new URL or None if the lookup fails.
        """
        for attempt in range(3):
            try:
                data = self._lookup_records([photo.id], zone_id=zone_id)
                found = False
                server_error = False
                for record in data.get("records", []):
                    if record.get("recordName") != photo.id:
                        continue
                    found = True
                    if record.get("serverErrorCode"):
                        server_error = True
                        LOGGER.warning("Refresh got serverError %s for %s",
                                       record["serverErrorCode"], photo.id)
                        break
                    orig = record.get("fields", {}).get(
                        "resOriginalRes", {}).get("value", {})
                    url = orig.get("downloadURL")
                    if url:
                        photo._master = record
                        return PhotoAsset._fix_url(url)
                if found and not server_error:
                    return None
            except Exception:
                LOGGER.debug("Refresh attempt %d failed for %s",
                             attempt + 1, photo.id)
            if attempt < 2:
                time.sleep(1 + attempt * 2)
        LOGGER.error("Failed to refresh URL for %s after %d attempts",
                     photo.id, 3)
        return None

    _LOOKUP_CHUNK_SIZE = 50
    _LOOKUP_CHUNK_DELAY = 2

    def batch_refresh_photo_urls(self, photos, zone_id=None):
        """Re-fetch master records for multiple photos to get fresh URLs.

        Returns dict of photo.id -> fresh_url for successfully refreshed
        photos. Raises on session/auth errors so the caller can re-auth.
        Splits into small chunks with delays to avoid Apple rate-limiting.
        """
        if not photos:
            return {}
        photo_map = {p.id: p for p in photos}
        result = {}
        total_records = 0
        total_server_errors = 0
        total_deleted = 0
        total_no_url = 0
        lookup_broken = False
        for i in range(0, len(photos), self._LOOKUP_CHUNK_SIZE):
            chunk = photos[i:i + self._LOOKUP_CHUNK_SIZE]
            record_names = [p.id for p in chunk]
            data = self._lookup_records(record_names, zone_id=zone_id)
            records = data.get("records", [])
            total_records += len(records)
            chunk_errors = 0
            for record in records:
                rn = record.get("recordName", "")
                if rn not in photo_map:
                    continue
                err = record.get("serverErrorCode")
                if err:
                    total_server_errors += 1
                    chunk_errors += 1
                    if total_server_errors <= 3:
                        LOGGER.warning(
                            "Refresh: serverErrorCode=%s reason=%s for %s",
                            err, record.get("reason", ""), rn)
                    continue
                fields = record.get("fields", {})
                if fields.get("isDeleted", {}).get("value"):
                    total_deleted += 1
                    continue
                orig = fields.get(
                    "resOriginalRes", {}).get("value", {})
                url = orig.get("downloadURL")
                if url:
                    photo_map[rn]._master = record
                    result[rn] = PhotoAsset._fix_url(url)
                else:
                    total_no_url += 1
            if records and chunk_errors == len(records) and not result:
                LOGGER.warning("Lookup returned 100%% server errors — "
                               "aborting remaining refresh chunks")
                lookup_broken = True
                break
            if i + self._LOOKUP_CHUNK_SIZE < len(photos):
                time.sleep(self._LOOKUP_CHUNK_DELAY)
        not_returned = len(photos) - total_records
        if len(photos) > 1:
            LOGGER.info(
                "Batch refresh: requested=%d records_returned=%d "
                "urls_found=%d server_errors=%d deleted=%d "
                "no_url=%d not_returned=%d",
                len(photos), total_records, len(result),
                total_server_errors, total_deleted,
                total_no_url, not_returned)
        return result

    def _batch_query(self, payload):
        """Execute a CloudKit batch query."""
        url = "%s/internal/records/query/batch" % self._service_endpoint
        response = self.session.post(
            url,
            params=self.params,
            data=json.dumps(payload),
            headers={"Content-Type": "text/plain"},
        )
        data = response.json()
        self._check_cloudkit_adp(data)
        return data

    @staticmethod
    def _check_cloudkit_adp(data):
        """Detect CloudKit errors that indicate ADP is blocking access."""
        from pyicloud_ipd.exceptions import PyiCloudADPProtectionException
        if not isinstance(data, dict):
            return
        for record in data.get("records", []):
            reason = record.get("serverErrorCode", "")
            if reason in ("ACCESS_DENIED", "PRIVATE_DB_DISABLED",
                          "ZONE_NOT_FOUND"):
                raise PyiCloudADPProtectionException(reason)

    def check_indexing(self):
        """Check if Photos library indexing is complete."""
        data = self._query({
            "query": {"recordType": "CheckIndexingState"},
            "zoneID": self.ZONE_ID,
        })
        records = data.get("records", [])
        if records:
            state = records[0].get("fields", {}).get("state", {}).get("value")
            return state == "FINISHED"
        return False

    @property
    def full_library(self):
        """Return the true whole iCloud Photos library pseudo-album.

        Do not look this up through ``albums["All Photos"]``: user-created
        albums can have the same name and overwrite the synthetic entry in
        the album listing.  This mirrors icloudpd's dedicated
        ``library_object.all`` path.
        """
        return PhotoAlbum(self, "All Photos", album_type="all")

    @property
    def albums(self):
        """Returns dict of album name -> PhotoAlbum."""
        if self._albums is not None:
            return self._albums

        self._albums = {}

        # "All Photos" built-in
        self._albums["All Photos"] = PhotoAlbum(
            self, "All Photos", album_type="all"
        )

        # Smart folders
        for name, (query_filter, count_key) in SMART_FOLDERS.items():
            self._albums[name] = PhotoAlbum(
                self, name, album_type="smart",
                smart_filter=query_filter, smart_count_key=count_key,
            )

        # Bursts use dedicated record types instead of a smartAlbum filter
        self._albums["Bursts"] = PhotoAlbum(
            self, "Bursts", album_type="burst"
        )

        # User-created albums and folders (recursively, including nested folders).
        try:
            data = self._query({
                "query": {"recordType": "CPLAlbumByPositionLive"},
                "zoneID": self.ZONE_ID,
                "resultsLimit": 500,
            })
            folders = []
            for record in data.get("records", []):
                rn = record.get("recordName", "")
                if rn in ("----Root-Folder----", "----Project-Root-Folder----"):
                    continue
                fields = record.get("fields", {})
                if fields.get("isDeleted", {}).get("value"):
                    continue
                raw_name = fields.get("albumNameEnc", {}).get("value", "")
                name = _decode_b64_name(raw_name)
                if not name:
                    name = fields.get("albumName", {}).get("value", "")
                if not name:
                    continue
                is_folder = fields.get("albumType", {}).get("value", 0) == 3
                self._albums[name] = PhotoAlbum(
                    self, name, record_name=rn,
                    album_type="folder" if is_folder else "user",
                )
                if is_folder:
                    folders.append((rn, name))
            self._fetch_folder_children(
                folders, self._albums, self.ZONE_ID, self._query)
        except Exception:
            LOGGER.exception("Failed to fetch user albums")

        return self._albums

    def _fetch_folder_children(self, folders, albums_dict, zone_id, query_fn,
                               max_depth=5):
        """Recursively fetch sub-albums for folder albums.

        `folders` is a list of (recordName, parent_path) tuples.
        Discovered sub-folders are queued for the next depth level.
        """
        use_zone = zone_id if zone_id != self.ZONE_ID else None
        for depth in range(max_depth):
            if not folders:
                break
            next_folders = []
            for folder_rn, parent_path in folders:
                try:
                    child_data = query_fn({
                        "query": {
                            "recordType": "CPLAlbumByPositionLive",
                            "filterBy": [{
                                "fieldName": "parentId",
                                "comparator": "EQUALS",
                                "fieldValue": {"type": "STRING",
                                               "value": folder_rn},
                            }],
                        },
                        "zoneID": zone_id,
                        "resultsLimit": 500,
                    })
                    for record in child_data.get("records", []):
                        rn = record.get("recordName", "")
                        fields = record.get("fields", {})
                        if fields.get("isDeleted", {}).get("value"):
                            continue
                        raw_name = fields.get("albumNameEnc", {}).get(
                            "value", "")
                        name = _decode_b64_name(raw_name)
                        if not name:
                            name = fields.get("albumName", {}).get(
                                "value", "")
                        if not name:
                            continue
                        is_folder = (fields.get("albumType", {})
                                     .get("value", 0) == 3)
                        albums_dict[name] = PhotoAlbum(
                            self, name, record_name=rn,
                            album_type="folder" if is_folder else "user",
                            parent_folder=parent_path,
                            zone_id=use_zone,
                        )
                        if is_folder:
                            child_path = parent_path + "/" + name
                            next_folders.append((rn, child_path))
                except Exception:
                    LOGGER.exception(
                        "Failed to fetch sub-albums for folder %s",
                        parent_path)
            folders = next_folders

    def refresh_albums(self):
        """Invalidate cached albums so the next access re-fetches from iCloud."""
        self._albums = None
        self._shared_albums = None
        self._shared_albums_error = None
        self._shared_library_albums = None

    def _get_album_count(self, obj_type, zone_id=None):
        """Get photo count for an album by its obj_type."""
        try:
            data = self._batch_query({
                "batch": [{
                    "resultsLimit": 1,
                    "query": {
                        "filterBy": {
                            "fieldName": "indexCountID",
                            "fieldValue": {
                                "type": "STRING_LIST",
                                "value": [obj_type],
                            },
                            "comparator": "IN",
                        },
                        "recordType": "HyperionIndexCountLookup",
                    },
                    "zoneWide": True,
                    "zoneID": zone_id or self.ZONE_ID,
                }],
            })
            records = data.get("batch", [{}])[0].get("records", [])
            if records:
                return records[0].get("fields", {}).get("itemCount", {}).get("value", 0)
        except Exception:
            LOGGER.exception("Failed to get album count for %s", obj_type)
        return 0

    def _get_album_photos(self, album, limit=200, offset=0, direction="ASCENDING"):
        """Fetch photos in an album. Returns list of PhotoAsset.

        CloudKit often returns partial batches (far fewer than requested).
        We iterate internally, advancing startRank by the actual number of
        photos returned, until we've collected `limit` photos or CloudKit
        returns nothing.
        """
        result = []
        current_offset = offset
        zone_id = album.zone_id or self.ZONE_ID
        # Guard against pathological loops — cap total HTTP calls per request.
        for _ in range(max(limit, 20)):
            if len(result) >= limit:
                break

            filters = [
                {
                    "fieldName": "startRank",
                    "fieldValue": {"type": "INT64", "value": current_offset},
                    "comparator": "EQUALS",
                },
                {
                    "fieldName": "direction",
                    "fieldValue": {"type": "STRING", "value": direction},
                    "comparator": "EQUALS",
                },
            ]

            if album.album_type == "user":
                filters.append({
                    "fieldName": "parentId",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": album.record_name},
                })
            elif album.album_type == "smart":
                filters.append({
                    "fieldName": "smartAlbum",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": album.smart_filter},
                })

            remaining = limit - len(result)
            data = self._query({
                "query": {
                    "filterBy": filters,
                    "recordType": album.list_type,
                },
                "resultsLimit": max(remaining * 2, 4),
                "zoneID": zone_id,
            })

            masters = {}
            assets = {}
            for record in data.get("records", []):
                rt = record.get("recordType", "")
                rn = record.get("recordName", "")
                if rt == "CPLMaster":
                    masters[rn] = record
                elif rt == "CPLAsset":
                    ref = record.get("fields", {}).get(
                        "masterRef", {}
                    ).get("value", {}).get("recordName")
                    if ref:
                        assets[ref] = record

            batch = []
            for master_id, master in masters.items():
                asset = assets.get(master_id)
                batch.append(PhotoAsset(master, asset))

            if not batch:
                break  # end of album

            result.extend(batch)
            step = len(batch) if direction == "ASCENDING" else -len(batch)
            current_offset += step
            if current_offset < 0:
                break

        return result[:limit]

    # ── Shared Library (iOS 16+ family sharing) ────────────────────

    def _private_zones(self):
        """List all zones in the private database."""
        url = "%s/zones/list" % self._service_endpoint
        response = self.session.post(
            url,
            params=self.params,
            data=json.dumps({}),
            headers={"Content-Type": "text/plain"},
        )
        return response.json()

    def _detect_shared_library_zone(self):
        """Find the SharedSync-* zone in private or shared database.

        The iCloud Shared Library (iOS 16+) stores photos in a zone
        named 'SharedSync-<UUID>'.  On some accounts this zone appears
        in the private database, on others only in the shared database.
        """
        if self._shared_library_zone is not None:
            return self._shared_library_zone or None
        # Check private zones first
        try:
            data = self._private_zones()
            zones = data.get("zones", [])
            zone_names = [z.get("zoneID", {}).get("zoneName", "?") for z in zones]
            LOGGER.debug("Private zones: %s", zone_names)
            for zone in zones:
                zone_id = zone.get("zoneID", {})
                zone_name = zone_id.get("zoneName", "")
                if zone_name.startswith("SharedSync-"):
                    self._shared_library_zone = zone_id
                    self._shared_library_uses_shared_db = False
                    LOGGER.info("Shared Library zone found in private DB: %s", zone_name)
                    return zone_id
            LOGGER.info("No SharedSync zone among %d private zones: %s", len(zones), zone_names)
        except Exception:
            LOGGER.exception("Failed to check private zones for shared library")
        # Fallback: check shared zones
        try:
            data = self._shared_zones()
            zones = data.get("zones", [])
            for zone in zones:
                zone_id = zone.get("zoneID", {})
                zone_name = zone_id.get("zoneName", "")
                if zone_name.startswith("SharedSync-"):
                    self._shared_library_zone = zone_id
                    self._shared_library_uses_shared_db = True
                    LOGGER.info("Shared Library zone found in shared DB: %s", zone_name)
                    return zone_id
            LOGGER.info("No SharedSync zone in shared zones either")
        except Exception:
            LOGGER.exception("Failed to check shared zones for shared library")
        self._shared_library_zone = False
        return None

    def _query_zone(self, payload, zone_id):
        """Execute a CloudKit query against a specific private zone."""
        url = "%s/records/query" % self._service_endpoint
        payload["zoneID"] = zone_id
        response = self.session.post(
            url,
            params=self.params,
            data=json.dumps(payload),
            headers={"Content-Type": "text/plain"},
        )
        data = response.json()
        self._check_cloudkit_adp(data)
        return data

    @property
    def has_shared_library(self):
        """Return True if the account has an iCloud Shared Library."""
        return self._detect_shared_library_zone() is not None

    @property
    def shared_library(self):
        """Returns a PhotoAlbum representing the Shared Library, or None."""
        if self._shared_library is not None:
            return self._shared_library or None

        zone_id = self._detect_shared_library_zone()
        if not zone_id:
            self._shared_library = False
            return None

        self._shared_library = PhotoAlbum(
            self, "Shared Library", album_type="all", zone_id=zone_id,
        )
        return self._shared_library

    @property
    def shared_library_albums(self):
        """Returns dict of album name -> PhotoAlbum for the Shared Library zone."""
        if self._shared_library_albums is not None:
            return self._shared_library_albums

        self._shared_library_albums = {}
        zone_id = self._detect_shared_library_zone()
        if not zone_id:
            return self._shared_library_albums

        self._shared_library_albums["All Photos"] = PhotoAlbum(
            self, "All Photos", album_type="all", zone_id=zone_id,
        )

        if getattr(self, '_shared_library_uses_shared_db', False):
            return self._shared_library_albums

        for name, (query_filter, count_key) in SMART_FOLDERS.items():
            self._shared_library_albums[name] = PhotoAlbum(
                self, name, album_type="smart",
                smart_filter=query_filter, smart_count_key=count_key,
                zone_id=zone_id,
            )

        folders = []
        try:
            data = self._query_zone({
                "query": {"recordType": "CPLAlbumByPositionLive"},
                "resultsLimit": 500,
            }, zone_id)
            for record in data.get("records", []):
                rn = record.get("recordName", "")
                if rn in ("----Root-Folder----", "----Project-Root-Folder----"):
                    continue
                fields = record.get("fields", {})
                if fields.get("isDeleted", {}).get("value"):
                    continue
                raw_name = fields.get("albumNameEnc", {}).get("value", "")
                name = _decode_b64_name(raw_name)
                if not name:
                    name = fields.get("albumName", {}).get("value", "")
                if not name:
                    continue
                is_folder = fields.get("albumType", {}).get("value", 0) == 3
                self._shared_library_albums[name] = PhotoAlbum(
                    self, name, record_name=rn, zone_id=zone_id,
                    album_type="folder" if is_folder else "user",
                )
                if is_folder:
                    folders.append((rn, name))
        except Exception:
            LOGGER.exception("Failed to fetch shared library user albums")

        self._fetch_folder_children(
            folders, self._shared_library_albums, zone_id, self._query)

        return self._shared_library_albums

    def _get_shared_library_count(self):
        """Get photo count for the Shared Library zone."""
        zone_id = self._detect_shared_library_zone()
        if not zone_id:
            return 0
        try:
            url = "%s/internal/records/query/batch" % self._service_endpoint
            payload = {
                "batch": [{
                    "resultsLimit": 1,
                    "query": {
                        "filterBy": {
                            "fieldName": "indexCountID",
                            "fieldValue": {
                                "type": "STRING_LIST",
                                "value": ["CPLAssetByAssetDateWithoutHiddenOrDeleted"],
                            },
                            "comparator": "IN",
                        },
                        "recordType": "HyperionIndexCountLookup",
                    },
                    "zoneWide": True,
                    "zoneID": zone_id,
                }],
            }
            response = self.session.post(
                url,
                params=self.params,
                data=json.dumps(payload),
                headers={"Content-Type": "text/plain"},
            )
            data = response.json()
            records = data.get("batch", [{}])[0].get("records", [])
            if records:
                return records[0].get("fields", {}).get("itemCount", {}).get("value", 0)
        except Exception:
            LOGGER.exception("Failed to get shared library count")
        return 0

    def get_shared_library_photos(self, limit=200, offset=0, direction="ASCENDING"):
        """Fetch photos from the Shared Library zone."""
        zone_id = self._detect_shared_library_zone()
        if not zone_id:
            return []

        result = []
        current_offset = offset
        for _ in range(max(limit, 20)):
            if len(result) >= limit:
                break

            data = self._query_zone({
                "query": {
                    "filterBy": [
                        {"fieldName": "startRank",
                         "fieldValue": {"type": "INT64", "value": current_offset},
                         "comparator": "EQUALS"},
                        {"fieldName": "direction",
                         "fieldValue": {"type": "STRING", "value": direction},
                         "comparator": "EQUALS"},
                    ],
                    "recordType": "CPLAssetAndMasterByAssetDateWithoutHiddenOrDeleted",
                },
                "resultsLimit": max((limit - len(result)) * 2, 4),
            }, zone_id)

            masters = {}
            assets = {}
            for record in data.get("records", []):
                rt = record.get("recordType", "")
                rn = record.get("recordName", "")
                if rt == "CPLMaster":
                    masters[rn] = record
                elif rt == "CPLAsset":
                    ref = record.get("fields", {}).get(
                        "masterRef", {}
                    ).get("value", {}).get("recordName")
                    if ref:
                        assets[ref] = record

            batch = []
            for master_id, master in masters.items():
                asset = assets.get(master_id)
                batch.append(PhotoAsset(master, asset))

            if not batch:
                break

            result.extend(batch)
            step = len(batch) if direction == "ASCENDING" else -len(batch)
            current_offset += step
            if current_offset < 0:
                break

        return result[:limit]

    def refresh_shared_library_photo_url(self, photo):
        """Re-fetch a shared library photo's master record for fresh URLs."""
        zone_id = self._detect_shared_library_zone()
        if not zone_id:
            return None
        return self.refresh_photo_url(photo, zone_id=zone_id)

    # ── Shared Albums ──────────────────────────────────────────────

    def _shared_query(self, payload):
        """Execute a CloudKit query against the shared database.

        Uses the raw requests session to avoid the pyicloud session's
        error-checking, which raises exceptions for CloudKit error
        responses (e.g. BAD_REQUEST on shared zones).  This lets
        callers inspect the response instead of having to catch.
        """
        url = "%s/records/query" % self._shared_endpoint
        params = {k: v for k, v in self.params.items()
                  if k != "getCurrentSyncToken"}
        response = _RawSession.request(
            self.session, "POST", url,
            params=params,
            data=json.dumps(payload),
            headers={"Content-Type": "text/plain"},
        )
        try:
            data = response.json()
        except ValueError:
            LOGGER.error("Shared query: non-JSON response (HTTP %d)", response.status_code)
            return {"records": []}
        if response.status_code != 200:
            LOGGER.error("Shared query HTTP %d: %s", response.status_code, data)
        elif data.get("error") or data.get("reason"):
            LOGGER.error("Shared query CloudKit error: %s",
                         data.get("error") or data.get("reason"))
        for rec in data.get("records", []):
            if rec.get("serverErrorCode"):
                LOGGER.warning("Shared query record error: %s — %s",
                               rec.get("serverErrorCode"),
                               rec.get("reason", ""))
        return data

    def _shared_zones(self):
        """List all shared zones (each represents one shared album)."""
        url = "%s/zones/list" % self._shared_endpoint
        params = {k: v for k, v in self.params.items()
                  if k != "getCurrentSyncToken"}
        response = _RawSession.request(
            self.session, "POST", url,
            params=params,
            data=json.dumps({}),
            headers={"Content-Type": "text/plain"},
        )
        try:
            data = response.json()
        except ValueError:
            LOGGER.error("Shared zones: non-JSON response (HTTP %d)", response.status_code)
            return {"zones": []}
        if not data.get("zones") and data.get("error"):
            LOGGER.error("Shared zones API error: %s", data.get("error"))
        return data

    @property
    def shared_albums(self):
        """Returns dict of album name -> PhotoAlbum for shared albums."""
        if self._shared_albums is not None:
            return self._shared_albums

        self._shared_albums = {}
        self._shared_albums_error = None
        try:
            data = self._shared_zones()
            zones = data.get("zones", [])
            LOGGER.info("Shared zones response: %d zone(s) (endpoint=%s)",
                        len(zones), self._shared_endpoint)
            if not zones:
                if data.get("error") or data.get("reason") or data.get("errorMessage"):
                    err_detail = (data.get("error") or data.get("reason")
                                  or data.get("errorMessage"))
                    LOGGER.warning("Shared zones returned 0 zones with error: %s",
                                   err_detail)
                    self._shared_albums_error = str(err_detail)
                else:
                    LOGGER.info(
                        "No shared zones returned by iCloud.  This means the "
                        "account has no Shared Albums (the legacy feature), or "
                        "Apple's API did not return them.  Note: 'Shared Library' "
                        "(iOS 16+) is a separate feature and listed separately."
                    )
                LOGGER.debug("Shared zones raw response keys: %s",
                             list(data.keys()) if isinstance(data, dict) else type(data))
            for zone in zones:
                zone_id = zone.get("zoneID", {})
                zone_name = zone_id.get("zoneName", "")
                owner = zone_id.get("ownerRecordName", "")
                LOGGER.debug("Shared zone: name=%s owner=%s", zone_name, owner[:20] if owner else "?")
                if not zone_name or zone_name == "PrimarySync" or zone_name.startswith("SharedSync-"):
                    continue

                # Fetch album metadata from the shared zone
                try:
                    album_data = self._shared_query({
                        "query": {"recordType": "CPLAlbumByPositionLive"},
                        "zoneID": zone_id,
                    })
                    album_name = None
                    album_records = album_data.get("records", [])
                    LOGGER.debug("Zone %s: %d album record(s)", zone_name, len(album_records))
                    for record in album_records:
                        rn = record.get("recordName", "")
                        if rn in ("----Root-Folder----", "----Project-Root-Folder----"):
                            continue
                        fields = record.get("fields", {})
                        raw_name = fields.get("albumNameEnc", {}).get("value", "")
                        album_name = _decode_b64_name(raw_name)
                        if not album_name:
                            album_name = fields.get("albumName", {}).get("value", "")
                        if album_name:
                            break

                    if not album_name:
                        album_name = zone_name
                        LOGGER.warning("No album name found in zone %s, using zone name as fallback", zone_name)

                    self._shared_albums[album_name] = PhotoAlbum(
                        self, album_name, album_type="shared",
                        zone_id=zone_id,
                    )
                    LOGGER.info("Found shared album: '%s' (zone=%s, owner=%s)",
                                album_name, zone_name, owner[:20] if owner else "?")
                except Exception:
                    LOGGER.warning("Failed to read shared zone %s, adding with zone name",
                                   zone_name, exc_info=True)
                    self._shared_albums[zone_name] = PhotoAlbum(
                        self, zone_name, album_type="shared",
                        zone_id=zone_id,
                    )

        except Exception as exc:
            LOGGER.error("Failed to fetch shared albums: %s", exc, exc_info=True)
            self._shared_albums_error = str(exc)

        return self._shared_albums

    def _get_shared_album_count(self, album):
        """Get photo count for a shared album by querying its zone.

        Shared zones don't support CPLAssetByAssetDate — use
        CPLAssetAndMasterByAssetDate and count only CPLMaster records.
        """
        try:
            total = 0
            continuation = None
            LOGGER.debug("Counting shared album '%s' zone=%s", album.name,
                         (album.zone_id or {}).get("zoneName", "?"))
            for page in range(100):
                payload = {
                    "query": {
                        "recordType": "CPLAssetAndMasterByAssetDate",
                    },
                    "resultsLimit": 200,
                    "zoneID": album.zone_id,
                }
                if continuation:
                    payload["continuationMarker"] = continuation
                data = self._shared_query(payload)
                records = data.get("records", [])
                if page == 0 and not records:
                    LOGGER.warning("Shared album '%s': first page returned 0 records "
                                   "(keys=%s)", album.name, list(data.keys()))
                total += sum(1 for r in records if r.get("recordType") == "CPLMaster")
                continuation = data.get("continuationMarker")
                if not continuation or not records:
                    break
            LOGGER.info("Shared album '%s' count: %d", album.name, total)
            return total
        except Exception:
            LOGGER.exception("Failed to count shared album %s", album.name)
            return 0

    def _get_shared_album_photos(self, album, limit=200, offset=0, direction="ASCENDING"):
        """Fetch photos from a shared album zone."""
        all_masters = {}
        all_assets = {}
        continuation = None

        for _ in range(50):
            payload = {
                "query": {
                    "recordType": "CPLAssetAndMasterByAssetDate",
                },
                "resultsLimit": 200,
                "zoneID": album.zone_id,
            }
            if continuation:
                payload["continuationMarker"] = continuation

            data = self._shared_query(payload)
            records = data.get("records", [])

            for record in records:
                rt = record.get("recordType", "")
                rn = record.get("recordName", "")
                if rt == "CPLMaster":
                    all_masters[rn] = record
                elif rt == "CPLAsset":
                    ref = record.get("fields", {}).get(
                        "masterRef", {}
                    ).get("value", {}).get("recordName")
                    if ref:
                        all_assets[ref] = record

            continuation = data.get("continuationMarker")
            if not continuation or not records:
                break

        result = []
        for master_id, master in all_masters.items():
            asset = all_assets.get(master_id)
            result.append(PhotoAsset(master, asset))

        if direction == "DESCENDING":
            result.reverse()

        return result[offset:offset + limit]
