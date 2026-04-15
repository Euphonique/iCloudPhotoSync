# Synology iCloud Photo Sync

A native Synology DSM 7.2 package that automatically mirrors your iCloud photo library to your NAS — so your memories live on storage you own, not just on Apple's servers.
Runs as a proper DSM app with its own tile, settings UI, scheduler daemon, and DSM notifications. No Docker, no cron hacks, no SSH fiddling.

<img width="1021" height="542" alt="Screenshot 2026-04-15 092935" src="https://github.com/user-attachments/assets/93f6764b-89a2-427e-b647-f8b992005909" />
More Screenshots: SCREENSHOTS.md

## Why this exists

When I first set up my DiskStation, I couldn’t believe there was no way to sync Apple Photos directly with it. Even Cloud Sync doesn’t offer this option. So I spent a long time looking for a way to back up my photos: Docker images, even a separate virtual machine running on iCloud. None of it was really how it should be.
But that’s all over now: I’m bringing you the iCloud Photos Sync app — just as it should have officially existed all along.

iCloud is convenient but it's a black box: Apple decides what stays, what gets "optimized", and what happens if your account is locked or deleted. A local mirror on your Synology gives you:

- **A real backup** you can restore from, independent of Apple
- **Full-resolution originals** kept forever (not the phone-optimised versions)
- **Searchable, organised files** in Photo Station, Synology Photos, or any other tool
- **Offline access** from your home network without touching the cloud

## Features

### Sync
- **iCloud Photostream** — all photos from your library, incrementally downloaded
- **Albums** — pick which shared and personal albums to sync, toggle each one individually
- **Multi-account** — several Apple IDs side by side, each with its own target folder and settings
- **Incremental** — only new/changed photos are downloaded; existing files are skipped
- **Deduplication via hardlinks** — the same photo in Photostream *and* an album is stored once on disk
- **Parallel downloads** — 1/2/4/8 configurable per account
- **Multi-track fetch** — for libraries >1000 photos, 4 producers fetch in parallel from iCloud

### Organisation
- **Folder structure per source** — year / year-month / year-month-day / flat
- **Filename style** — original Apple names or date-based
- **HEIC / JPG handling** — keep originals, convert to JPG, or both (optional sibling folders)
- **Conflict policy** — skip, overwrite, or rename on filename collisions

### Scheduling
- **Per-account sync interval** — 1h to 24h, set independently for each Apple ID
- **Long-running scheduler daemon** — not cron, no root required; respects DSM's package lifecycle
- **Manual sync-now** button in the UI for on-demand runs
- **Background-safe** — survives DSM reboots, stops cleanly on package shutdown

### Authentication
- **Apple 2FA** via trusted-device push (tap "Allow" on your iPhone/iPad/Mac)
- **SMS fallback** when no trusted device is available
- **SRP-based login** — the same protocol the official Apple clients use
- **Session reuse** — Apple's trusted cookie is valid ~60 days, no daily logins
- **Re-auth notifications** — DSM pushes a warning ~14 days before expiry so sync never dies silently

### Integration
- **Native DSM UI** — built with SYNO.ux components, matches Package Center look & feel
- **Multi-language** — English and German UI strings
- **DSM notifications** — re-auth prompts, expiry warnings, sync failures
- **Unprivileged** — runs as its own `iCloudPhotoSync` user, not root
- **Self-contained** — Python deps vendored in, no pip at install time

## Installation

1. Download the latest `.spk` from [Releases](../../releases).
2. In DSM **Package Center → Manual Install**, select the `.spk`.
3. Confirm the "publisher unknown" warning (this is a community package, not signed by Synology).
4. Open the **iCloud Photo Sync** tile from the main menu.

The installer will:
- Create `/volume1/iCloudPhotos` as the default target (you can change it per account later)
- Create a dedicated `iCloudPhotoSync` user with write access to that folder only
- Register the long-running scheduler with DSM's package lifecycle
- Add a tile in the DSM main menu

## First run

1. Click **Add account** and enter your Apple ID + password.
2. Approve the 2FA prompt on one of your trusted Apple devices, or fall back to SMS.
3. Wait for the album list to load (a few seconds to a minute for large libraries).
4. Pick which albums to sync, choose folder structure and formats.
5. The first sync starts automatically. Subsequent syncs run on the per-account interval you set.

The first full sync of a large library can take hours. Subsequent syncs are incremental and typically finish in seconds to a few minutes.

## Requirements

- Synology DSM **7.2** or newer (uses data-share for target folder permissions, which requires DSM 7.2+)
- Any architecture — the package is `arch=noarch` (pure Python, no compiled binaries)
- An Apple ID with 2FA enabled (required by Apple since 2019, not something this app imposes)
- Enough disk space for your photo library

## Privacy & security

- Your Apple password is held in memory **only during the 2FA handshake**, then discarded. It is never written to disk.
- The Apple trusted-session cookie is stored on your NAS under `/var/packages/iCloudPhotoSync/var/accounts/{id}/session/` and is readable only by the package user.
- No telemetry, no analytics, no phone-home. The package talks to Apple's servers and nothing else.
- Source is open (MIT) — read it, audit it, fork it.

## Building from source

Requires the Synology DSM 7.2 toolkit (Linux-only — uses `chroot`). Under Windows, use WSL2 with Ubuntu. See [SETUP.md](SETUP.md) for the full toolkit setup.

```bash
# From the toolkit root (inside your Linux environment)
cd /toolkit/pkgscripts-ng
./PkgCreate.py -v 7.2 -p broadwellnk -c iCloudPhotoSync
```

The resulting `.spk` lands in `/toolkit/build_env/ds.broadwellnk-7.2/image/packages/`.

## Architecture

```
bin/
  scheduler.py         Long-running daemon, triggers syncs per account on interval
  sync_runner.py       Single-sync entry point (called by UI sync-now button)
  move_runner.py       Target-folder migration helper

lib/
  sync_engine.py       Core sync loop: list -> dedupe -> download -> verify
  icloud_client.py     iCloud API wrapper around pyicloud_ipd
  config_manager.py    Global + per-account config with atomic file locking
  heic_converter.py    Optional HEIC -> JPG conversion
  handlers/            CGI endpoints mounted at /webman/3rdparty/iCloudPhotoSync/api.cgi
  vendor/              Bundled Python deps (pyicloud_ipd, srp, six)

ui/                    DSM SPA — Ext.js + SYNO.ux components
conf/                  privilege + resource (data-share) definitions
scripts/               DSM lifecycle hooks (preinst, postinst, start-stop-status, ...)
```

Runtime data lives under `/var/packages/iCloudPhotoSync/var/`:

- `config.json` — global settings (account list, log level)
- `accounts/{id}/sync_config.json` — per-account settings (interval, folders, formats)
- `accounts/{id}/session/` — iCloud trusted-session cookies (~60 day lifetime)
- `accounts/{id}/manifest.json` — local file index for incremental sync
- `logs/scheduler.log` + `logs/sync.log` — split logs for scheduling vs. sync runs

## License

[MIT](LICENSE). Vendored third-party code keeps its original license:
- [pyicloud_ipd](https://github.com/icloud-photos-downloader/pyicloud_ipd) — MIT
- [srp](https://github.com/cocagne/pysrp) — BSD

## Disclaimer

Not affiliated with or endorsed by Apple Inc. "Apple", "iCloud", and related marks are trademarks of Apple Inc. This package talks to Apple's private-but-reverse-engineered iCloud APIs; Apple can change these at any time and break the sync. If that happens, open an issue — or better, a pull request.
