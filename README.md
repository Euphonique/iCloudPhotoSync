# Synology iCloud Photo Sync — spksrc package

A native Synology DSM 7.2 package that automatically mirrors your iCloud photo library to your NAS — so your memories live on storage you own, not just on Apple's servers.
Runs as a proper DSM app with its own tile, settings UI, scheduler daemon, and DSM notifications. No Docker, no cron hacks, no SSH fiddling.

Built with the [SynoCommunity/spksrc](https://github.com/SynoCommunity/spksrc) cross-compilation framework.

## Features

- **iCloud Photostream & Albums** — incremental sync with deduplication via hardlinks
- **Multi-account** — several Apple IDs side by side, each with its own settings
- **Parallel downloads** — 1/2/4/8 configurable per account
- **Folder structure** — year / year-month / year-month-day / flat
- **HEIC / JPG conversion** — keep originals, convert, or both
- **Apple 2FA** via trusted-device push or SMS fallback
- **Native DSM UI** — built with SYNO.ux components
- **Multi-language** — English and German
- **Unprivileged** — runs as `sc-icloudphotosync`, not root

## Building

### Prerequisites

1. Clone the [spksrc](https://github.com/SynoCommunity/spksrc) repository
2. Set up the build environment (Docker recommended):
   ```bash
   git clone https://github.com/SynoCommunity/spksrc.git
   cd spksrc
   docker build -t spksrc .
   ```

### Adding this package

Copy or symlink the package directory into your spksrc checkout:

```bash
# From the spksrc root
cp -r /path/to/iCloudPhotoSync-spksrc/spk/icloudphotosync spk/
```

### Build

```bash
# Build for a specific architecture
cd spk/icloudphotosync
make arch-x64-7.2

# Or build for all supported architectures
make all-supported
```

The resulting `.spk` files land in `packages/`.

## Package structure (spksrc layout)

```
spk/icloudphotosync/
  Makefile                 spksrc package definition
  PLIST                    File list for SPK contents
  src/
    service-setup.sh       DSM lifecycle hooks (start/stop/install/upgrade)
    PACKAGE_ICON.PNG       Package icons
    PACKAGE_ICON_256.PNG
    requirements-pure.txt  Python wheel dependencies
    bin/
      scheduler.py         Long-running daemon, triggers syncs per interval
      sync_runner.py       Single-sync entry point (UI sync-now button)
      move_runner.py       Target-folder migration helper
      heif/                Bundled HEIC conversion binaries (per architecture)
    lib/
      sync_engine.py       Core sync loop: list -> dedupe -> download -> verify
      icloud_client.py     iCloud API wrapper (pyicloud_ipd)
      config_manager.py    Global + per-account config with atomic file locking
      heic_converter.py    HEIC -> JPG conversion with multi-backend fallback
      handlers/            CGI request handlers
      vendor/              Bundled Python deps (pyicloud_ipd, srp, six)
    app/                   DSM SPA — Ext.js + SYNO.ux components
    conf/
      privilege            run-as: package
      resource             data-share for /volume1/iCloudPhotos
```

## Requirements

- Synology DSM **7.2** or newer
- Python 3.8+ (provided by spksrc cross/python311 dependency)
- An Apple ID with 2FA enabled
- **iCloud Advanced Data Protection (ADP) must be disabled** for iCloud Photos

## Known limitations

### iCloud Advanced Data Protection (ADP)

If you have ADP enabled, this app cannot access your iCloud Photos. ADP encrypts photos end-to-end so only trusted Apple devices hold decryption keys.

**Workarounds:**
1. Disable ADP: *Settings -> Apple ID -> iCloud -> Advanced Data Protection -> Turn Off*
2. Enable temporary web access at [icloud.com](https://icloud.com) (grants ~1 hour API access)

## Privacy & security

- Apple password is never stored permanently — it is only held temporarily during the 2FA handshake, encrypted with a machine-specific key (SHA-256), and kept in RAM only (/dev/shm). It is discarded immediately after authentication completes.
- Session cookies stored under `/var/packages/icloudphotosync/var/accounts/{id}/session/`
- No telemetry, no analytics, no phone-home

## License

[MIT](LICENSE). Vendored third-party code keeps its original license:
- [pyicloud_ipd](https://github.com/icloud-photos-downloader/pyicloud_ipd) — MIT
- [srp](https://github.com/cocagne/pysrp) — BSD

## Disclaimer

Not affiliated with or endorsed by Apple Inc. "Apple", "iCloud", and related marks are trademarks of Apple Inc.
