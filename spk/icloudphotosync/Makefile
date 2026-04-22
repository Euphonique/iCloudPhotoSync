SPK_NAME = icloudphotosync
SPK_VERS = 1.3.3
SPK_REV  = 1
SPK_ICON = src/PACKAGE_ICON.PNG

DEPENDS  = cross/python311
DEPENDS += cross/heif-convert

UNSUPPORTED_ARCHS = $(OLD_PPC_ARCHS) $(ARMv5_ARCHS)

MAINTAINER     = Pascal Pagel
DESCRIPTION    = Automatically mirrors your iCloud photo library to a Synology NAS. Supports multi-account setups, incremental sync, album selection, HEIC conversion, and scheduled operation.
DISPLAY_NAME   = iCloud Photo Sync
CHANGELOG      = Fix mass download failures from expired CDN URLs (batch refresh with session re-auth). Fix album folder nesting losing parent folder hierarchy. Add JPEG quality setting for HEIC conversion.

HOMEPAGE   = https://github.com/SynoCommunity/spksrc
LICENSE    = MIT

WIZARDS_DIR = src/wizard

REQUIRED_MIN_DSM = 7.2
SERVICE_USER     = auto
STARTABLE        = yes
SERVICE_SETUP    = src/service-setup.sh

SERVICE_PORT       = 0
SERVICE_PORT_TITLE = iCloud Photo Sync

DSM_UI_DIR = app

SPK_COMMANDS  = bin/scheduler.py
SPK_COMMANDS += bin/sync_runner.py
SPK_COMMANDS += bin/move_runner.py

WHEELS = src/requirements-pure.txt

POST_STRIP_TARGET = icloudphotosync_extra_install

include ../../mk/spksrc.spk.mk

.PHONY: icloudphotosync_extra_install
icloudphotosync_extra_install:
	@$(MSG) Installing iCloudPhotoSync application files
	@install -d -m 755 $(STAGING_INSTALL_PREFIX)/bin
	@install -d -m 755 $(STAGING_INSTALL_PREFIX)/lib
	@install -d -m 755 $(STAGING_INSTALL_PREFIX)/app
	@# Python application scripts
	@install -m 755 src/bin/scheduler.py $(STAGING_INSTALL_PREFIX)/bin/
	@install -m 755 src/bin/sync_runner.py $(STAGING_INSTALL_PREFIX)/bin/
	@install -m 755 src/bin/move_runner.py $(STAGING_INSTALL_PREFIX)/bin/
	@# Python library modules
	@cp -R src/lib/*.py $(STAGING_INSTALL_PREFIX)/lib/
	@cp -R src/lib/handlers $(STAGING_INSTALL_PREFIX)/lib/
	@cp -R src/lib/vendor $(STAGING_INSTALL_PREFIX)/lib/
	@# heif-convert is provided by cross/heif-convert dependency
	@# (installed to STAGING_INSTALL_PREFIX/bin/heif-convert automatically)
	@# Web UI (DSM app)
	@cp -R src/app/* $(STAGING_INSTALL_PREFIX)/app/
	@# DSM configuration
	@install -d -m 755 $(STAGING_INSTALL_PREFIX)/conf
	@cp src/conf/privilege $(STAGING_INSTALL_PREFIX)/conf/
	@cp src/conf/resource $(STAGING_INSTALL_PREFIX)/conf/
