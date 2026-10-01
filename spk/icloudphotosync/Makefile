SPK_NAME = icloudphotosync
SPK_VERS = $(shell cat $(CURDIR)/VERSION)
SPK_REV  = 1
SPK_ICON = src/PACKAGE_ICON.PNG

DEPENDS  = cross/heif-convert

UNSUPPORTED_ARCHS = $(OLD_PPC_ARCHS) $(ARMv5_ARCHS)

MAINTAINER     = Pascal Pagel
DESCRIPTION    = Automatically mirrors your iCloud photo library to a Synology NAS. Supports multi-account setups, incremental sync, album selection, HEIC conversion, and scheduled operation.
DISPLAY_NAME   = iCloud Photo Sync
CHANGELOG      = Fix Chinese iCloud accounts (iCloud.com.cn domain normalization).

HOMEPAGE   = https://github.com/Euphonique/iCloudPhotoSync
LICENSE    = MIT

REQUIRED_MIN_DSM = 7.2
SERVICE_USER     = auto
STARTABLE        = yes
SERVICE_SETUP    = src/service-setup.sh

DSM_UI_DIR = app


PRE_COPY_TARGET = icloudphotosync_extra_install

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
	@cp -R src/app/* $(STAGING_INSTALL_PREFIX)/app/
	@# DSM configuration
	@install -d -m 755 $(STAGING_INSTALL_PREFIX)/conf
	@cp src/conf/privilege $(STAGING_INSTALL_PREFIX)/conf/
	@cp src/conf/resource $(STAGING_INSTALL_PREFIX)/conf/
