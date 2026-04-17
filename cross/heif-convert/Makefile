PKG_NAME = heif-convert
PKG_VERS = 1.19.7
PKG_EXT = tar.gz
PKG_DIST_NAME = v$(PKG_VERS).$(PKG_EXT)
PKG_DIST_SITE = https://github.com/niclas-schwalbe/libheif-heif-convert/archive/refs/tags
PKG_DIR = libheif-heif-convert-$(PKG_VERS)

# heif-convert was removed from libheif 1.19+ and moved to a separate repo.
# This package builds only the heif-convert CLI tool.
HOMEPAGE = https://github.com/niclas-schwalbe/libheif-heif-convert
COMMENT  = HEIC/HEIF to JPEG conversion tool (standalone from libheif)
LICENSE  = LGPL-3.0

DEPENDS  = cross/libheif-latest
DEPENDS += cross/libde265
DEPENDS += cross/libjpeg
DEPENDS += cross/libtiff
DEPENDS += cross/zstd
DEPENDS += cross/xz
DEPENDS += cross/jbigkit
DEPENDS += cross/libdeflate
DEPENDS += cross/Lerc

UNSUPPORTED_ARCHS = $(OLD_PPC_ARCHS) $(ARMv5_ARCHS)
REQUIRED_MIN_DSM = 7.1

CMAKE_ARGS = -DCMAKE_FIND_ROOT_PATH=$(INSTALL_DIR)/$(INSTALL_PREFIX)

include ../../mk/spksrc.cross-cmake.mk
