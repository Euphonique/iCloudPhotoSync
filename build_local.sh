#!/bin/bash
# Local build script — macOS/Linux, no Synology toolkit required.
# Produces the same .spk that PkgCreate.py would generate for noarch packages.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Read version from INFO.sh ─────────────────────────────────────────────────
VERSION=$(grep '^version=' INFO.sh | head -1 | tr -d '"' | cut -d= -f2)
PACKAGE="iCloudPhotoSync"
SPK_NAME="${PACKAGE}-noarch-${VERSION}.spk"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

PKG_DIR="$BUILD_DIR/pkg"
PAYLOAD_DIR="$BUILD_DIR/payload"
mkdir -p "$PKG_DIR" "$PAYLOAD_DIR"

echo "Building ${SPK_NAME} ..."

# ── 1. Assemble package payload (→ package.tgz) ───────────────────────────────
cp -a ui       "$PAYLOAD_DIR/ui"
cp -a lib      "$PAYLOAD_DIR/lib"
cp -a webapi   "$PAYLOAD_DIR/webapi"
[ -d bin ] && cp -a bin "$PAYLOAD_DIR/bin"

chmod +x "$PAYLOAD_DIR/ui/api.cgi"
chmod +x "$PAYLOAD_DIR/webapi/iCloudPhotoSync.cgi"

(cd "$PAYLOAD_DIR" && tar -czf "$PKG_DIR/package.tgz" .)

# ── 2. Assemble SPK directory ─────────────────────────────────────────────────
# INFO file — key=value, no quotes (DSM format)
cat > "$PKG_DIR/INFO" <<EOF
package=${PACKAGE}
version=${VERSION}
os_min_ver=7.2-64570
displayname=iCloud Photo Sync
description=Sync photos from iCloud to your Synology NAS
maintainer=Pascal Pagel
maintainer_url=https://github.com/Euphonique
arch=noarch
dsmuidir=ui
dsmappname=SYNO.SDS.iCloudPhotoSync
dsmapplaunchname=SYNO.SDS.iCloudPhotoSync.Instance
silent_install=yes
silent_upgrade=yes
silent_uninstall=yes
thirdparty=yes
startable=yes
EOF

mkdir -p "$PKG_DIR/scripts"
cp -a scripts/* "$PKG_DIR/scripts/"

mkdir -p "$PKG_DIR/conf"
cp -a conf/* "$PKG_DIR/conf/"

cp PACKAGE_ICON.PNG     "$PKG_DIR/"
cp PACKAGE_ICON_256.PNG "$PKG_DIR/"

# ── 3. Pack into .spk (plain tar, not gzipped) ───────────────────────────────
OUTPUT_DIR="$SCRIPT_DIR/dist"
mkdir -p "$OUTPUT_DIR"

(cd "$PKG_DIR" && tar -cf "$OUTPUT_DIR/$SPK_NAME" \
    INFO package.tgz scripts conf PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG)

echo ""
echo "Done: dist/${SPK_NAME}"
echo "Install via DSM → Package Center → Manual Install"
