#!/bin/bash
# Build icloudphotosync.spk from spksrc source layout (no full spksrc needed)
set -euo pipefail

PKG_NAME="iCloudPhotoSync"
PKG_VER="1.1.2"
PKG_REV="1"
DISPLAY_NAME="iCloud Photo Sync"
DESCRIPTION="Automatically mirrors your iCloud photo library to a Synology NAS."

SRC_DIR="$(cd "$(dirname "$0")/spk/icloudphotosync/src" && pwd)"
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)/build"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{staging,scripts,conf}

# ── 1. Stage package files (what goes into /var/packages/NAME/target/) ────────

echo "==> Staging package files..."
STAGE="$BUILD_DIR/staging"

# bin/
mkdir -p "$STAGE/bin"
cp "$SRC_DIR"/bin/scheduler.py "$STAGE/bin/"
cp "$SRC_DIR"/bin/sync_runner.py "$STAGE/bin/"
cp "$SRC_DIR"/bin/move_runner.py "$STAGE/bin/"
chmod 755 "$STAGE"/bin/*.py
cp -R "$SRC_DIR/bin/heif" "$STAGE/bin/"
chmod +x "$STAGE"/bin/heif/*/heif-convert 2>/dev/null || true

# lib/
mkdir -p "$STAGE/lib/handlers"
cp "$SRC_DIR"/lib/*.py "$STAGE/lib/"
cp "$SRC_DIR"/lib/handlers/*.py "$STAGE/lib/handlers/"
cp -R "$SRC_DIR/lib/vendor" "$STAGE/lib/"

# Install pure-Python dependencies into vendor/ so the standalone .spk
# works without any system-level pip packages (requests, urllib3, etc.).
echo "==> Installing Python dependencies into vendor/..."
if command -v pip3 >/dev/null 2>&1; then
    PIP_CMD=pip3
elif command -v pip >/dev/null 2>&1; then
    PIP_CMD=pip
else
    echo "WARNING: pip not found — skipping dependency install."
    echo "         The .spk will only work if the NAS has 'requests' installed system-wide."
    PIP_CMD=""
fi
if [ -n "$PIP_CMD" ]; then
    $PIP_CMD install --target "$STAGE/lib/vendor" \
        --no-compile --no-deps \
        -r "$SRC_DIR/requirements-pure.txt" \
        2>&1 | sed 's/^/    /'
    rm -rf "$STAGE"/lib/vendor/*.dist-info
    rm -rf "$STAGE"/lib/vendor/bin
fi

# app/ (DSM web UI — mapped to /webman/3rdparty/PKG_NAME/)
mkdir -p "$STAGE/app"
cp "$SRC_DIR"/app/api.cgi "$STAGE/app/"
chmod 755 "$STAGE/app/api.cgi"
cp "$SRC_DIR"/app/config "$STAGE/app/"
cp "$SRC_DIR"/app/index.html "$STAGE/app/"
cp "$SRC_DIR"/app/iCloudPhotoSync.js "$STAGE/app/"
cp -R "$SRC_DIR/app/images" "$STAGE/app/"
cp -R "$SRC_DIR/app/texts" "$STAGE/app/"

# ── 2. Create package.tgz ────────────────────────────────────────────────────

echo "==> Creating package.tgz..."
(cd "$STAGE" && tar czf "$BUILD_DIR/package.tgz" --owner=0 --group=0 .)

# ── 3. Generate scripts ─────────────────────────────────────────────────────

echo "==> Generating lifecycle scripts..."

# start-stop-status — adapted from service-setup.sh for direct use
cat > "$BUILD_DIR/scripts/start-stop-status" <<'SSSEOF'
#!/bin/sh
PKG_DIR="/var/packages/iCloudPhotoSync"
TARGET_DIR="$PKG_DIR/target"
VAR_DIR="${SYNOPKG_PKGVAR:-$PKG_DIR/var}"
SCHEDULER="$TARGET_DIR/bin/scheduler.py"
PID_FILE="$VAR_DIR/scheduler.pid"
LOG_DIR="$VAR_DIR/logs"
LOG_FILE="$LOG_DIR/scheduler.log"
STARTUP_ERR="$LOG_DIR/startup-error.log"

find_python() {
    for c in \
        /var/packages/python311/target/bin/python3 \
        /var/packages/python3/target/usr/bin/python3 \
        /usr/bin/python3 \
        /usr/bin/python3.8 /usr/bin/python3.9 \
        /usr/bin/python3.10 /usr/bin/python3.11 \
        /usr/local/bin/python3 \
        /var/packages/py3k/target/usr/bin/python3
    do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    command -v python3 2>/dev/null && return 0
    return 1
}

mkdir -p "$LOG_DIR" 2>/dev/null || true

is_running() {
    [ -f "$PID_FILE" ] || return 1
    PID=$(cat "$PID_FILE" 2>/dev/null)
    [ -n "$PID" ] || return 1
    kill -0 "$PID" 2>/dev/null
}

case $1 in
    start)
        if is_running; then exit 0; fi
        PYTHON=$(find_python)
        if [ -z "$PYTHON" ]; then
            echo "No Python 3 found" >> "$STARTUP_ERR"
            exit 1
        fi
        [ -f "$SCHEDULER" ] || { echo "Scheduler missing: $SCHEDULER" >> "$STARTUP_ERR"; exit 1; }
        "$PYTHON" -c "import sys; sys.exit(0)" 2>/dev/null || { echo "Python sanity check failed" >> "$STARTUP_ERR"; exit 1; }
        SYNOPKG_PKGVAR="$VAR_DIR" ICLOUD_STARTUP_ERR="$STARTUP_ERR" \
            nohup "$PYTHON" "$SCHEDULER" >> "$LOG_FILE" 2>&1 &
        echo $! > "$PID_FILE"
        sleep 2
        if is_running; then
            exit 0
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') Scheduler exited immediately after start." >> "$STARTUP_ERR"
            echo "Python: $PYTHON" >> "$STARTUP_ERR"
            echo "Check $LOG_FILE and $STARTUP_ERR for details." >> "$STARTUP_ERR"
            "$PYTHON" -c "
import sys, os
sys.path.insert(0, '$TARGET_DIR/lib')
sys.path.insert(0, '$TARGET_DIR/lib/vendor')
try:
    import requests
except ImportError as e:
    print('MISSING DEPENDENCY: %s' % e)
try:
    import config_manager
except ImportError as e:
    print('MISSING DEPENDENCY: %s' % e)
try:
    import sync_engine
except Exception as e:
    print('IMPORT ERROR: %s' % e)
" >> "$STARTUP_ERR" 2>&1
            exit 1
        fi
        ;;
    stop)
        [ -f "$PID_FILE" ] && {
            PID=$(cat "$PID_FILE" 2>/dev/null)
            [ -n "$PID" ] && kill "$PID" 2>/dev/null
            rm -f "$PID_FILE"
        }
        pkill -f "$TARGET_DIR/bin/sync_runner.py" 2>/dev/null || true
        pkill -f "$TARGET_DIR/bin/scheduler.py" 2>/dev/null || true
        sleep 1
        pkill -9 -f "$TARGET_DIR/bin/sync_runner.py" 2>/dev/null || true
        pkill -9 -f "$TARGET_DIR/bin/scheduler.py" 2>/dev/null || true
        exit 0
        ;;
    status)
        if is_running; then exit 0; else exit 3; fi
        ;;
    log)
        echo "$LOG_FILE"
        exit 0
        ;;
esac
exit 1
SSSEOF

# preinst
cat > "$BUILD_DIR/scripts/preinst" <<'EOF'
#!/bin/sh
for c in \
    /var/packages/python311/target/bin/python3 \
    /var/packages/python3/target/usr/bin/python3 \
    /usr/bin/python3 /usr/bin/python3.8 /usr/bin/python3.9 \
    /usr/bin/python3.10 /usr/bin/python3.11 \
    /usr/local/bin/python3 \
    /var/packages/py3k/target/usr/bin/python3
do
    [ -x "$c" ] && exit 0
done
command -v python3 >/dev/null 2>&1 && exit 0
echo "Python 3 is required. Install it from Package Center."
exit 1
EOF

# postinst
cat > "$BUILD_DIR/scripts/postinst" <<'EOF'
#!/bin/sh
PKG_VAR="${SYNOPKG_PKGVAR:-/var/packages/iCloudPhotoSync/var}"
mkdir -p "$PKG_VAR/accounts" "$PKG_VAR/logs"
[ -f "$PKG_VAR/config.json" ] || \
    echo '{"accounts": [], "default_target_dir": "/volume1/iCloudPhotos"}' > "$PKG_VAR/config.json"
# Clean legacy artifacts
rm -f /etc/sudoers.d/iCloudPhotoSync 2>/dev/null || true
rm -f /etc/cron.d/iCloudPhotoSync 2>/dev/null || true
exit 0
EOF

# preuninst
cat > "$BUILD_DIR/scripts/preuninst" <<'EOF'
#!/bin/sh
TARGET_DIR="/var/packages/iCloudPhotoSync/target"
pkill -f "$TARGET_DIR/bin/sync_runner.py" 2>/dev/null || true
pkill -f "$TARGET_DIR/bin/scheduler.py" 2>/dev/null || true
sleep 1
pkill -9 -f "$TARGET_DIR/bin/sync_runner.py" 2>/dev/null || true
pkill -9 -f "$TARGET_DIR/bin/scheduler.py" 2>/dev/null || true
sed -i "/#iCloudPhotoSync/d" /etc/crontab 2>/dev/null || true
rm -f /etc/cron.d/iCloudPhotoSync 2>/dev/null || true
rm -f /etc/sudoers.d/iCloudPhotoSync 2>/dev/null || true
exit 0
EOF

# postuninst
cat > "$BUILD_DIR/scripts/postuninst" <<'EOF'
#!/bin/sh
exit 0
EOF

# preupgrade
cat > "$BUILD_DIR/scripts/preupgrade" <<'EOF'
#!/bin/sh
exit 0
EOF

# postupgrade
cat > "$BUILD_DIR/scripts/postupgrade" <<'EOF'
#!/bin/sh
rm -f /etc/sudoers.d/iCloudPhotoSync 2>/dev/null || true
rm -f /etc/cron.d/iCloudPhotoSync 2>/dev/null || true
exit 0
EOF

chmod 755 "$BUILD_DIR"/scripts/*

# ── 4. conf/ ─────────────────────────────────────────────────────────────────

echo "==> Copying conf files..."
cp "$SRC_DIR/conf/privilege" "$BUILD_DIR/conf/"
cp "$SRC_DIR/conf/resource" "$BUILD_DIR/conf/"

# ── 5. Icons ─────────────────────────────────────────────────────────────────

cp "$SRC_DIR/PACKAGE_ICON.PNG" "$BUILD_DIR/"
cp "$SRC_DIR/PACKAGE_ICON_256.PNG" "$BUILD_DIR/"

# ── 6. INFO file ─────────────────────────────────────────────────────────────

echo "==> Generating INFO..."
CHECKSUM=$(md5sum "$BUILD_DIR/package.tgz" | cut -d' ' -f1)

cat > "$BUILD_DIR/INFO" <<INFOEOF
package="$PKG_NAME"
version="$PKG_VER"
description="$DESCRIPTION"
description_enu="$DESCRIPTION"
description_ger="Spiegelt automatisch deine iCloud-Fotobibliothek auf eine Synology NAS."
arch="noarch"
displayname="$DISPLAY_NAME"
maintainer="Pascal Pagel"
maintainer_url="https://github.com/SynoCommunity/spksrc"
distributor="SynoCommunity"
distributor_url="https://synocommunity.com"
os_min_ver="7.2-64570"
dsmuidir="app"
dsmappname="SYNO.SDS.iCloudPhotoSync.Instance"
startable="yes"
thirdparty="yes"
silent_install="yes"
silent_upgrade="yes"
silent_uninstall="yes"
checksum="$CHECKSUM"
INFOEOF

# ── 7. Assemble .spk ─────────────────────────────────────────────────────────

echo "==> Building ${PKG_NAME}-${PKG_VER}.spk ..."
SPK_FILE="$OUT_DIR/${PKG_NAME}-${PKG_VER}.spk"
(cd "$BUILD_DIR" && tar cf "$SPK_FILE" --owner=0 --group=0 \
    INFO package.tgz scripts conf \
    PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG)

echo "==> Done: $SPK_FILE ($(du -h "$SPK_FILE" | cut -f1))"

# Cleanup
rm -rf "$BUILD_DIR"
